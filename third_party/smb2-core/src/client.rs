//! Serialized SMB 2.0.2/2.1 client over an OS-supplied transport.
//! One request at a time, bounded frames, mandatory signing after NTLMv2.
use crate::{
    Error, Result,
    auth::{
        ntlm::{NtlmAuthenticator, NtlmCredentials},
        spnego,
    },
    msg::*,
    pack::{Guid, Pack, ReadCursor, Unpack, WriteCursor},
    types::{flags::*, *},
};
use alloc::{string::ToString, vec, vec::Vec};
use digest::KeyInit;
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<sha2::Sha256>;
const MAX_FRAME: usize = 65536 + 512;
const MORE_PROCESSING: u32 = 0xc0000016;
pub const EOF: u32 = 0xc0000011;
pub const NO_MORE_FILES: u32 = 0x80000006;

pub trait Transport {
    fn begin_request(&mut self) {}
    fn disconnect(&mut self) {}
    fn send_all(&mut self, bytes: &[u8]) -> Result<()>;
    fn receive_exact(&mut self, bytes: &mut [u8]) -> Result<()>;
}

pub struct Client<T> {
    transport: T,
    next_message: u64,
    session: SessionId,
    tree: TreeId,
    credits: u32,
    key: Option<Vec<u8>>,
    failed: bool,
    pub max_read: u32,
    pub max_write: u32,
}

/// HMAC-SHA256 with the wire signature field logically zeroed.
pub fn signature(message: &[u8], key: &[u8]) -> Result<[u8; 16]> {
    if message.len() < 64 {
        return Err(Error::Signature);
    }
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| Error::Signature)?;
    mac.update(&message[..48]);
    mac.update(&[0; 16]);
    mac.update(&message[64..]);
    let digest = mac.finalize().into_bytes();
    Ok(digest[..16].try_into().unwrap())
}
pub fn verify(message: &[u8], key: &[u8]) -> Result<()> {
    let expected = signature(message, key)?;
    let difference = expected
        .iter()
        .zip(&message[48..64])
        .fold(0u8, |v, (a, b)| v | (a ^ b));
    if difference != 0 {
        return Err(Error::Signature);
    }
    Ok(())
}

impl<T: Transport> Client<T> {
    pub fn connect(
        transport: T,
        server: &str,
        share: &str,
        credentials: NtlmCredentials,
        random: fn(&mut [u8]) -> Result<()>,
        filetime: fn() -> u64,
    ) -> Result<Self> {
        let mut client = Self {
            transport,
            next_message: 0,
            session: SessionId::NONE,
            tree: TreeId(0),
            credits: 1,
            key: None,
            failed: false,
            max_read: 32768,
            max_write: 32768,
        };
        let mut guid = [0; 16];
        random(&mut guid)?;
        let guid = Guid::unpack(&mut ReadCursor::new(&guid))?;
        let (_, bytes) = client.call(
            Command::Negotiate,
            &negotiate::NegotiateRequest {
                security_mode: SecurityMode::new(3),
                capabilities: Capabilities::default(),
                client_guid: guid,
                dialects: vec![Dialect::Smb2_0_2, Dialect::Smb2_1],
                negotiate_contexts: Vec::new(),
            },
        )?;
        let negotiated = negotiate::NegotiateResponse::unpack(&mut ReadCursor::new(&bytes[64..]))?;
        if !matches!(
            negotiated.dialect_revision,
            Dialect::Smb2_0_2 | Dialect::Smb2_1
        ) || negotiated.max_read_size == 0
            || negotiated.max_write_size == 0
        {
            return Err(Error::invalid_data("unsupported negotiation"));
        }
        client.max_read = negotiated.max_read_size.min(32768);
        client.max_write = negotiated.max_write_size.min(32768);
        let mut ntlm = NtlmAuthenticator::new(credentials, random, filetime);
        let negotiate_token = ntlm.negotiate();
        let token = spnego::wrap_neg_token_init(&[spnego::OID_NTLMSSP], &negotiate_token);
        let (header, bytes) =
            client.call_allow(Command::SessionSetup, &Self::setup(token), MORE_PROCESSING)?;
        if header.status.0 != MORE_PROCESSING || header.session_id == SessionId::NONE {
            return Err(Error::Authentication);
        }
        client.session = header.session_id;
        let setup =
            session_setup::SessionSetupResponse::unpack(&mut ReadCursor::new(&bytes[64..]))?;
        let challenge = spnego::parse_neg_token_resp(&setup.security_buffer)?
            .response_token
            .ok_or(Error::Authentication)?;
        let authenticate = ntlm.authenticate(&challenge)?;
        let key = ntlm.session_key().ok_or(Error::Authentication)?.to_vec();
        let (last, mut bytes) = client.call_allow(
            Command::SessionSetup,
            &Self::setup(spnego::wrap_neg_token_resp(&authenticate)),
            MORE_PROCESSING,
        )?;
        if last.status.0 == MORE_PROCESSING {
            let setup =
                session_setup::SessionSetupResponse::unpack(&mut ReadCursor::new(&bytes[64..]))?;
            let response = spnego::parse_neg_token_resp(&setup.security_buffer)?;
            if response.response_token.is_some() {
                return Err(Error::Authentication);
            }
            let list = spnego::ntlm_mechanism_list();
            let server_mic = response.mech_list_mic.ok_or(Error::Authentication)?;
            let expected = ntlm.mechanism_mic(&list, true)?;
            if server_mic.len() != 16
                || expected
                    .iter()
                    .zip(&server_mic)
                    .fold(0u8, |v, (a, b)| v | (a ^ b))
                    != 0
            {
                return Err(Error::Signature);
            }
            let mic = ntlm.mechanism_mic(&list, false)?;
            bytes = client
                .call(
                    Command::SessionSetup,
                    &Self::setup(spnego::wrap_mechanism_mic(&mic)),
                )?
                .1;
        }
        let setup =
            session_setup::SessionSetupResponse::unpack(&mut ReadCursor::new(&bytes[64..]))?;
        // Never silently fall back to guest, anonymous, or an encrypted session.
        if setup.session_flags.0 != 0 {
            return Err(Error::Authentication);
        }
        if bytes[16] & 8 == 0 {
            return Err(Error::Signature);
        }
        verify(&bytes, &key)?;
        client.key = Some(key);
        let (header, bytes) = client.call(
            Command::TreeConnect,
            &tree_connect::TreeConnectRequest {
                flags: tree_connect::TreeConnectRequestFlags(0),
                path: alloc::format!("\\\\{}\\{}", server, share),
            },
        )?;
        let tree = tree_connect::TreeConnectResponse::unpack(&mut ReadCursor::new(&bytes[64..]))?;
        if tree.share_flags.0 & 0x8000 != 0 {
            return Err(Error::Unavailable);
        }
        client.tree = header
            .tree_id
            .ok_or(Error::invalid_data("missing tree id"))?;
        Ok(client)
    }
    fn setup(token: Vec<u8>) -> session_setup::SessionSetupRequest {
        session_setup::SessionSetupRequest {
            flags: session_setup::SessionSetupRequestFlags(0),
            security_mode: SecurityMode::new(3),
            capabilities: Capabilities::default(),
            channel: 0,
            previous_session_id: 0,
            security_buffer: token,
        }
    }
    fn call(&mut self, command: Command, body: &impl Pack) -> Result<(header::Header, Vec<u8>)> {
        self.call_allow(command, body, 0)
    }
    fn call_allow(
        &mut self,
        command: Command,
        body: &impl Pack,
        allowed: u32,
    ) -> Result<(header::Header, Vec<u8>)> {
        if self.failed {
            return Err(Error::Transport);
        }
        let result = self.exchange(command, body, allowed);
        if result
            .as_ref()
            .is_err_and(|e| !matches!(e, Error::Status(_)))
        {
            self.failed = true;
            self.transport.disconnect();
        }
        result
    }
    fn exchange(
        &mut self,
        command: Command,
        body: &impl Pack,
        allowed: u32,
    ) -> Result<(header::Header, Vec<u8>)> {
        if self.credits == 0 {
            return Err(Error::invalid_data("server supplied no credits"));
        }
        let id = MessageId(self.next_message);
        self.next_message = self.next_message.checked_add(1).ok_or(Error::Unavailable)?;
        self.credits -= 1;
        let mut header = header::Header::new_request(command);
        header.message_id = id;
        header.session_id = self.session;
        header.tree_id = Some(self.tree);
        header.credit_charge = CreditCharge(1);
        header.credits = 16;
        if self.key.is_some() {
            header.flags.set_signed();
        }
        let mut cursor = WriteCursor::new();
        header.pack(&mut cursor);
        body.pack(&mut cursor);
        let mut message = cursor.into_inner();
        if let Some(key) = &self.key {
            let sig = signature(&message, key)?;
            message[48..64].copy_from_slice(&sig);
        }
        if message.len() > MAX_FRAME {
            return Err(Error::invalid_data("oversized request"));
        }
        self.transport.begin_request();
        self.transport
            .send_all(&(message.len() as u32).to_be_bytes())?;
        self.transport.send_all(&message)?;
        // Bound interim STATUS_PENDING frames as well as frame allocation.
        let mut async_id = None;
        for _ in 0..64 {
            let mut length = [0; 4];
            self.transport.receive_exact(&mut length)?;
            let length = u32::from_be_bytes(length) as usize;
            if !(64..=MAX_FRAME).contains(&length) {
                return Err(Error::invalid_data("invalid frame length"));
            }
            let mut response = vec![0; length];
            self.transport.receive_exact(&mut response)?;
            let header = header::Header::unpack(&mut ReadCursor::new(&response))?;
            if !header.is_response()
                || header.command != command
                || header.message_id != id
                || header.next_command != 0
                || (self.session != SessionId::NONE && header.session_id != self.session)
            {
                return Err(Error::invalid_data("unexpected response identity"));
            }
            if header.status.0 == 0x103 {
                // MS-SMB2 interim async replies may be unsigned. They never
                // complete an operation or expose data; the final reply must
                // authenticate and carry the same async identity.
                if header.async_id.is_none() || (async_id.is_some() && async_id != header.async_id)
                {
                    return Err(Error::invalid_data("invalid async interim"));
                }
                if response[16] & 8 != 0
                    && let Some(key) = &self.key
                {
                    verify(&response, key)?;
                }
                async_id = header.async_id;
                self.credits = self.credits.saturating_add(u32::from(header.credits));
                continue;
            }
            if async_id.is_some() && async_id != header.async_id {
                return Err(Error::invalid_data("async completion mismatch"));
            }
            if let Some(key) = &self.key {
                if response[16] & 8 == 0 {
                    return Err(Error::Signature);
                }
                verify(&response, key)?;
            }
            self.credits = self.credits.saturating_add(u32::from(header.credits));
            if header.status.0 != 0 && header.status.0 != allowed {
                return Err(Error::Status(header.status.0));
            }
            return Ok((header, response));
        }
        Err(Error::Timeout)
    }
    pub fn disconnect(&mut self) -> Result<()> {
        let result = self
            .call(
                Command::TreeDisconnect,
                &tree_disconnect::TreeDisconnectRequest,
            )
            .and_then(|_| {
                self.tree = TreeId(0);
                self.call(Command::Logoff, &logoff::LogoffRequest)
            })
            .map(|_| ());
        self.failed = true;
        self.transport.disconnect();
        result
    }

    pub fn open(
        &mut self,
        path: &str,
        access: u32,
        disposition: create::CreateDisposition,
        options: u32,
    ) -> Result<create::CreateResponse> {
        let (_, bytes) = self.call(
            Command::Create,
            &create::CreateRequest {
                requested_oplock_level: OplockLevel::None,
                impersonation_level: create::ImpersonationLevel::Impersonation,
                desired_access: FileAccessMask::new(access),
                file_attributes: 0,
                share_access: create::ShareAccess(7),
                create_disposition: disposition,
                create_options: options,
                name: path.replace('/', "\\"),
                create_contexts: Vec::new(),
            },
        )?;
        create::CreateResponse::unpack(&mut ReadCursor::new(&bytes[64..]))
    }
    pub fn close(&mut self, file: FileId) -> Result<()> {
        self.call(
            Command::Close,
            &close::CloseRequest {
                flags: 0,
                file_id: file,
            },
        )
        .map(|_| ())
    }
    pub fn flush(&mut self, file: FileId) -> Result<()> {
        self.call(Command::Flush, &flush::FlushRequest { file_id: file })
            .map(|_| ())
    }
    pub fn read(&mut self, file: FileId, offset: u64, count: usize) -> Result<Vec<u8>> {
        let (_, bytes) = match self.call(
            Command::Read,
            &read::ReadRequest {
                padding: 0,
                flags: 0,
                length: count.min(self.max_read as usize) as u32,
                offset,
                file_id: file,
                minimum_count: 0,
                channel: 0,
                remaining_bytes: 0,
                read_channel_info: Vec::new(),
            },
        ) {
            Err(Error::Status(EOF)) => return Ok(Vec::new()),
            r => r?,
        };
        let result = read::ReadResponse::unpack(&mut ReadCursor::new(&bytes[64..]))?;
        if result.data.len() > count {
            return Err(Error::invalid_data("read exceeds request"));
        }
        Ok(result.data)
    }
    pub fn write(&mut self, file: FileId, offset: u64, bytes: &[u8]) -> Result<usize> {
        let data = bytes[..bytes.len().min(self.max_write as usize)].to_vec();
        let count = data.len();
        let (_, bytes) = self.call(
            Command::Write,
            &write::WriteRequest {
                data_offset: 112,
                offset,
                file_id: file,
                channel: 0,
                remaining_bytes: 0,
                write_channel_info_offset: 0,
                write_channel_info_length: 0,
                flags: 0,
                data,
            },
        )?;
        let response = write::WriteResponse::unpack(&mut ReadCursor::new(&bytes[64..]))?;
        if response.count as usize > count {
            return Err(Error::invalid_data("write exceeds request"));
        }
        Ok(response.count as usize)
    }
    pub fn directory(
        &mut self,
        file: FileId,
        restart: bool,
    ) -> Result<Vec<directory_info::DirectoryInfoEntry>> {
        let (_, bytes) = match self.call(
            Command::QueryDirectory,
            &query_directory::QueryDirectoryRequest {
                file_information_class:
                    query_directory::FileInformationClass::FileIdBothDirectoryInformation,
                flags: query_directory::QueryDirectoryFlags(if restart { 1 } else { 0 }),
                file_index: 0,
                file_id: file,
                output_buffer_length: 32768,
                file_name: "*".to_string(),
            },
        ) {
            Err(Error::Status(NO_MORE_FILES)) => return Ok(Vec::new()),
            r => r?,
        };
        let response =
            query_directory::QueryDirectoryResponse::unpack(&mut ReadCursor::new(&bytes[64..]))?;
        directory_info::parse_entries(
            query_directory::FileInformationClass::FileIdBothDirectoryInformation,
            &response.output_buffer,
        )
    }
    pub fn set_info(&mut self, file: FileId, class: u8, buffer: Vec<u8>) -> Result<()> {
        self.call(
            Command::SetInfo,
            &set_info::SetInfoRequest {
                info_type: query_info::InfoType::File,
                file_info_class: class,
                additional_information: 0,
                file_id: file,
                buffer,
            },
        )
        .map(|_| ())
    }
}
