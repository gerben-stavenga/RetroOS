//! QMI service messages over a datagram transport (not the QMUX modem wrapper).
//! Header/TLV layout follows include/linux/soc/qcom/qmi.h. No Linux runtime.
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Packet,
    Busy,
    Timeout,
    Transaction,
    Remote { result: u16, error: u16 },
}
pub type Result<T> = core::result::Result<T, Error>;
pub const REQUEST: u8 = 0;
pub const RESPONSE: u8 = 2;
pub const INDICATION: u8 = 4;
const HEADER: usize = 7;
const MAX_BODY: usize = 8192 - HEADER;

pub fn tlv(out: &mut Vec<u8>, tag: u8, value: &[u8]) -> Result<()> {
    if value.len() > u16::MAX as usize || out.len() + 3 + value.len() > MAX_BODY {
        return Err(Error::Packet);
    }
    out.push(tag);
    out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    out.extend_from_slice(value);
    Ok(())
}

/// Validated message; unknown TLVs remain available to the service decoder.
pub struct Message<'a> {
    pub kind: u8,
    pub transaction: u16,
    pub id: u16,
    body: &'a [u8],
}
impl<'a> Message<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < HEADER || !matches!(bytes[0], REQUEST | RESPONSE | INDICATION) {
            return Err(Error::Packet);
        }
        let length = u16::from_le_bytes([bytes[5], bytes[6]]) as usize;
        if length > MAX_BODY || bytes.len() != HEADER + length {
            return Err(Error::Packet);
        }
        let this = Self {
            kind: bytes[0],
            transaction: u16::from_le_bytes([bytes[1], bytes[2]]),
            id: u16::from_le_bytes([bytes[3], bytes[4]]),
            body: &bytes[HEADER..],
        };
        // Reject ambiguous duplicate TLVs and incomplete tails before dispatch.
        let mut seen = [false; 256];
        let mut tail = this.body;
        while !tail.is_empty() {
            if tail.len() < 3 || seen[tail[0] as usize] {
                return Err(Error::Packet);
            }
            seen[tail[0] as usize] = true;
            let len = u16::from_le_bytes([tail[1], tail[2]]) as usize;
            tail = tail.get(3 + len..).ok_or(Error::Packet)?;
        }
        Ok(this)
    }
    pub fn get(&self, tag: u8) -> Option<&'a [u8]> {
        let mut tail = self.body;
        while !tail.is_empty() {
            let len = u16::from_le_bytes([tail[1], tail[2]]) as usize;
            if tail[0] == tag {
                return Some(&tail[3..3 + len]);
            }
            tail = &tail[3 + len..];
        }
        None
    }
    pub fn required(&self, tag: u8) -> Result<&'a [u8]> {
        self.get(tag).ok_or(Error::Packet)
    }
    pub fn success(&self) -> Result<()> {
        let value = self.required(2)?;
        if value.len() != 4 {
            return Err(Error::Packet);
        }
        let result = u16::from_le_bytes([value[0], value[1]]);
        let error = u16::from_le_bytes([value[2], value[3]]);
        if result == 0 && error == 0 {
            Ok(())
        } else {
            Err(Error::Remote { result, error })
        }
    }
}

pub fn encode(kind: u8, transaction: u16, id: u16, body: &[u8]) -> Result<Vec<u8>> {
    if body.len() > MAX_BODY {
        return Err(Error::Packet);
    }
    let mut bytes = Vec::with_capacity(HEADER + body.len());
    bytes.push(kind);
    bytes.extend_from_slice(&transaction.to_le_bytes());
    bytes.extend_from_slice(&id.to_le_bytes());
    bytes.extend_from_slice(&(body.len() as u16).to_le_bytes());
    bytes.extend_from_slice(body);
    Message::parse(&bytes)?;
    Ok(bytes)
}

/// One outstanding request; indications never consume its transaction.
pub struct Client {
    next: u16,
    pending: Option<(u16, u16, u64)>,
}
impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}
impl Client {
    pub fn new() -> Self {
        Self {
            next: 1,
            pending: None,
        }
    }
    pub fn request(&mut self, now: u64, timeout: u64, id: u16, body: &[u8]) -> Result<Vec<u8>> {
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        let bytes = encode(REQUEST, self.next, id, body)?;
        self.pending = Some((self.next, id, now.saturating_add(timeout)));
        self.next = self.next.wrapping_add(1).max(1);
        Ok(bytes)
    }
    pub fn check_timeout(&self, now: u64) -> Result<()> {
        if self.pending.is_some_and(|(_, _, deadline)| now >= deadline) {
            Err(Error::Timeout)
        } else {
            Ok(())
        }
    }
    pub fn receive<'a>(&mut self, bytes: &'a [u8]) -> Result<Option<Message<'a>>> {
        let message = Message::parse(bytes)?;
        if message.kind == INDICATION {
            return Ok(Some(message));
        }
        if message.kind != RESPONSE {
            return Err(Error::Packet);
        }
        let Some((transaction, id, _)) = self.pending else {
            return Ok(None);
        };
        if message.transaction != transaction {
            return Ok(None);
        }
        if message.id != id {
            return Err(Error::Transaction);
        }
        self.pending = None;
        message.success()?;
        Ok(Some(message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    #[test]
    fn service_header_and_tlv_match_wire_bytes() {
        let mut body = Vec::new();
        tlv(&mut body, 0x10, &[1]).unwrap();
        assert_eq!(
            encode(REQUEST, 0x1234, 0x20, &body).unwrap(),
            [0, 0x34, 0x12, 0x20, 0, 4, 0, 0x10, 1, 0, 1]
        );
        for length in 0..11 {
            let bytes = encode(REQUEST, 1, 0x20, &body).unwrap();
            assert!(Message::parse(&bytes[..length]).is_err());
        }
        for body in [vec![1, 3, 0, 0], vec![1, 0, 0, 1, 0, 0], vec![1]] {
            assert!(encode(RESPONSE, 1, 0x20, &body).is_err());
        }
        assert!(tlv(&mut Vec::new(), 1, &vec![0; 8192]).is_err());
    }
    #[test]
    fn matching_responses_errors_indications_and_deadlines() {
        let mut client = Client::new();
        client.request(100, 10, 0x20, &[]).unwrap();
        assert_eq!(client.request(100, 10, 0x24, &[]), Err(Error::Busy));
        let indication = encode(INDICATION, 0, 0x35, &[]).unwrap();
        assert_eq!(client.receive(&indication).unwrap().unwrap().id, 0x35);
        let ok = [2, 4, 0, 0, 0, 0, 0];
        assert!(
            client
                .receive(&encode(RESPONSE, 2, 0x20, &ok).unwrap())
                .unwrap()
                .is_none()
        );
        assert_eq!(client.check_timeout(109), Ok(()));
        assert_eq!(client.check_timeout(110), Err(Error::Timeout));
        assert!(matches!(
            client.receive(&encode(RESPONSE, 1, 0x24, &ok).unwrap()),
            Err(Error::Transaction)
        ));
        client
            .receive(&encode(RESPONSE, 1, 0x20, &ok).unwrap())
            .unwrap();
        client.request(200, 10, 0x34, &[]).unwrap();
        let fail = [2, 4, 0, 1, 0, 0x2a, 0];
        assert!(matches!(
            client.receive(&encode(RESPONSE, 2, 0x34, &fail).unwrap()),
            Err(Error::Remote {
                result: 1,
                error: 0x2a
            })
        ));
    }
}
