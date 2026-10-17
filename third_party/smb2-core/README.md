# Freestanding SMB protocol code

Adapted from [vdavid/smb2](https://github.com/vdavid/smb2), commit
`a6e2b0fc8c27a2dd339f7f045bfee7600627c8c0` (0.31.0).
The upstream MIT and Apache-2.0 licenses are included here.

`src/pack`, `src/msg`, `src/types`, `src/name.rs`, and `src/auth` derive from
upstream. Changes replace `std` with `core`/`alloc`, remove the host
`SystemTime` convenience conversions, inject entropy and clock callbacks into
NTLM, check 32-bit offset arithmetic, and implement NTLM SPNEGO mechanism-list
MICs. Upstream tests remain alongside the source as reference; the host test
target here tests the adapted production library without enabling upstream's
application/runtime test dependencies.

`src/client.rs` is RetroOS's serialized SMB 2.0.2/2.1 session implementation.
It uses the upstream wire codecs and NTLMv2, with mandatory HMAC-SHA256
signing, bounded frames, response identity checks, and explicit connection
failure. It handles Samba's SPNEGO MIC exchange and asynchronous interim
responses. SMB3, encryption, Kerberos, DFS, leases, and reconnect are not
advertised by this client. The unused SMB3 wire types are retained to make
future upstream updates and dialect support straightforward.

There is no host networking, Tokio, or `std` dependency in the library. The
kernel supplies transport, entropy, time, VFS handles, and status mapping.
`probe.rs` is a separate host executable for testing the protocol library
against a Samba share; it is not linked into the kernel.

Validation:

```sh
bazelisk test //third_party/smb2-core:protocol_test
python3 test/smb.py
```

The second command requires QEMU, OVMF, gcc with 32-bit support, mtools, and
Samba's `smbd` and `pdbedit`. It starts an isolated server with mandatory
signing on a temporary unprivileged port, and never changes the system Samba
configuration. `SMB_TEST_SMBD` and `SMB_TEST_PDBEDIT` can select private binaries.
