// SMB2 userspace client for Linux — connects to a Windows named pipe over TCP:445
//
// Implements only the minimal SMB2 subset needed to open and do I/O on a named pipe:
//   Negotiate → Session Setup (NTLMSSP anonymous) → Tree Connect (IPC$) → Create → Read/Write

use std::io::{self, Read, Write};
use std::net::{TcpStream, Shutdown};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use super::P2PTransport;

const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(30);

// ── SMB2 constants ──────────────────────────────────────────────────────────

const SMB2_MAGIC: &[u8; 4] = b"\xfeSMB";
const SMB2_NEGOTIATE: u16       = 0x0000;
const SMB2_SESSION_SETUP: u16   = 0x0001;
const SMB2_TREE_CONNECT: u16    = 0x0003;
const SMB2_CREATE: u16          = 0x0005;
const SMB2_READ: u16            = 0x0008;
const SMB2_WRITE: u16           = 0x0009;
const SMB2_FLAGS_NONE: u32 = 0;
const SMB2_HEADER_LEN: usize = 64;

// Dialects
const SMB2_DIALECT_202: u16 = 0x0202;
const SMB2_DIALECT_210: u16 = 0x0210;

// Create dispositions / access
const FILE_OPEN: u32 = 0x00000001;
const GENERIC_READ: u32  = 0x80000000;
const GENERIC_WRITE: u32 = 0x40000000;
const FILE_SHARE_READ: u32  = 0x00000001;
const FILE_SHARE_WRITE: u32 = 0x00000002;

// NTLMSSP
const NTLMSSP_NEGOTIATE: u32 = 1;

// ── NetBIOS session framing ─────────────────────────────────────────────────

fn nb_send(stream: &mut TcpStream, data: &[u8]) -> io::Result<()> {
    let len = data.len() as u32;
    let mut hdr = [0u8; 4];
    hdr[1] = ((len >> 16) & 0xFF) as u8;
    hdr[2] = ((len >> 8) & 0xFF) as u8;
    hdr[3] = (len & 0xFF) as u8;
    stream.write_all(&hdr)?;
    stream.write_all(data)?;
    stream.flush()
}

fn nb_recv(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr)?;
    let len = ((hdr[1] as usize) << 16) | ((hdr[2] as usize) << 8) | (hdr[3] as usize);
    if len > MAX_FRAME_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "SMB frame too large"));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

// ── SMB2 header builder ─────────────────────────────────────────────────────

struct Smb2Header {
    command:    u16,
    flags:      u32,
    message_id: u64,
    session_id: u64,
    tree_id:    u32,
}

impl Smb2Header {
    fn serialize(&self) -> [u8; SMB2_HEADER_LEN] {
        let mut h = [0u8; SMB2_HEADER_LEN];
        h[0..4].copy_from_slice(SMB2_MAGIC);
        // StructureSize = 64
        h[4] = 64; h[5] = 0;
        // CreditCharge = 1
        h[6] = 1; h[7] = 0;
        // Status = 0 (request)
        // Command
        h[12] = (self.command & 0xFF) as u8;
        h[13] = ((self.command >> 8) & 0xFF) as u8;
        // CreditRequest = 1
        h[14] = 1; h[15] = 0;
        // Flags
        h[16..20].copy_from_slice(&self.flags.to_le_bytes());
        // MessageId
        h[28..36].copy_from_slice(&self.message_id.to_le_bytes());
        // TreeId
        h[40..44].copy_from_slice(&self.tree_id.to_le_bytes());
        // SessionId
        h[44..52].copy_from_slice(&self.session_id.to_le_bytes());
        h
    }
}

fn parse_status(resp: &[u8]) -> io::Result<u32> {
    if resp.len() < SMB2_HEADER_LEN {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "short SMB2 response"));
    }
    if &resp[0..4] != SMB2_MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad SMB2 magic"));
    }
    Ok(u32::from_le_bytes([resp[8], resp[9], resp[10], resp[11]]))
}

fn parse_session_id(resp: &[u8]) -> u64 {
    u64::from_le_bytes([resp[44], resp[45], resp[46], resp[47],
                        resp[48], resp[49], resp[50], resp[51]])
}

fn parse_tree_id(resp: &[u8]) -> u32 {
    u32::from_le_bytes([resp[40], resp[41], resp[42], resp[43]])
}

// ── NTLMSSP anonymous negotiate token ───────────────────────────────────────

fn ntlmssp_negotiate_blob() -> Vec<u8> {
    let mut buf = Vec::with_capacity(40);
    buf.extend_from_slice(b"NTLMSSP\0");
    buf.extend_from_slice(&NTLMSSP_NEGOTIATE.to_le_bytes());
    // NegotiateFlags: NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_REQUEST_TARGET | NTLMSSP_NEGOTIATE_NTLM
    let flags: u32 = 0x00000001 | 0x00000004 | 0x00000200;
    buf.extend_from_slice(&flags.to_le_bytes());
    // DomainNameFields (len=0, maxlen=0, offset=0)
    buf.extend_from_slice(&[0u8; 8]);
    // WorkstationFields (len=0, maxlen=0, offset=0)
    buf.extend_from_slice(&[0u8; 8]);
    buf
}

fn ntlmssp_auth_blob_anonymous() -> Vec<u8> {
    let mut buf = Vec::with_capacity(88);
    buf.extend_from_slice(b"NTLMSSP\0");
    // MessageType = AUTHENTICATE (3)
    buf.extend_from_slice(&3u32.to_le_bytes());
    let fields_offset: u32 = 72; // fixed payload offset
    // LmChallengeResponse (len=0, max=0, offset=fields_offset)
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&fields_offset.to_le_bytes());
    // NtChallengeResponse (len=0, max=0, offset=fields_offset)
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&fields_offset.to_le_bytes());
    // DomainName (len=0, max=0, offset=fields_offset)
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&fields_offset.to_le_bytes());
    // UserName (len=0, max=0, offset=fields_offset)
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&fields_offset.to_le_bytes());
    // Workstation (len=0, max=0, offset=fields_offset)
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&fields_offset.to_le_bytes());
    // EncryptedRandomSessionKey (len=0, max=0, offset=fields_offset)
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&fields_offset.to_le_bytes());
    // NegotiateFlags
    let flags: u32 = 0x00000001 | 0x00000200;
    buf.extend_from_slice(&flags.to_le_bytes());
    buf
}

// ── GSS-API / SPNEGO wrappers ───────────────────────────────────────────────

fn spnego_init_token(ntlmssp: &[u8]) -> Vec<u8> {
    // mechType OID for NTLMSSP: 1.3.6.1.4.1.311.2.2.10
    let mech_oid: &[u8] = &[0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];
    // SPNEGO OID: 1.3.6.1.5.5.2
    let spnego_oid: &[u8] = &[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

    // mechToken [2] OCTET STRING
    let mech_token = asn1_context(2, &asn1_octet_string(ntlmssp));
    // mechTypes [0] SEQUENCE { OID }
    let mech_types = asn1_context(0, &asn1_sequence(&[mech_oid]));
    // negTokenInit SEQUENCE { mechTypes, mechToken }
    let neg_token_init = asn1_sequence_raw(&[&mech_types, &mech_token]);
    // [0] negTokenInit
    let inner = asn1_context(0, &neg_token_init);
    // APPLICATION [0] { SPNEGO_OID, inner }
    asn1_application_0(&[spnego_oid, &inner])
}

fn spnego_response_token(ntlmssp: &[u8]) -> Vec<u8> {
    // responseToken [2] OCTET STRING
    let resp_token = asn1_context(2, &asn1_octet_string(ntlmssp));
    // negTokenResp SEQUENCE { responseToken }
    let neg_token_resp = asn1_sequence_raw(&[&resp_token]);
    // [1] negTokenResp
    asn1_context(1, &neg_token_resp)
}

// ── ASN.1 DER helpers (minimal) ─────────────────────────────────────────────

fn asn1_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xFF {
        vec![0x81, len as u8]
    } else {
        vec![0x82, ((len >> 8) & 0xFF) as u8, (len & 0xFF) as u8]
    }
}

fn asn1_octet_string(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x04];
    out.extend_from_slice(&asn1_len(data.len()));
    out.extend_from_slice(data);
    out
}

fn asn1_context(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0xA0 | tag];
    out.extend_from_slice(&asn1_len(data.len()));
    out.extend_from_slice(data);
    out
}

fn asn1_sequence(items: &[&[u8]]) -> Vec<u8> {
    let total: usize = items.iter().map(|i| i.len()).sum();
    let mut out = vec![0x30];
    out.extend_from_slice(&asn1_len(total));
    for item in items { out.extend_from_slice(item); }
    out
}

fn asn1_sequence_raw(items: &[&[u8]]) -> Vec<u8> {
    asn1_sequence(items)
}

fn asn1_application_0(items: &[&[u8]]) -> Vec<u8> {
    let total: usize = items.iter().map(|i| i.len()).sum();
    let mut out = vec![0x60];
    out.extend_from_slice(&asn1_len(total));
    for item in items { out.extend_from_slice(item); }
    out
}

// ── SMB2 commands ───────────────────────────────────────────────────────────

struct Smb2Session {
    stream:     TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id:    u32,
    file_id:    [u8; 16],
    max_read:   u32,
    max_write:  u32,
}

impl Smb2Session {
    fn next_id(&mut self) -> u64 {
        let id = self.message_id;
        self.message_id += 1;
        id
    }

    fn send_smb2(&mut self, command: u16, flags: u32, body: &[u8]) -> io::Result<()> {
        let mid = self.next_id();
        let hdr = Smb2Header {
            command, flags, message_id: mid,
            session_id: self.session_id,
            tree_id: self.tree_id,
        }.serialize();
        let mut pkt = Vec::with_capacity(SMB2_HEADER_LEN + body.len());
        pkt.extend_from_slice(&hdr);
        pkt.extend_from_slice(body);
        nb_send(&mut self.stream, &pkt)
    }

    fn recv_smb2(&mut self) -> io::Result<Vec<u8>> {
        nb_recv(&mut self.stream)
    }
}

fn smb1_negotiate(stream: &mut TcpStream) -> io::Result<()> {
    // SMB1 COM_NEGOTIATE with "SMB 2.002" and "SMB 2.???" dialects.
    // Windows SMB server expects this as the first packet on port 445 before
    // accepting direct SMB2 framing.  It replies with an SMB2 Negotiate
    // Response (magic \xFESMB), which we discard — the real SMB2 Negotiate
    // follows immediately after.
    let dialects: &[&[u8]] = &[b"SMB 2.002", b"SMB 2.???"];
    let mut dialect_buf = Vec::new();
    for d in dialects {
        dialect_buf.push(0x02); // dialect buffer format
        dialect_buf.extend_from_slice(d);
        dialect_buf.push(0x00); // null terminator
    }
    // SMB1 header (32 bytes) + COM_NEGOTIATE body
    let mut pkt = Vec::with_capacity(32 + 3 + dialect_buf.len());
    // SMB1 magic
    pkt.extend_from_slice(b"\xffSMB");
    // Command = COM_NEGOTIATE (0x72)
    pkt.push(0x72);
    // Status (4 bytes) = 0
    pkt.extend_from_slice(&[0u8; 4]);
    // Flags = 0x18 (case-insensitive, canonical paths)
    pkt.push(0x18);
    // Flags2 = 0xC853 (unicode, NT status, extended security, long names)
    pkt.extend_from_slice(&0xC853u16.to_le_bytes());
    // PIDHigh, SecurityFeatures, Reserved, TID, PIDLow, UID, MID (18 bytes) = 0
    pkt.extend_from_slice(&[0u8; 18]);
    // WordCount = 0
    pkt.push(0);
    // ByteCount
    pkt.extend_from_slice(&(dialect_buf.len() as u16).to_le_bytes());
    // Dialect strings
    pkt.extend_from_slice(&dialect_buf);

    nb_send(stream, &pkt)?;
    // Read and discard the SMB1/SMB2 negotiate response
    let _resp = nb_recv(stream)?;
    Ok(())
}

fn negotiate(sess: &mut Smb2Session) -> io::Result<()> {
    // Phase 0: SMB1 COM_NEGOTIATE so Windows enters SMB2 mode
    smb1_negotiate(&mut sess.stream)?;

    // Phase 1: SMB2 NEGOTIATE request
    let mut body = Vec::with_capacity(36 + 4);
    // StructureSize = 36
    body.extend_from_slice(&36u16.to_le_bytes());
    // DialectCount = 2
    body.extend_from_slice(&2u16.to_le_bytes());
    // SecurityMode = NEGOTIATE_SIGNING_ENABLED (0x01)
    body.extend_from_slice(&1u16.to_le_bytes());
    // Reserved = 0
    body.extend_from_slice(&0u16.to_le_bytes());
    // Capabilities = 0
    body.extend_from_slice(&0u32.to_le_bytes());
    // ClientGuid (16 bytes random)
    let mut guid = [0u8; 16];
    for b in guid.iter_mut() { *b = rand::random(); }
    body.extend_from_slice(&guid);
    // ClientStartTime = 0
    body.extend_from_slice(&0u64.to_le_bytes());
    // Dialects
    body.extend_from_slice(&SMB2_DIALECT_202.to_le_bytes());
    body.extend_from_slice(&SMB2_DIALECT_210.to_le_bytes());

    sess.send_smb2(SMB2_NEGOTIATE, SMB2_FLAGS_NONE, &body)?;

    let resp = sess.recv_smb2()?;
    let status = parse_status(&resp)?;
    if status != 0 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied,
            format!("SMB2 NEGOTIATE failed: 0x{:08X}", status)));
    }

    // Parse MaxReadSize, MaxWriteSize from negotiate response
    if resp.len() >= SMB2_HEADER_LEN + 65 {
        let off = SMB2_HEADER_LEN;
        sess.max_read = u32::from_le_bytes([resp[off+32], resp[off+33], resp[off+34], resp[off+35]]);
        sess.max_write = u32::from_le_bytes([resp[off+36], resp[off+37], resp[off+38], resp[off+39]]);
    }

    Ok(())
}

fn session_setup(sess: &mut Smb2Session) -> io::Result<()> {
    // Phase 1: NTLMSSP Negotiate wrapped in SPNEGO
    let ntlmssp_neg = ntlmssp_negotiate_blob();
    let gss_token = spnego_init_token(&ntlmssp_neg);

    let mut body = Vec::with_capacity(24 + gss_token.len());
    // StructureSize = 25
    body.extend_from_slice(&25u16.to_le_bytes());
    // Flags = 0
    body.push(0);
    // SecurityMode = NEGOTIATE_SIGNING_ENABLED
    body.push(0x01);
    // Capabilities = 0
    body.extend_from_slice(&0u32.to_le_bytes());
    // Channel = 0
    body.extend_from_slice(&0u32.to_le_bytes());
    // SecurityBufferOffset = 88 (header 64 + body fixed 24)
    body.extend_from_slice(&88u16.to_le_bytes());
    // SecurityBufferLength
    body.extend_from_slice(&(gss_token.len() as u16).to_le_bytes());
    // PreviousSessionId = 0
    body.extend_from_slice(&0u64.to_le_bytes());
    // SecurityBuffer
    body.extend_from_slice(&gss_token);

    sess.send_smb2(SMB2_SESSION_SETUP, SMB2_FLAGS_NONE, &body)?;

    let resp = sess.recv_smb2()?;
    let status = parse_status(&resp)?;

    sess.session_id = parse_session_id(&resp);

    // STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016
    if status != 0xC0000016 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied,
            format!("SMB2 SESSION_SETUP phase1 unexpected: 0x{:08X}", status)));
    }

    // Extract NTLMSSP challenge from response (we don't actually need it for anonymous)
    // Phase 2: send NTLMSSP Auth (anonymous) wrapped in SPNEGO
    let ntlmssp_auth = ntlmssp_auth_blob_anonymous();
    let gss_token2 = spnego_response_token(&ntlmssp_auth);

    let mut body2 = Vec::with_capacity(24 + gss_token2.len());
    body2.extend_from_slice(&25u16.to_le_bytes());
    body2.push(0);
    body2.push(0x01);
    body2.extend_from_slice(&0u32.to_le_bytes());
    body2.extend_from_slice(&0u32.to_le_bytes());
    body2.extend_from_slice(&88u16.to_le_bytes());
    body2.extend_from_slice(&(gss_token2.len() as u16).to_le_bytes());
    body2.extend_from_slice(&0u64.to_le_bytes());
    body2.extend_from_slice(&gss_token2);

    sess.send_smb2(SMB2_SESSION_SETUP, SMB2_FLAGS_NONE, &body2)?;

    let resp2 = sess.recv_smb2()?;
    let status2 = parse_status(&resp2)?;

    sess.session_id = parse_session_id(&resp2);

    // STATUS_SUCCESS = 0 or STATUS_MORE_PROCESSING_REQUIRED
    if status2 != 0 && status2 != 0xC0000016 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied,
            format!("SMB2 SESSION_SETUP phase2 failed: 0x{:08X}", status2)));
    }

    Ok(())
}

fn tree_connect(sess: &mut Smb2Session, target: &str) -> io::Result<()> {
    let path = format!("\\\\{}\\IPC$", target);
    let path_utf16: Vec<u8> = path.encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let mut body = Vec::with_capacity(8 + path_utf16.len());
    // StructureSize = 9
    body.extend_from_slice(&9u16.to_le_bytes());
    // Reserved = 0
    body.extend_from_slice(&0u16.to_le_bytes());
    // PathOffset = 72 (header 64 + body fixed 8)
    body.extend_from_slice(&72u16.to_le_bytes());
    // PathLength
    body.extend_from_slice(&(path_utf16.len() as u16).to_le_bytes());
    // Path (UTF-16LE)
    body.extend_from_slice(&path_utf16);

    sess.send_smb2(SMB2_TREE_CONNECT, SMB2_FLAGS_NONE, &body)?;

    let resp = sess.recv_smb2()?;
    let status = parse_status(&resp)?;
    if status != 0 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied,
            format!("SMB2 TREE_CONNECT to IPC$ failed: 0x{:08X}", status)));
    }

    sess.tree_id = parse_tree_id(&resp);
    Ok(())
}

fn create_pipe(sess: &mut Smb2Session, pipe_name: &str) -> io::Result<()> {
    let name_utf16: Vec<u8> = pipe_name.encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let mut body = Vec::with_capacity(56 + name_utf16.len());
    // StructureSize = 57
    body.extend_from_slice(&57u16.to_le_bytes());
    // SecurityFlags = 0
    body.push(0);
    // RequestedOplockLevel = SMB2_OPLOCK_LEVEL_NONE
    body.push(0);
    // ImpersonationLevel = Impersonation (2)
    body.extend_from_slice(&2u32.to_le_bytes());
    // SmbCreateFlags = 0
    body.extend_from_slice(&0u64.to_le_bytes());
    // Reserved = 0
    body.extend_from_slice(&0u64.to_le_bytes());
    // DesiredAccess
    body.extend_from_slice(&(GENERIC_READ | GENERIC_WRITE).to_le_bytes());
    // FileAttributes = 0
    body.extend_from_slice(&0u32.to_le_bytes());
    // ShareAccess
    body.extend_from_slice(&(FILE_SHARE_READ | FILE_SHARE_WRITE).to_le_bytes());
    // CreateDisposition = FILE_OPEN
    body.extend_from_slice(&FILE_OPEN.to_le_bytes());
    // CreateOptions = 0
    body.extend_from_slice(&0u32.to_le_bytes());
    // NameOffset = 120 (header 64 + body fixed 56)
    body.extend_from_slice(&120u16.to_le_bytes());
    // NameLength
    body.extend_from_slice(&(name_utf16.len() as u16).to_le_bytes());
    // CreateContextsOffset = 0
    body.extend_from_slice(&0u32.to_le_bytes());
    // CreateContextsLength = 0
    body.extend_from_slice(&0u32.to_le_bytes());
    // Name (UTF-16LE)
    body.extend_from_slice(&name_utf16);

    sess.send_smb2(SMB2_CREATE, SMB2_FLAGS_NONE, &body)?;

    let resp = sess.recv_smb2()?;
    let status = parse_status(&resp)?;
    if status != 0 {
        return Err(io::Error::new(io::ErrorKind::ConnectionRefused,
            format!("SMB2 CREATE pipe '{}' failed: 0x{:08X}", pipe_name, status)));
    }

    // FileId is at response body offset 64+64 = 128, 16 bytes
    if resp.len() < SMB2_HEADER_LEN + 88 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "CREATE response too short"));
    }
    let fid_off = SMB2_HEADER_LEN + 64;
    sess.file_id.copy_from_slice(&resp[fid_off..fid_off + 16]);
    Ok(())
}

fn smb2_write(sess: &mut Smb2Session, data: &[u8]) -> io::Result<()> {
    let mut body = Vec::with_capacity(48 + data.len());
    // StructureSize = 49
    body.extend_from_slice(&49u16.to_le_bytes());
    // DataOffset = 112 (header 64 + body fixed 48)
    body.extend_from_slice(&112u16.to_le_bytes());
    // Length
    body.extend_from_slice(&(data.len() as u32).to_le_bytes());
    // Offset = 0 (pipes ignore offset)
    body.extend_from_slice(&0u64.to_le_bytes());
    // FileId
    body.extend_from_slice(&sess.file_id);
    // Channel = 0
    body.extend_from_slice(&0u32.to_le_bytes());
    // RemainingBytes = 0
    body.extend_from_slice(&0u32.to_le_bytes());
    // WriteChannelInfoOffset = 0
    body.extend_from_slice(&0u16.to_le_bytes());
    // WriteChannelInfoLength = 0
    body.extend_from_slice(&0u16.to_le_bytes());
    // Flags = 0
    body.extend_from_slice(&0u32.to_le_bytes());
    // Data
    body.extend_from_slice(data);

    sess.send_smb2(SMB2_WRITE, SMB2_FLAGS_NONE, &body)?;

    let resp = sess.recv_smb2()?;
    let status = parse_status(&resp)?;
    if status != 0 {
        return Err(io::Error::new(io::ErrorKind::BrokenPipe,
            format!("SMB2 WRITE failed: 0x{:08X}", status)));
    }
    Ok(())
}

fn smb2_read(sess: &mut Smb2Session, max_len: u32) -> io::Result<Vec<u8>> {
    let read_size = max_len.min(sess.max_read).max(4096);

    let mut body = Vec::with_capacity(48);
    // StructureSize = 49
    body.extend_from_slice(&49u16.to_le_bytes());
    // Padding = 0
    body.push(0);
    // Flags = 0
    body.push(0);
    // Length
    body.extend_from_slice(&read_size.to_le_bytes());
    // Offset = 0
    body.extend_from_slice(&0u64.to_le_bytes());
    // FileId
    body.extend_from_slice(&sess.file_id);
    // MinimumCount = 0
    body.extend_from_slice(&0u32.to_le_bytes());
    // Channel = 0
    body.extend_from_slice(&0u32.to_le_bytes());
    // RemainingBytes = 0
    body.extend_from_slice(&0u32.to_le_bytes());
    // ReadChannelInfoOffset = 0
    body.extend_from_slice(&0u16.to_le_bytes());
    // ReadChannelInfoLength = 0
    body.extend_from_slice(&0u16.to_le_bytes());
    // Buffer (1 byte minimum)
    body.push(0);

    sess.send_smb2(SMB2_READ, SMB2_FLAGS_NONE, &body)?;

    let resp = sess.recv_smb2()?;
    let status = parse_status(&resp)?;
    if status != 0 {
        return Err(io::Error::new(io::ErrorKind::BrokenPipe,
            format!("SMB2 READ failed: 0x{:08X}", status)));
    }

    // Parse read response: DataOffset (byte offset from header start), DataLength
    if resp.len() < SMB2_HEADER_LEN + 16 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "READ response too short"));
    }
    let data_offset = resp[SMB2_HEADER_LEN + 2] as usize;
    let data_length = u32::from_le_bytes([
        resp[SMB2_HEADER_LEN + 4], resp[SMB2_HEADER_LEN + 5],
        resp[SMB2_HEADER_LEN + 6], resp[SMB2_HEADER_LEN + 7],
    ]) as usize;

    if data_offset + data_length > resp.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "READ data overflow"));
    }

    Ok(resp[data_offset..data_offset + data_length].to_vec())
}

// ── P2PTransport implementation over SMB2 ───────────────────────────────────

pub struct SmbClientTransport {
    session: Mutex<Smb2Session>,
    alive:   AtomicBool,
    peer:    String,
}

impl P2PTransport for SmbClientTransport {
    fn send(&self, data: &[u8]) -> io::Result<()> {
        let mut sess = self.session.lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "lock poisoned"))?;
        // Length-prefix framing (same as TCP/Win32 SMB transports)
        let len_bytes = (data.len() as u32).to_le_bytes();
        let mut frame = Vec::with_capacity(4 + data.len());
        frame.extend_from_slice(&len_bytes);
        frame.extend_from_slice(data);
        smb2_write(&mut sess, &frame)
    }

    fn recv(&self) -> io::Result<Vec<u8>> {
        let mut sess = self.session.lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "lock poisoned"))?;
        // Read 4-byte length prefix
        let len_data = smb2_read(&mut sess, 4)?;
        if len_data.len() < 4 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "short length prefix"));
        }
        let len = u32::from_le_bytes([len_data[0], len_data[1], len_data[2], len_data[3]]) as usize;
        if len > MAX_FRAME_SIZE {
            self.alive.store(false, Ordering::SeqCst);
            return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
        }
        if len == 0 {
            return Ok(Vec::new());
        }
        // Read payload — may need multiple reads
        let mut payload = Vec::with_capacity(len);
        while payload.len() < len {
            let remaining = (len - payload.len()) as u32;
            let chunk = smb2_read(&mut sess, remaining)?;
            if chunk.is_empty() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "pipe closed"));
            }
            payload.extend_from_slice(&chunk);
        }
        Ok(payload)
    }

    fn close(&self) {
        self.alive.store(false, Ordering::SeqCst);
        if let Ok(sess) = self.session.lock() {
            let _ = sess.stream.shutdown(Shutdown::Both);
        }
    }

    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }

    fn peer_addr(&self) -> String {
        self.peer.clone()
    }
}

// ── Public connect function ─────────────────────────────────────────────────

pub fn smb_client_connect(target: &str, pipe_name: &str) -> io::Result<SmbClientTransport> {
    let addr = if target.contains(':') {
        target.to_string()
    } else {
        format!("{}:445", target)
    };

    let stream = TcpStream::connect_timeout(
        &addr.parse().map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
        CONNECT_TIMEOUT,
    )?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    stream.set_nodelay(true)?;
    super::configure_keepalive(&stream);

    let peer = format!("\\\\{}\\pipe\\{}", target, pipe_name);

    let mut sess = Smb2Session {
        stream,
        message_id: 0,
        session_id: 0,
        tree_id: 0,
        file_id: [0u8; 16],
        max_read: 65536,
        max_write: 65536,
    };

    negotiate(&mut sess)?;
    session_setup(&mut sess)?;
    tree_connect(&mut sess, target)?;
    create_pipe(&mut sess, pipe_name)?;

    Ok(SmbClientTransport {
        session: Mutex::new(sess),
        alive: AtomicBool::new(true),
        peer,
    })
}
