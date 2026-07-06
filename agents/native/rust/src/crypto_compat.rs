//! Stage2 / config decrypt for Stratum agents.
//!
//! Supports two wire formats:
//!   GCM (current): "SGCM:" + base64(salt[8] + nonce[12] + ciphertext + tag[16])
//!   CBC (legacy):  base64("Salted__" + salt[8] + ciphertext)  — backward compat only
//!
//! Key derivation: PBKDF2-HMAC-SHA256, 210 000 iterations.
//!   GCM: 32-byte key only.
//!   CBC: 48-byte key+IV.

use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, Nonce}};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use rand::RngCore;

const ITER:      u32   = 210_000;
const CBC_MAGIC: &[u8] = b"Salted__";
const GCM_PFX:   &str  = "SGCM:";

// ── GCM ───────────────────────────────────────────────────────────────────────

fn derive_gcm(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut dk = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, ITER, &mut dk);
    dk
}

fn gcm_decrypt(password: &str, b64: &str) -> Option<String> {
    let raw = B64.decode(b64.trim()).ok()?;
    if raw.len() < 36 { return None; }   // 8 + 12 + 16 minimum
    let (salt, rest) = raw.split_at(8);
    let (nonce_bytes, ct_tag) = rest.split_at(12);
    let key   = derive_gcm(password, salt);
    let cipher = Aes256Gcm::new_from_slice(&key).ok()?;
    let nonce  = Nonce::<Aes256Gcm>::from_slice(nonce_bytes);
    let pt     = cipher.decrypt(nonce, ct_tag).ok()?;
    String::from_utf8(pt).ok()
}

fn gcm_encrypt(password: &str, plaintext: &[u8]) -> String {
    let mut salt  = [0u8; 8];
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let key    = derive_gcm(password, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let nonce  = Nonce::<Aes256Gcm>::from_slice(&nonce_bytes);
    let ct_tag = cipher.encrypt(nonce, plaintext).unwrap();
    let mut out = Vec::with_capacity(20 + ct_tag.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct_tag);
    format!("{}{}", GCM_PFX, B64.encode(out))
}

// ── CBC (legacy) ──────────────────────────────────────────────────────────────

fn derive_cbc(password: &str, salt: &[u8]) -> ([u8; 32], [u8; 16]) {
    let mut dk = [0u8; 48];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, ITER, &mut dk);
    let mut key = [0u8; 32]; key.copy_from_slice(&dk[..32]);
    let mut iv  = [0u8; 16]; iv.copy_from_slice(&dk[32..48]);
    (key, iv)
}

fn cbc_decrypt(password: &str, b64: &str) -> Option<String> {
    let raw = B64.decode(b64.trim()).ok()?;
    if raw.len() < 16 || &raw[..8] != CBC_MAGIC { return None; }
    let (key, iv) = derive_cbc(password, &raw[8..16]);
    let pt = Decryptor::<Aes256>::new(&key.into(), &iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(&raw[16..])
        .ok()?;
    String::from_utf8(pt).ok()
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Decrypt stage2 / config blob. Accepts both GCM (current) and CBC (legacy) formats.
pub fn stratum_decrypt(password: &str, blob: &str) -> Option<String> {
    if let Some(b64) = blob.strip_prefix(GCM_PFX) {
        gcm_decrypt(password, b64)
    } else {
        cbc_decrypt(password, blob)
    }
}

/// Decrypt to raw bytes — for binary payloads (e.g. Windows DLL stage2)
/// where the plaintext is not valid UTF-8.  GCM format only.
pub fn stratum_decrypt_bytes(password: &str, blob: &str) -> Option<Vec<u8>> {
    let b64 = blob.strip_prefix(GCM_PFX)?;
    let raw = B64.decode(b64.trim()).ok()?;
    if raw.len() < 36 { return None; }
    let (salt, rest)       = raw.split_at(8);
    let (nonce_bytes, ct_tag) = rest.split_at(12);
    let key    = derive_gcm(password, salt);
    let cipher = Aes256Gcm::new_from_slice(&key).ok()?;
    let nonce  = Nonce::<Aes256Gcm>::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ct_tag).ok()
}

/// Encrypt using current GCM format.
pub fn stratum_encrypt(password: &str, plaintext: &[u8]) -> String {
    gcm_encrypt(password, plaintext)
}

// ── Legacy aliases (hw.rs uses openssl_encrypt for blob re-encryption) ────────

pub fn openssl_decrypt(password: &str, b64: &str) -> Option<String> {
    stratum_decrypt(password, b64)
}

pub fn openssl_encrypt(password: &str, plaintext: &[u8]) -> String {
    stratum_encrypt(password, plaintext)
}
