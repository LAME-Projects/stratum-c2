//! Crypto primitives — RSA, AES-256-GCM helpers + staging file decrypt.
//! Protocol-level encrypt/decrypt (heartbeat, command, response) moved to epoch.rs (v2).

use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use rand::RngCore;
use zeroize::Zeroize;
use rsa::{
    pkcs8::DecodePublicKey,
    pss::{Signature as PssSignature, VerifyingKey},
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
pub(crate) fn rsa_pss_verify(pub_key: &PubKey, msg: &[u8], sig_bytes: &[u8]) -> bool {
    let vk  = VerifyingKey::<Sha256>::new(pub_key.clone());
    let sig = match PssSignature::try_from(sig_bytes) {
        Ok(s)  => s,
        Err(_) => return false,
    };
    vk.verify(msg, &sig).is_ok()
}

// ── AES-256-GCM ───────────────────────────────────────────────────────────────

pub(crate) fn gcm_seal(key_bytes: &[u8; 32], plaintext: &[u8]) -> Option<Vec<u8>> {
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

pub(crate) fn gcm_open(key_bytes: &[u8; 32], blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < 28 { return None; }  // 12 nonce + 16 tag minimum
    let nonce  = Nonce::from_slice(&blob[..12]);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_bytes));
    cipher.decrypt(nonce, &blob[12..]).ok()
}

pub(crate) fn slice_to_key32(b: &[u8]) -> Option<[u8; 32]> {
    if b.len() != 32 { return None; }
    let mut k = [0u8; 32];
    k.copy_from_slice(b);
    Some(k)
}

// ── protocol ──────────────────────────────────────────────────────────────────

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
