use hmac::{Hmac, Mac};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::crypto::{gcm_seal, gcm_open, slice_to_key32, rsa_pss_verify, PubKey};

type HmacSha256 = Hmac<Sha256>;

const VERSION_BYTE: u8 = 0x02;
const MAX_SKIP: u64 = 10;

#[derive(Clone)]
pub struct EpochState {
    pub epoch: u32,
    pub epoch_key: [u8; 32],
    pub chain_key: [u8; 32],
    pub counter: u64,
    pub my_eph_priv: [u8; 32],
    pub my_eph_pub: [u8; 32],
    pub prev_epoch_key: Option<[u8; 32]>,
}

impl Drop for EpochState {
    fn drop(&mut self) {
        self.epoch_key.zeroize();
        self.chain_key.zeroize();
        self.my_eph_priv.zeroize();
        if let Some(ref mut k) = self.prev_epoch_key {
            k.zeroize();
        }
    }
}

fn hkdf_derive(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out).expect("HKDF expand");
    out
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn x25519_dh(my_priv: &[u8; 32], their_pub: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*my_priv);
    let public = PublicKey::from(*their_pub);
    *secret.diffie_hellman(&public).as_bytes()
}

fn gen_ephemeral() -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::random_from_rng(rand::thread_rng());
    let public = PublicKey::from(&secret);
    let mut priv_bytes = [0u8; 32];
    priv_bytes.copy_from_slice(&secret.to_bytes());
    (priv_bytes, *public.as_bytes())
}

pub fn derive_agent_id(session_key: &[u8; 32]) -> Vec<u8> {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(b"stratum-agent-id:");
    h.update(session_key);
    h.finalize().to_vec()
}

pub fn bootstrap_epoch(
    prekey_pub: &[u8; 32],
    session_key: &[u8; 32],
    agent_id: &[u8],
) -> EpochState {
    let (eph_priv, eph_pub) = gen_ephemeral();
    let shared = x25519_dh(&eph_priv, prekey_pub);
    let epoch_key = hkdf_derive(&shared, session_key, b"stratum-epoch-0");
    let chain_key = hkdf_derive(&epoch_key, agent_id, b"stratum-chain-v1");

    EpochState {
        epoch: 0,
        epoch_key,
        chain_key,
        counter: 0,
        my_eph_priv: eph_priv,
        my_eph_pub: eph_pub,
        prev_epoch_key: None,
    }
}

pub fn rotate_epoch(state: &mut EpochState, server_eph_pub: &[u8; 32], agent_id: &[u8]) {
    let (new_priv, new_pub) = gen_ephemeral();
    let shared = x25519_dh(&new_priv, server_eph_pub);
    let info_str = format!("stratum-epoch-{}", state.epoch + 1);
    let new_epoch_key = hkdf_derive(&shared, &state.epoch_key, info_str.as_bytes());
    let new_chain_key = hkdf_derive(&new_epoch_key, agent_id, b"stratum-chain-v1");

    let mut old_ek = [0u8; 32];
    old_ek.copy_from_slice(&state.epoch_key);

    state.epoch_key.zeroize();
    state.my_eph_priv.zeroize();

    state.prev_epoch_key = Some(old_ek);
    state.epoch += 1;
    state.epoch_key = new_epoch_key;
    state.chain_key = new_chain_key;
    state.counter = 0;
    state.my_eph_priv = new_priv;
    state.my_eph_pub = new_pub;
}

pub fn chain_advance(state: &mut EpochState, payload: &[u8]) -> ([u8; 32], u64) {
    let msg_key = hmac_sha256(&state.chain_key, &[0x01]);
    state.chain_key = hmac_sha256(&state.chain_key, &[0x02]);
    let counter = state.counter;
    state.counter += 1;

    let mut tag_input = Vec::with_capacity(payload.len() + 8);
    tag_input.extend_from_slice(&counter.to_le_bytes());
    tag_input.extend_from_slice(payload);
    let tag = hmac_sha256(&msg_key, &tag_input);

    (tag, counter)
}

pub fn chain_verify(
    state: &mut EpochState,
    claimed_counter: u64,
    payload: &[u8],
    claimed_tag: &[u8; 32],
) -> bool {
    if claimed_counter < state.counter {
        return false;
    }
    if claimed_counter > state.counter + MAX_SKIP {
        return false;
    }

    let mut tmp_chain = state.chain_key;
    let mut tmp_counter = state.counter;

    while tmp_counter < claimed_counter {
        let _msg_key = hmac_sha256(&tmp_chain, &[0x01]);
        tmp_chain = hmac_sha256(&tmp_chain, &[0x02]);
        tmp_counter += 1;
    }

    let msg_key = hmac_sha256(&tmp_chain, &[0x01]);
    let next_chain = hmac_sha256(&tmp_chain, &[0x02]);

    let mut tag_input = Vec::with_capacity(payload.len() + 8);
    tag_input.extend_from_slice(&claimed_counter.to_le_bytes());
    tag_input.extend_from_slice(payload);
    let expected = hmac_sha256(&msg_key, &tag_input);

    if expected == *claimed_tag {
        state.chain_key = next_chain;
        state.counter = claimed_counter + 1;
        true
    } else {
        false
    }
}

pub fn encrypt_message_v2(state: &mut EpochState, plaintext: &[u8]) -> Option<Vec<u8>> {
    let gcm_payload = gcm_seal(&state.epoch_key, plaintext)?;
    let (tag, counter) = chain_advance(state, &gcm_payload);

    let mut out = Vec::with_capacity(1 + 4 + 32 + 8 + 32 + gcm_payload.len());
    out.push(VERSION_BYTE);
    out.extend_from_slice(&state.epoch.to_le_bytes());
    out.extend_from_slice(&state.my_eph_pub);
    out.extend_from_slice(&counter.to_le_bytes());
    out.extend_from_slice(&tag);
    out.extend_from_slice(&gcm_payload);
    Some(out)
}

pub fn decrypt_command_v2(
    raw: &[u8],
    state: &mut EpochState,
    pub_key: &PubKey,
    session_key: &[u8; 32],
    agent_id: &[u8],
    prekey_pub: &[u8; 32],
) -> Option<crate::protocol::Task> {
    if raw.len() < 1 + 4 + 32 + 4 + 32 + 28 {
        return None;
    }
    if raw[0] != VERSION_BYTE {
        return None;
    }

    let server_epoch = u32::from_le_bytes([raw[1], raw[2], raw[3], raw[4]]);
    let mut server_eph_pub = [0u8; 32];
    server_eph_pub.copy_from_slice(&raw[5..37]);

    let rest = &raw[37..];

    // Server wire: [wrapped_aes: GCM(epoch_key)] [payload: GCM(aes_key)] [sig: PSS]
    // wrapped_aes len prefix (4 bytes LE)
    if rest.len() < 4 {
        return None;
    }
    let wrapped_len = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
    if rest.len() < 4 + wrapped_len + 4 {
        return None;
    }
    let wrapped_aes = &rest[4..4 + wrapped_len];

    let rest2 = &rest[4 + wrapped_len..];
    if rest2.len() < 4 {
        return None;
    }
    let payload_len = u32::from_le_bytes([rest2[0], rest2[1], rest2[2], rest2[3]]) as usize;
    if rest2.len() < 4 + payload_len {
        return None;
    }
    let payload_blob = &rest2[4..4 + payload_len];
    let sig = &rest2[4 + payload_len..];

    // Verify PSS over wrapped_aes || payload_blob
    let mut sig_msg = Vec::with_capacity(wrapped_aes.len() + payload_blob.len());
    sig_msg.extend_from_slice(wrapped_aes);
    sig_msg.extend_from_slice(payload_blob);
    if !rsa_pss_verify(pub_key, &sig_msg, sig) {
        return None;
    }

    // Handle epoch rotation
    if server_epoch > state.epoch {
        rotate_epoch(state, &server_eph_pub, agent_id);
    } else if server_epoch + 1 < state.epoch {
        // Server far behind — re-bootstrap
        *state = bootstrap_epoch(prekey_pub, session_key, agent_id);
    }

    // Try current epoch_key first, then prev_epoch_key
    let aes_key_bytes = gcm_open(&state.epoch_key, wrapped_aes)
        .or_else(|| {
            state.prev_epoch_key.as_ref().and_then(|pk| gcm_open(pk, wrapped_aes))
        })?;

    let mut aes_key = slice_to_key32(&aes_key_bytes)?;
    let plain = gcm_open(&aes_key, payload_blob);
    aes_key.zeroize();

    let text = String::from_utf8(plain?).ok()?;
    let task: crate::protocol::Task = serde_json::from_str(&text).ok()?;
    Some(task)
}

pub fn decrypt_command_v2_raw(
    raw: &[u8],
    state: &mut EpochState,
    pub_key: &PubKey,
    session_key: &[u8; 32],
    agent_id: &[u8],
    prekey_pub: &[u8; 32],
) -> Option<(crate::protocol::Task, Vec<u8>)> {
    if raw.len() < 1 + 4 + 32 + 4 + 32 + 28 { return None; }
    if raw[0] != VERSION_BYTE { return None; }
    let server_epoch = u32::from_le_bytes([raw[1], raw[2], raw[3], raw[4]]);
    let mut server_eph_pub = [0u8; 32];
    server_eph_pub.copy_from_slice(&raw[5..37]);
    let rest = &raw[37..];
    if rest.len() < 4 { return None; }
    let wrapped_len = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
    if rest.len() < 4 + wrapped_len + 4 { return None; }
    let wrapped_aes = &rest[4..4 + wrapped_len];
    let rest2 = &rest[4 + wrapped_len..];
    if rest2.len() < 4 { return None; }
    let payload_len = u32::from_le_bytes([rest2[0], rest2[1], rest2[2], rest2[3]]) as usize;
    if rest2.len() < 4 + payload_len { return None; }
    let payload_blob = &rest2[4..4 + payload_len];
    let sig = &rest2[4 + payload_len..];
    let mut sig_msg = Vec::with_capacity(wrapped_aes.len() + payload_blob.len());
    sig_msg.extend_from_slice(wrapped_aes);
    sig_msg.extend_from_slice(payload_blob);
    if !rsa_pss_verify(pub_key, &sig_msg, sig) { return None; }
    if server_epoch > state.epoch {
        rotate_epoch(state, &server_eph_pub, agent_id);
    } else if server_epoch + 1 < state.epoch {
        *state = bootstrap_epoch(prekey_pub, session_key, agent_id);
    }
    let aes_key_bytes = gcm_open(&state.epoch_key, wrapped_aes)
        .or_else(|| state.prev_epoch_key.as_ref().and_then(|pk| gcm_open(pk, wrapped_aes)))?;
    let mut aes_key = slice_to_key32(&aes_key_bytes)?;
    let plain = gcm_open(&aes_key, payload_blob);
    aes_key.zeroize();
    let plain_bytes = plain?;
    let text = String::from_utf8(plain_bytes.clone()).ok()?;
    let task: crate::protocol::Task = serde_json::from_str(&text).ok()?;
    Some((task, plain_bytes))
}

pub fn prekey_fingerprint(pool: &[[u8; 32]]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(b"stratum-prekey-fp:");
    for k in pool {
        h.update(k);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

pub fn epoch_state_to_bytes_v2(state: &EpochState, pool: &[[u8; 32]]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(205);
    buf.extend_from_slice(&state.epoch.to_le_bytes());       // 4
    buf.extend_from_slice(&state.epoch_key);                  // 32
    buf.extend_from_slice(&state.chain_key);                  // 32
    buf.extend_from_slice(&state.counter.to_le_bytes());      // 8
    buf.extend_from_slice(&state.my_eph_priv);                // 32
    buf.extend_from_slice(&state.my_eph_pub);                 // 32
    match &state.prev_epoch_key {
        Some(k) => { buf.push(1); buf.extend_from_slice(k); } // 1+32
        None    => { buf.push(0); buf.extend_from_slice(&[0u8; 32]); }
    }
    buf.extend_from_slice(&prekey_fingerprint(pool));          // 32
    buf // total: 173 + 32 = 205
}

pub fn epoch_state_to_bytes(state: &EpochState) -> Vec<u8> {
    epoch_state_to_bytes_v2(state, &[])
}

pub fn epoch_state_from_bytes_with_fp(data: &[u8], pool: &[[u8; 32]]) -> Option<EpochState> {
    if data.len() < 173 {
        return None;
    }
    if data.len() >= 205 {
        let mut cached_fp = [0u8; 32];
        cached_fp.copy_from_slice(&data[173..205]);
        if cached_fp != prekey_fingerprint(pool) {
            return None;
        }
    } else if !pool.is_empty() {
        return None;
    }
    let epoch = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let mut epoch_key = [0u8; 32];
    epoch_key.copy_from_slice(&data[4..36]);
    let mut chain_key = [0u8; 32];
    chain_key.copy_from_slice(&data[36..68]);
    let counter = u64::from_le_bytes([
        data[68], data[69], data[70], data[71],
        data[72], data[73], data[74], data[75],
    ]);
    let mut my_eph_priv = [0u8; 32];
    my_eph_priv.copy_from_slice(&data[76..108]);
    let mut my_eph_pub = [0u8; 32];
    my_eph_pub.copy_from_slice(&data[108..140]);
    let has_prev = data[140];
    let prev_epoch_key = if has_prev == 1 {
        let mut k = [0u8; 32];
        k.copy_from_slice(&data[141..173]);
        Some(k)
    } else {
        None
    };

    Some(EpochState {
        epoch,
        epoch_key,
        chain_key,
        counter,
        my_eph_priv,
        my_eph_pub,
        prev_epoch_key,
    })
}

pub fn epoch_state_from_bytes(data: &[u8]) -> Option<EpochState> {
    epoch_state_from_bytes_with_fp(data, &[])
}

pub fn is_v2(raw: &[u8]) -> bool {
    !raw.is_empty() && raw[0] == VERSION_BYTE
}

pub fn decode_prekey_pool(pool_b64: &str) -> Vec<[u8; 32]> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let bytes = match B64.decode(pool_b64) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    if bytes.len() % 32 != 0 {
        return Vec::new();
    }
    bytes.chunks_exact(32).map(|c| {
        let mut k = [0u8; 32];
        k.copy_from_slice(c);
        k
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_and_chain() {
        let session_key = [0xAA; 32];
        let agent_id = b"test-agent-id";

        let (_, prekey_pub) = gen_ephemeral();
        let mut state = bootstrap_epoch(&prekey_pub, &session_key, agent_id);

        assert_eq!(state.epoch, 0);
        assert_eq!(state.counter, 0);

        let payload = b"hello world";
        let (tag, counter) = chain_advance(&mut state, payload);
        assert_eq!(counter, 0);
        assert_eq!(state.counter, 1);

        // tag should be deterministic for same inputs (but we can't recompute without the chain_key before advance)
        assert_ne!(tag, [0u8; 32]);
    }

    #[test]
    fn chain_verify_ok() {
        let session_key = [0xBB; 32];
        let agent_id = b"verify-agent";
        let (_, prekey_pub) = gen_ephemeral();

        // Simulate server and agent with same bootstrap
        let (eph_priv, eph_pub) = gen_ephemeral();
        let shared = x25519_dh(&eph_priv, &prekey_pub);
        let epoch_key = hkdf_derive(&shared, &session_key, b"stratum-epoch-0");
        let chain_key = hkdf_derive(&epoch_key, agent_id, b"stratum-chain-v1");

        let mut sender = EpochState {
            epoch: 0, epoch_key, chain_key,
            counter: 0, my_eph_priv: eph_priv, my_eph_pub: eph_pub,
            prev_epoch_key: None,
        };
        let mut receiver = sender.clone();

        let payload = b"test payload";
        let (tag, counter) = chain_advance(&mut sender, payload);
        assert!(chain_verify(&mut receiver, counter, payload, &tag));
    }

    #[test]
    fn chain_verify_tampered() {
        let session_key = [0xCC; 32];
        let agent_id = b"tamper-agent";
        let (_, prekey_pub) = gen_ephemeral();
        let (eph_priv, eph_pub) = gen_ephemeral();
        let shared = x25519_dh(&eph_priv, &prekey_pub);
        let epoch_key = hkdf_derive(&shared, &session_key, b"stratum-epoch-0");
        let chain_key = hkdf_derive(&epoch_key, agent_id, b"stratum-chain-v1");

        let mut sender = EpochState {
            epoch: 0, epoch_key, chain_key,
            counter: 0, my_eph_priv: eph_priv, my_eph_pub: eph_pub,
            prev_epoch_key: None,
        };
        let mut receiver = sender.clone();

        let payload = b"real payload";
        let (tag, counter) = chain_advance(&mut sender, payload);
        assert!(!chain_verify(&mut receiver, counter, b"tampered payload", &tag));
    }

    #[test]
    fn serialization_roundtrip() {
        let session_key = [0xDD; 32];
        let agent_id = b"serial-agent";
        let (_, prekey_pub) = gen_ephemeral();
        let state = bootstrap_epoch(&prekey_pub, &session_key, agent_id);
        let pool = vec![prekey_pub];

        let bytes = epoch_state_to_bytes_v2(&state, &pool);
        assert_eq!(bytes.len(), 205);

        let restored = epoch_state_from_bytes_with_fp(&bytes, &pool).unwrap();
        assert_eq!(restored.epoch, state.epoch);
        assert_eq!(restored.epoch_key, state.epoch_key);
        assert_eq!(restored.chain_key, state.chain_key);
        assert_eq!(restored.counter, state.counter);
        assert_eq!(restored.my_eph_pub, state.my_eph_pub);
    }

    #[test]
    fn stale_cache_rejected() {
        let session_key = [0xDD; 32];
        let agent_id = b"stale-agent";
        let (_, prekey_pub) = gen_ephemeral();
        let state = bootstrap_epoch(&prekey_pub, &session_key, agent_id);
        let pool = vec![prekey_pub];

        let bytes = epoch_state_to_bytes_v2(&state, &pool);

        let (_, new_prekey_pub) = gen_ephemeral();
        let new_pool = vec![new_prekey_pub];
        assert!(epoch_state_from_bytes_with_fp(&bytes, &new_pool).is_none());
    }

    #[test]
    fn legacy_cache_rejected_when_pool_present() {
        let session_key = [0xDD; 32];
        let agent_id = b"legacy-agent";
        let (_, prekey_pub) = gen_ephemeral();
        let state = bootstrap_epoch(&prekey_pub, &session_key, agent_id);

        let bytes = epoch_state_to_bytes_v2(&state, &[]);
        let legacy_173 = bytes[..173].to_vec();

        let pool = vec![prekey_pub];
        assert!(epoch_state_from_bytes_with_fp(&legacy_173, &pool).is_none());
    }

    #[test]
    fn encrypt_v2_wire_format() {
        let session_key = [0xEE; 32];
        let agent_id = b"wire-agent";
        let (_, prekey_pub) = gen_ephemeral();
        let mut state = bootstrap_epoch(&prekey_pub, &session_key, agent_id);

        let msg = b"test message";
        let wire = encrypt_message_v2(&mut state, msg).unwrap();

        assert_eq!(wire[0], VERSION_BYTE);
        assert!(wire.len() > 1 + 4 + 32 + 8 + 32);
    }

    #[test]
    fn epoch_rotation() {
        let session_key = [0xFF; 32];
        let agent_id = b"rotate-agent";
        let (_, prekey_pub) = gen_ephemeral();
        let mut state = bootstrap_epoch(&prekey_pub, &session_key, agent_id);

        let old_epoch = state.epoch;
        let old_key = state.epoch_key;

        let (_, server_eph_pub) = gen_ephemeral();
        rotate_epoch(&mut state, &server_eph_pub, agent_id);

        assert_eq!(state.epoch, old_epoch + 1);
        assert_ne!(state.epoch_key, old_key);
        assert_eq!(state.counter, 0);
        assert_eq!(state.prev_epoch_key.unwrap(), old_key);
    }

    #[test]
    fn prekey_pool_decode() {
        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        let mut pool_raw = Vec::new();
        for i in 0..8u8 {
            pool_raw.extend_from_slice(&[i; 32]);
        }
        let b64 = B64.encode(&pool_raw);
        let keys = decode_prekey_pool(&b64);
        assert_eq!(keys.len(), 8);
        assert_eq!(keys[0], [0u8; 32]);
        assert_eq!(keys[7], [7u8; 32]);
    }

    #[test]
    fn v2_detection() {
        assert!(is_v2(&[0x02, 0x00, 0x01]));
        assert!(!is_v2(&[0x41, 0x42])); // 'A','B' — base64
        assert!(!is_v2(&[]));
    }
}
