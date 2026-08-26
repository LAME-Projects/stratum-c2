use std::io;
use std::sync::Arc;

use x25519_dalek::{PublicKey, StaticSecret};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use super::{P2PTransport, PeerLink, LinkType, CtrlType};
use crate::crypto::{gcm_seal, gcm_open};

// ── Link handshake wire format ───────────────────────────────────────────────
//
// LINK_HELLO (child → parent):
//   [1: ctrl_type=0x10] [16: child_guid] [32: child_x25519_pub]
//
// LINK_ACK (parent → child):
//   [1: ctrl_type=0x11] [16: parent_guid] [32: parent_x25519_pub]
//   [N: gcm_seal(shared_key, confirmation_nonce)]
//
// LINK_READY (child → parent):
//   [1: ctrl_type=0x12] [1: status=0x01]

const HELLO_SIZE: usize = 1 + 16 + 32; // 49
const ACK_MIN_SIZE: usize = 1 + 16 + 32; // 49 + GCM confirmation blob

fn gen_ephemeral() -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::random_from_rng(rand::thread_rng());
    let public = PublicKey::from(&secret);
    let mut priv_bytes = [0u8; 32];
    priv_bytes.copy_from_slice(&secret.to_bytes());
    (priv_bytes, *public.as_bytes())
}

fn x25519_dh(my_priv: &[u8; 32], their_pub: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*my_priv);
    let public = PublicKey::from(*their_pub);
    *secret.diffie_hellman(&public).as_bytes()
}

fn derive_link_key(shared: &[u8; 32], child_guid: &[u8; 16], parent_guid: &[u8; 16]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(child_guid), shared);
    let mut info = Vec::with_capacity(20 + 16);
    info.extend_from_slice(b"stratum-p2p-link");
    info.extend_from_slice(parent_guid);
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key).expect("HKDF expand");
    key
}

// ── Parent-side: initiate link to a child ────────────────────────────────────

pub fn link_as_parent(
    transport: Arc<dyn P2PTransport>,
    my_guid: [u8; 16],
    link_type: LinkType,
) -> io::Result<PeerLink> {
    // 1. Receive LINK_HELLO from child
    let hello_data = transport.recv()?;
    if hello_data.len() < HELLO_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "short LINK_HELLO"));
    }
    if hello_data[0] != CtrlType::LinkHello as u8 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "expected LINK_HELLO"));
    }
    let mut child_guid = [0u8; 16];
    child_guid.copy_from_slice(&hello_data[1..17]);
    let mut child_pub = [0u8; 32];
    child_pub.copy_from_slice(&hello_data[17..49]);

    // 2. Generate ephemeral keypair, compute shared secret, derive link key
    let (my_priv, my_pub) = gen_ephemeral();
    let mut shared = x25519_dh(&my_priv, &child_pub);
    let link_key = derive_link_key(&shared, &child_guid, &my_guid);
    shared.zeroize();

    // 3. Send LINK_ACK with confirmation
    let confirmation = b"LINK_OK";
    let encrypted_conf = gcm_seal(&link_key, confirmation)
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "gcm_seal failed"))?;

    let mut ack = Vec::with_capacity(1 + 16 + 32 + encrypted_conf.len());
    ack.push(CtrlType::LinkAck as u8);
    ack.extend_from_slice(&my_guid);
    ack.extend_from_slice(&my_pub);
    ack.extend_from_slice(&encrypted_conf);
    transport.send(&ack)?;

    // 4. Receive LINK_READY
    let ready_data = transport.recv()?;
    if ready_data.len() < 2 || ready_data[0] != CtrlType::LinkReady as u8 || ready_data[1] != 0x01 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad LINK_READY"));
    }

    let addr = transport.peer_addr();
    Ok(PeerLink::new(child_guid, link_type, addr, link_key, transport))
}

// ── Child-side: accept link from a parent ────────────────────────────────────

pub fn link_as_child(
    transport: Arc<dyn P2PTransport>,
    my_guid: [u8; 16],
    link_type: LinkType,
) -> io::Result<PeerLink> {
    // 1. Generate ephemeral keypair
    let (my_priv, my_pub) = gen_ephemeral();

    // 2. Send LINK_HELLO
    let mut hello = Vec::with_capacity(HELLO_SIZE);
    hello.push(CtrlType::LinkHello as u8);
    hello.extend_from_slice(&my_guid);
    hello.extend_from_slice(&my_pub);
    transport.send(&hello)?;

    // 3. Receive LINK_ACK
    let ack_data = transport.recv()?;
    if ack_data.len() < ACK_MIN_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "short LINK_ACK"));
    }
    if ack_data[0] != CtrlType::LinkAck as u8 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "expected LINK_ACK"));
    }
    let mut parent_guid = [0u8; 16];
    parent_guid.copy_from_slice(&ack_data[1..17]);
    let mut parent_pub = [0u8; 32];
    parent_pub.copy_from_slice(&ack_data[17..49]);
    let encrypted_conf = &ack_data[49..];

    // 4. Compute shared secret, derive link key, verify confirmation
    let mut shared = x25519_dh(&my_priv, &parent_pub);
    let link_key = derive_link_key(&shared, &my_guid, &parent_guid);
    shared.zeroize();

    let conf_plain = gcm_open(&link_key, encrypted_conf)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "confirmation decrypt failed"))?;
    if conf_plain != b"LINK_OK" {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad confirmation"));
    }

    // 5. Send LINK_READY
    transport.send(&[CtrlType::LinkReady as u8, 0x01])?;

    let addr = transport.peer_addr();
    Ok(PeerLink::new(parent_guid, link_type, addr, link_key, transport))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::collections::VecDeque;

    struct MockTransport {
        inbox:  Mutex<VecDeque<Vec<u8>>>,
        outbox: Arc<Mutex<VecDeque<Vec<u8>>>>,
        addr:   String,
    }

    impl MockTransport {
        fn pair() -> (Arc<MockTransport>, Arc<MockTransport>) {
            let a_to_b = Arc::new(Mutex::new(VecDeque::new()));
            let b_to_a = Arc::new(Mutex::new(VecDeque::new()));
            let a = Arc::new(MockTransport {
                inbox: Mutex::new(VecDeque::new()),
                outbox: a_to_b.clone(),
                addr: "parent".to_string(),
            });
            let b = Arc::new(MockTransport {
                inbox: Mutex::new(VecDeque::new()),
                outbox: b_to_a.clone(),
                addr: "child".to_string(),
            });
            // Wire: a.outbox = b.inbox, b.outbox = a.inbox
            // We'll manually shuttle messages in the test
            (a, b)
        }
    }

    impl P2PTransport for MockTransport {
        fn send(&self, data: &[u8]) -> io::Result<()> {
            self.outbox.lock().unwrap().push_back(data.to_vec());
            Ok(())
        }
        fn recv(&self) -> io::Result<Vec<u8>> {
            self.inbox.lock().unwrap().pop_front()
                .ok_or_else(|| io::Error::new(io::ErrorKind::WouldBlock, "empty"))
        }
        fn close(&self) {}
        fn is_alive(&self) -> bool { true }
        fn peer_addr(&self) -> String { self.addr.clone() }
    }

    #[test]
    fn derive_link_key_deterministic() {
        let shared = [0xAA; 32];
        let child = [1u8; 16];
        let parent = [2u8; 16];
        let k1 = derive_link_key(&shared, &child, &parent);
        let k2 = derive_link_key(&shared, &child, &parent);
        assert_eq!(k1, k2);
        let k3 = derive_link_key(&shared, &parent, &child);
        assert_ne!(k1, k3);
    }
}
