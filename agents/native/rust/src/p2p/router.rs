use std::sync::Arc;
use std::time::Duration;

use crate::crypto::{gcm_seal, gcm_open};
use super::{LinkRegistry, RoutedMessage, MsgType, CtrlType};

// ── Traffic padding ─────────────────────────────────────────────────────────
//
// Pad plaintext to the next power-of-2 boundary (min 64 bytes) to defeat
// traffic analysis on P2P links.  Format: [4: real_len LE] [real_data] [random padding]

const MIN_PAD_SIZE: usize = 64;

fn pad_message(data: &[u8]) -> Vec<u8> {
    let real_len = data.len();
    let content_len = 4 + real_len;
    let padded_len = content_len.max(MIN_PAD_SIZE).next_power_of_two();
    let mut buf = Vec::with_capacity(padded_len);
    buf.extend_from_slice(&(real_len as u32).to_le_bytes());
    buf.extend_from_slice(data);
    let pad_needed = padded_len - content_len;
    if pad_needed > 0 {
        let mut pad = vec![0u8; pad_needed];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut pad);
        buf.extend_from_slice(&pad);
    }
    buf
}

fn unpad_message(padded: &[u8]) -> Option<Vec<u8>> {
    if padded.len() < 4 { return None; }
    let real_len = u32::from_le_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
    if padded.len() < 4 + real_len { return None; }
    Some(padded[4..4 + real_len].to_vec())
}

// ── Encrypt a message for a specific link hop ────────────────────────────────

pub fn encrypt_for_link(link_key: &[u8; 32], data: &[u8]) -> Option<Vec<u8>> {
    let padded = pad_message(data);
    gcm_seal(link_key, &padded)
}

pub fn decrypt_from_link(link_key: &[u8; 32], data: &[u8]) -> Option<Vec<u8>> {
    let padded = gcm_open(link_key, data)?;
    unpad_message(&padded)
}

// ── Process an incoming message on this beacon ───────────────────────────────
//
// Returns:
//   ProcessResult::ForMe(payload)       — message is for this beacon, execute it
//   ProcessResult::Forward(guid, data)  — relay to child with this guid
//   ProcessResult::Error(msg)           — something went wrong

pub enum ProcessResult {
    ForMe(Vec<u8>),
    Forward([u8; 16], Vec<u8>),
    Error(String),
}

pub fn process_incoming(
    registry: &LinkRegistry,
    encrypted_data: &[u8],
    from_link_key: &[u8; 32],
) -> ProcessResult {
    // Decrypt our layer
    let plain = match decrypt_from_link(from_link_key, encrypted_data) {
        Some(p) => p,
        None => return ProcessResult::Error("link decrypt failed".to_string()),
    };

    // Parse the RoutedMessage
    let msg = match RoutedMessage::deserialize(&plain) {
        Some(m) => m,
        None => return ProcessResult::Error("invalid routed message".to_string()),
    };

    match msg.msg_type {
        MsgType::Delivery => {
            // Message is for this beacon
            ProcessResult::ForMe(msg.payload)
        }
        MsgType::Routing => {
            // Check if next_guid is one of our children
            let children = registry.children.lock().unwrap();
            if let Some(child) = children.get(&msg.next_guid) {
                // Re-encrypt payload for the child's link key and forward
                match encrypt_for_link(&child.link_key, &msg.payload) {
                    Some(enc) => ProcessResult::Forward(msg.next_guid, enc),
                    None => ProcessResult::Error("re-encrypt for child failed".to_string()),
                }
            } else {
                ProcessResult::Error(format!(
                    "no child with guid {:?}",
                    &msg.next_guid[..4]
                ))
            }
        }
        MsgType::Control => {
            // Control messages are handled inline by the caller
            ProcessResult::ForMe(plain)
        }
    }
}

// ── Wrap a response going upstream (child → parent direction) ────────────────
//
// Each hop wraps the payload with its own link key before forwarding to parent.

pub fn wrap_upstream(link_key: &[u8; 32], payload: &[u8]) -> Option<Vec<u8>> {
    encrypt_for_link(link_key, payload)
}

// ── Relay jitter ────────────────────────────────────────────────────────────
//
// Random delay before forwarding to break timing correlation between hops.

fn relay_jitter() {
    let jitter_ms = rand::random::<u64>() % 50 + 5; // 5–54ms
    std::thread::sleep(Duration::from_millis(jitter_ms));
}

// ── Forward a message to a specific child ────────────────────────────────────

pub fn forward_to_child(
    registry: &LinkRegistry,
    child_guid: &[u8; 16],
    data: &[u8],
) -> Result<(), String> {
    relay_jitter();
    let children = registry.children.lock().unwrap();
    if let Some(child) = children.get(child_guid) {
        child.transport.send(data)
            .map_err(|e| format!("send to child failed: {}", e))
    } else {
        Err("child not found".to_string())
    }
}

// ── Send a message upstream to parent ────────────────────────────────────────

pub fn send_to_parent(
    registry: &LinkRegistry,
    data: &[u8],
) -> Result<(), String> {
    let parent = registry.parent.lock().unwrap();
    if let Some(ref p) = *parent {
        let encrypted = encrypt_for_link(&p.link_key, data)
            .ok_or_else(|| "encrypt for parent failed".to_string())?;
        p.transport.send(&encrypted)
            .map_err(|e| format!("send to parent failed: {}", e))
    } else {
        Err("no parent link".to_string())
    }
}

// ── Relay loop: read from a child, process, forward or handle ────────────────
//
// This runs in a dedicated thread per child link. When data arrives from a
// child, it's either:
//   - A response traveling upstream → wrap and forward to parent
//   - A control message → handle locally

pub fn relay_child_upstream(
    registry: &Arc<LinkRegistry>,
    child_guid: [u8; 16],
) {
    loop {
        let (data, link_key, routing_active) = {
            let children = registry.children.lock().unwrap();
            let child = match children.get(&child_guid) {
                Some(c) => c,
                None => break,
            };
            if !child.transport.is_alive() { break; }
            let data = match child.transport.recv() {
                Ok(d) => d,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut {
                        continue;
                    }
                    break;
                }
            };
            (data, child.link_key, child.routing_active.load(std::sync::atomic::Ordering::SeqCst))
        };

        let plain = match decrypt_from_link(&link_key, &data) {
            Some(p) => p,
            None => continue,
        };

        if plain.len() >= 1 && plain[0] == CtrlType::Heartbeat as u8 {
            continue;
        }

        if routing_active {
            let children = registry.children.lock().unwrap();
            if let Some(child) = children.get(&child_guid) {
                let _ = child.route_tx.lock().unwrap().send(plain);
            }
            continue;
        }

        if let Err(_) = send_to_parent(registry, &plain) {
            break;
        }
    }

    let (child_addr, child_link_type) = {
        let children = registry.children.lock().unwrap();
        match children.get(&child_guid) {
            Some(c) => (c.address.clone(), c.link_type),
            None => return,
        }
    };

    registry.remove_child(&child_guid);

    if child_addr.is_empty() { return; }
    reconnect_to_child(registry, child_guid, &child_addr, child_link_type);
}

fn reconnect_to_child(
    registry: &Arc<LinkRegistry>,
    child_guid: [u8; 16],
    address: &str,
    link_type: super::LinkType,
) {
    let cfg = &registry.reconnect_cfg;
    let mut attempt = 0u32;

    loop {
        if !cfg.should_retry(attempt) { break; }
        let delay = cfg.delay_for_attempt(attempt);
        std::thread::sleep(delay);

        let result = match link_type {
            super::LinkType::Tcp => {
                use std::time::Duration;
                crate::p2p::tcp::tcp_connect(address, Duration::from_secs(10))
                    .and_then(|t| {
                        let arc_t: std::sync::Arc<dyn super::P2PTransport> = std::sync::Arc::new(t);
                        crate::p2p::link::link_as_parent(arc_t, registry.my_guid, link_type)
                    })
            }
            #[cfg(windows)]
            super::LinkType::Smb => {
                let parts: Vec<&str> = address.rsplitn(2, '\\').collect();
                let pipe = parts.first().unwrap_or(&"stratum");
                let target = parts.last().unwrap_or(&"");
                crate::p2p::smb::smb_connect(target, pipe)
                    .and_then(|t| {
                        let arc_t: std::sync::Arc<dyn super::P2PTransport> = std::sync::Arc::new(t);
                        crate::p2p::link::link_as_parent(arc_t, registry.my_guid, link_type)
                    })
            }
            #[cfg(not(windows))]
            super::LinkType::Smb => {
                let parts: Vec<&str> = address.rsplitn(2, '\\').collect();
                let pipe = parts.first().unwrap_or(&"stratum");
                let target = parts.last().unwrap_or(&"");
                crate::p2p::smb_client::smb_client_connect(target, pipe)
                    .and_then(|t| {
                        let arc_t: std::sync::Arc<dyn super::P2PTransport> = std::sync::Arc::new(t);
                        crate::p2p::link::link_as_parent(arc_t, registry.my_guid, link_type)
                    })
            }
        };

        match result {
            Ok(link) => {
                registry.add_child(link);
                let reg2 = registry.clone();
                std::thread::spawn(move || {
                    relay_child_upstream(&reg2, child_guid);
                });
                return;
            }
            Err(_) => { attempt += 1; }
        }
    }
}

// ── Relay loop: read from parent, process, deliver or forward ────────────────
//
// This runs for P2P child beacons. Incoming from parent could be:
//   - Delivery: command for this beacon
//   - Routing: forward to one of our children

pub fn relay_parent_downstream(
    registry: &Arc<LinkRegistry>,
) -> Option<Vec<u8>> {
    let (data, link_key) = {
        let parent = registry.parent.lock().unwrap();
        let p = parent.as_ref()?;
        if !p.transport.is_alive() {
            drop(parent);
            registry.clear_parent();
            return None;
        }
        let data = match p.transport.recv() {
            Ok(d) => d,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut {
                    return None;
                }
                drop(parent);
                registry.clear_parent();
                return None;
            }
        };
        (data, p.link_key)
    };

    match process_incoming(registry, &data, &link_key) {
        ProcessResult::ForMe(payload) => {
            if payload.len() >= 1 && payload[0] == CtrlType::Heartbeat as u8 {
                registry.touch_parent();
                let _ = send_heartbeat_to_parent(registry);
                return None;
            }
            Some(payload)
        }
        ProcessResult::Forward(child_guid, enc_data) => {
            let _ = forward_to_child(registry, &child_guid, &enc_data);
            None
        }
        ProcessResult::Error(_) => None,
    }
}

// ── Heartbeat ───────────────────────────────────────────────────────────────

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const HEARTBEAT_TIMEOUT:  Duration = Duration::from_secs(120);

fn heartbeat_frame() -> Vec<u8> {
    vec![CtrlType::Heartbeat as u8, 0x01]
}

pub fn send_heartbeat_to_parent(registry: &LinkRegistry) -> Result<(), String> {
    let parent = registry.parent.lock().unwrap();
    if let Some(ref p) = *parent {
        let data = heartbeat_frame();
        let encrypted = encrypt_for_link(&p.link_key, &data)
            .ok_or_else(|| "encrypt heartbeat failed".to_string())?;
        p.transport.send(&encrypted)
            .map_err(|e| format!("send heartbeat to parent: {}", e))
    } else {
        Err("no parent".to_string())
    }
}

pub fn send_heartbeat_to_children(registry: &Arc<LinkRegistry>) {
    let children = registry.children.lock().unwrap();
    for child in children.values() {
        let data = heartbeat_frame();
        if let Some(enc) = encrypt_for_link(&child.link_key, &data) {
            let _ = child.transport.send(&enc);
        }
    }
}

pub fn start_heartbeat_sender(registry: Arc<LinkRegistry>) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(HEARTBEAT_INTERVAL);
            if registry.child_count() == 0 && !registry.has_parent() {
                continue;
            }
            send_heartbeat_to_children(&registry);
            if registry.has_parent() {
                let _ = send_heartbeat_to_parent(&registry);
            }
        }
    });
}
