pub mod tcp;
#[cfg(windows)]
pub mod smb;
#[cfg(not(windows))]
pub mod smb_client;
pub mod link;
pub mod router;
pub mod jump;

use std::io;
use std::sync::{Arc, Mutex, mpsc};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::collections::HashMap;
use std::time::{Duration, Instant};

// ── P2P transport trait ──────────────────────────────────────────────────────

pub trait P2PTransport: Send + Sync {
    fn send(&self, data: &[u8]) -> io::Result<()>;
    fn recv(&self) -> io::Result<Vec<u8>>;
    fn close(&self);
    fn is_alive(&self) -> bool;
    fn peer_addr(&self) -> String;
}

// ── Wire types ───────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum MsgType {
    Routing  = 0,
    Delivery = 1,
    Control  = 2,
}

impl MsgType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Routing),
            1 => Some(Self::Delivery),
            2 => Some(Self::Control),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RoutedMessage {
    pub msg_type:  MsgType,
    pub next_guid: [u8; 16],
    pub payload:   Vec<u8>,
}

impl RoutedMessage {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 16 + 4 + self.payload.len());
        buf.push(self.msg_type as u8);
        buf.extend_from_slice(&self.next_guid);
        buf.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < 1 + 16 + 4 { return None; }
        let msg_type = MsgType::from_u8(data[0])?;
        let mut next_guid = [0u8; 16];
        next_guid.copy_from_slice(&data[1..17]);
        let payload_len = u32::from_le_bytes([data[17], data[18], data[19], data[20]]) as usize;
        if data.len() < 21 + payload_len { return None; }
        let payload = data[21..21 + payload_len].to_vec();
        Some(Self { msg_type, next_guid, payload })
    }
}

// ── Control message types (type=2) ───────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum CtrlType {
    LinkHello  = 0x10,
    LinkAck    = 0x11,
    LinkReady  = 0x12,
    Heartbeat  = 0x20,
    Unlink     = 0x30,
}

impl CtrlType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x10 => Some(Self::LinkHello),
            0x11 => Some(Self::LinkAck),
            0x12 => Some(Self::LinkReady),
            0x20 => Some(Self::Heartbeat),
            0x30 => Some(Self::Unlink),
            _ => None,
        }
    }
}

// ── Link state ───────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LinkType {
    Tcp,
    Smb,
}

impl LinkType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Smb => "smb",
        }
    }
}

impl std::fmt::Display for LinkType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

pub struct PeerLink {
    pub guid:       [u8; 16],
    pub link_type:  LinkType,
    pub address:    String,
    pub link_key:   [u8; 32],
    pub transport:  Arc<dyn P2PTransport>,
    pub routing_active: Arc<AtomicBool>,
    pub route_tx: Mutex<mpsc::Sender<Vec<u8>>>,
    pub route_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
}

impl PeerLink {
    pub fn new(
        guid: [u8; 16], link_type: LinkType, address: String,
        link_key: [u8; 32], transport: Arc<dyn P2PTransport>,
    ) -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            guid, link_type, address, link_key, transport,
            routing_active: Arc::new(AtomicBool::new(false)),
            route_tx: Mutex::new(tx),
            route_rx: Mutex::new(rx),
        }
    }

    pub fn is_alive(&self) -> bool {
        self.transport.is_alive()
    }
}

// ── Reconnect configuration ────────────────────────────────────────────────

pub struct ReconnectConfig {
    pub initial_delay: Duration,
    pub max_delay:     Duration,
    pub max_retries:   u32,       // 0 = infinite
    pub jitter_pct:    u8,        // 0-100, randomized ± jitter around delay
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_secs(2),
            max_delay:     Duration::from_secs(300),
            max_retries:   0,
            jitter_pct:    25,
        }
    }
}

impl ReconnectConfig {
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let base = self.initial_delay.as_millis() as u64
            * 2u64.saturating_pow(attempt.min(20));
        let capped = base.min(self.max_delay.as_millis() as u64);
        if self.jitter_pct == 0 {
            return Duration::from_millis(capped);
        }
        let jitter_range = capped * self.jitter_pct as u64 / 100;
        let jitter = if jitter_range > 0 {
            (rand::random::<u64>() % (jitter_range * 2)).wrapping_sub(jitter_range)
        } else { 0 };
        Duration::from_millis((capped as i64 + jitter as i64).max(100) as u64)
    }

    pub fn should_retry(&self, attempt: u32) -> bool {
        self.max_retries == 0 || attempt < self.max_retries
    }
}

// ── Link registry ────────────────────────────────────────────────────────────

pub struct LinkRegistry {
    pub parent:   Mutex<Option<PeerLink>>,
    pub children: Mutex<HashMap<[u8; 16], PeerLink>>,
    pub my_guid:  [u8; 16],
    pub reconnect_cfg: ReconnectConfig,
    pub last_parent_seen: AtomicU64,   // epoch millis of last data from parent
    pub parent_lost: AtomicBool,
}

impl LinkRegistry {
    pub fn new(guid: [u8; 16]) -> Self {
        Self {
            parent:   Mutex::new(None),
            children: Mutex::new(HashMap::new()),
            my_guid:  guid,
            reconnect_cfg: ReconnectConfig::default(),
            last_parent_seen: AtomicU64::new(0),
            parent_lost: AtomicBool::new(false),
        }
    }

    pub fn touch_parent(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.last_parent_seen.store(now, Ordering::Relaxed);
    }

    pub fn parent_idle_ms(&self) -> u64 {
        let last = self.last_parent_seen.load(Ordering::Relaxed);
        if last == 0 { return 0; }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        now.saturating_sub(last)
    }

    pub fn add_child(&self, link: PeerLink) {
        self.children.lock().unwrap().insert(link.guid, link);
    }

    pub fn remove_child(&self, guid: &[u8; 16]) -> Option<PeerLink> {
        self.children.lock().unwrap().remove(guid)
    }

    pub fn set_parent(&self, link: PeerLink) {
        *self.parent.lock().unwrap() = Some(link);
    }

    pub fn clear_parent(&self) {
        *self.parent.lock().unwrap() = None;
    }

    pub fn child_count(&self) -> usize {
        self.children.lock().unwrap().len()
    }

    pub fn child_guids(&self) -> Vec<[u8; 16]> {
        self.children.lock().unwrap().keys().copied().collect()
    }

    pub fn has_parent(&self) -> bool {
        self.parent.lock().unwrap().is_some()
    }
}

// ── Framing: length-prefix I/O ───────────────────────────────────────────────

pub fn frame_send(transport: &dyn P2PTransport, data: &[u8]) -> io::Result<()> {
    let len = (data.len() as u32).to_le_bytes();
    let mut frame = Vec::with_capacity(4 + data.len());
    frame.extend_from_slice(&len);
    frame.extend_from_slice(data);
    transport.send(&frame)
}

pub fn frame_recv(transport: &dyn P2PTransport) -> io::Result<Vec<u8>> {
    let header = transport.recv()?;
    if header.len() < 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "short frame header"));
    }
    let payload_len = u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
    if payload_len == 0 {
        return Ok(Vec::new());
    }
    if header.len() >= 4 + payload_len {
        return Ok(header[4..4 + payload_len].to_vec());
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "incomplete frame"))
}
