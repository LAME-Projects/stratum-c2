use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, SocketAddr, Shutdown};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::P2PTransport;

const READ_TIMEOUT: Duration = Duration::from_secs(30);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024; // 16 MB

// ── TCP transport (wraps a connected TcpStream) ──────────────────────────────

pub struct TcpP2PTransport {
    stream: Mutex<TcpStream>,
    alive:  AtomicBool,
    peer:   String,
}

impl TcpP2PTransport {
    pub fn from_stream(stream: TcpStream) -> io::Result<Self> {
        let peer = stream.peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        stream.set_read_timeout(Some(READ_TIMEOUT))?;
        stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
        stream.set_nodelay(true)?;
        super::configure_keepalive(&stream);
        Ok(Self {
            stream: Mutex::new(stream),
            alive: AtomicBool::new(true),
            peer,
        })
    }
}

impl P2PTransport for TcpP2PTransport {
    fn send(&self, data: &[u8]) -> io::Result<()> {
        let mut stream = self.stream.lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "lock poisoned"))?;
        let len = (data.len() as u32).to_le_bytes();
        stream.write_all(&len)?;
        stream.write_all(data)?;
        stream.flush()
    }

    fn recv(&self) -> io::Result<Vec<u8>> {
        let mut stream = self.stream.lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "lock poisoned"))?;
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf)?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > MAX_FRAME_SIZE {
            self.alive.store(false, Ordering::SeqCst);
            return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
        }
        if len == 0 {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn close(&self) {
        self.alive.store(false, Ordering::SeqCst);
        if let Ok(stream) = self.stream.lock() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }

    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }

    fn peer_addr(&self) -> String {
        self.peer.clone()
    }
}

// ── TCP Listener (child binds, parent connects) ─────────────────────────────

pub struct TcpP2PListener {
    listener: TcpListener,
    alive:    AtomicBool,
}

impl TcpP2PListener {
    pub fn bind(addr: &str) -> io::Result<Self> {
        let socket_addr: SocketAddr = addr.parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        #[cfg(unix)]
        let listener = {
            use std::os::unix::io::FromRawFd;
            let domain = if socket_addr.is_ipv4() {
                libc::AF_INET
            } else {
                libc::AF_INET6
            };
            let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM, 0) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let optval: libc::c_int = 1;
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_REUSEADDR,
                    &optval as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
            let bind_ret = unsafe {
                match socket_addr {
                    SocketAddr::V4(ref v4) => {
                        let sa = libc::sockaddr_in {
                            sin_family: libc::AF_INET as libc::sa_family_t,
                            sin_port: v4.port().to_be(),
                            sin_addr: libc::in_addr {
                                s_addr: u32::from_ne_bytes(v4.ip().octets()),
                            },
                            sin_zero: [0; 8],
                        };
                        libc::bind(fd, &sa as *const _ as *const libc::sockaddr,
                                   std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t)
                    }
                    SocketAddr::V6(ref v6) => {
                        let sa = libc::sockaddr_in6 {
                            sin6_family: libc::AF_INET6 as libc::sa_family_t,
                            sin6_port: v6.port().to_be(),
                            sin6_flowinfo: v6.flowinfo(),
                            sin6_addr: libc::in6_addr {
                                s6_addr: v6.ip().octets(),
                            },
                            sin6_scope_id: v6.scope_id(),
                        };
                        libc::bind(fd, &sa as *const _ as *const libc::sockaddr,
                                   std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t)
                    }
                }
            };
            if bind_ret < 0 {
                unsafe { libc::close(fd); }
                return Err(io::Error::last_os_error());
            }
            if unsafe { libc::listen(fd, 4) } < 0 {
                unsafe { libc::close(fd); }
                return Err(io::Error::last_os_error());
            }
            unsafe { TcpListener::from_raw_fd(fd) }
        };

        #[cfg(not(unix))]
        let listener = TcpListener::bind(socket_addr)?;

        listener.set_nonblocking(false)?;
        Ok(Self {
            listener,
            alive: AtomicBool::new(true),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn accept(&self) -> io::Result<TcpP2PTransport> {
        let (stream, _addr) = self.listener.accept()?;
        TcpP2PTransport::from_stream(stream)
    }

    pub fn stop(&self) {
        self.alive.store(false, Ordering::SeqCst);
    }

    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }
}

// ── TCP Client (parent connects to child) ────────────────────────────────────

pub fn tcp_connect(addr: &str, timeout: Duration) -> io::Result<TcpP2PTransport> {
    let socket_addr: SocketAddr = addr.parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let stream = TcpStream::connect_timeout(&socket_addr, timeout)?;
    TcpP2PTransport::from_stream(stream)
}

// ── Listener manager (tracks active P2P listeners) ───────────────────────────

pub struct ListenerHandle {
    pub addr:     String,
    pub listener: Arc<TcpP2PListener>,
}

pub struct TcpListenerManager {
    listeners: Mutex<Vec<ListenerHandle>>,
}

impl TcpListenerManager {
    pub fn new() -> Self {
        Self { listeners: Mutex::new(Vec::new()) }
    }

    pub fn start(&self, addr: &str) -> io::Result<Arc<TcpP2PListener>> {
        let listener = Arc::new(TcpP2PListener::bind(addr)?);
        let actual_addr = listener.local_addr()?.to_string();
        self.listeners.lock().unwrap().push(ListenerHandle {
            addr: actual_addr,
            listener: listener.clone(),
        });
        Ok(listener)
    }

    pub fn stop(&self, addr: &str) -> bool {
        let mut listeners = self.listeners.lock().unwrap();
        if let Some(pos) = listeners.iter().position(|h| h.addr == addr) {
            listeners[pos].listener.stop();
            listeners.remove(pos);
            true
        } else {
            false
        }
    }

    pub fn stop_all(&self) {
        let mut listeners = self.listeners.lock().unwrap();
        for h in listeners.iter() {
            h.listener.stop();
        }
        listeners.clear();
    }

    pub fn list(&self) -> Vec<String> {
        self.listeners.lock().unwrap()
            .iter()
            .map(|h| h.addr.clone())
            .collect()
    }
}
