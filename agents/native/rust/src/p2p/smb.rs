use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use super::P2PTransport;

const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;
const PIPE_BUFFER_SIZE: u32 = 65536;

// ── Win32 pipe constants ─────────────────────────────────────────────────────

const PIPE_ACCESS_DUPLEX: u32 = 0x00000003;
const PIPE_TYPE_BYTE: u32 = 0x00000000;
const PIPE_READMODE_BYTE: u32 = 0x00000000;
const PIPE_WAIT: u32 = 0x00000000;
const PIPE_UNLIMITED_INSTANCES: u32 = 255;
const GENERIC_READ: u32 = 0x80000000;
const GENERIC_WRITE: u32 = 0x40000000;
const OPEN_EXISTING: u32 = 3;
const INVALID_HANDLE: isize = -1;

extern "system" {
    fn CreateNamedPipeA(
        name: *const u8, open_mode: u32, pipe_mode: u32,
        max_instances: u32, out_buf: u32, in_buf: u32,
        default_timeout: u32, security: *mut u8,
    ) -> isize;
    fn ConnectNamedPipe(pipe: isize, overlapped: *mut u8) -> i32;
    fn CreateFileA(
        name: *const u8, access: u32, share: u32, security: *mut u8,
        disposition: u32, flags: u32, template: isize,
    ) -> isize;
    fn ReadFile(
        handle: isize, buffer: *mut u8, to_read: u32,
        bytes_read: *mut u32, overlapped: *mut u8,
    ) -> i32;
    fn WriteFile(
        handle: isize, buffer: *const u8, to_write: u32,
        bytes_written: *mut u32, overlapped: *mut u8,
    ) -> i32;
    fn CloseHandle(handle: isize) -> i32;
    fn FlushFileBuffers(handle: isize) -> i32;
    fn DisconnectNamedPipe(handle: isize) -> i32;
}

// ── Pipe handle wrapper ──────────────────────────────────────────────────────

struct PipeHandle(isize);

unsafe impl Send for PipeHandle {}
unsafe impl Sync for PipeHandle {}

impl PipeHandle {
    fn read_exact(&self, buf: &mut [u8]) -> io::Result<()> {
        let mut offset = 0;
        while offset < buf.len() {
            let mut bytes_read: u32 = 0;
            let to_read = (buf.len() - offset).min(u32::MAX as usize) as u32;
            let ok = unsafe {
                ReadFile(self.0, buf[offset..].as_mut_ptr(), to_read, &mut bytes_read, std::ptr::null_mut())
            };
            if ok == 0 || bytes_read == 0 {
                return Err(io::Error::last_os_error());
            }
            offset += bytes_read as usize;
        }
        Ok(())
    }

    fn write_all(&self, data: &[u8]) -> io::Result<()> {
        let mut offset = 0;
        while offset < data.len() {
            let mut bytes_written: u32 = 0;
            let to_write = (data.len() - offset).min(u32::MAX as usize) as u32;
            let ok = unsafe {
                WriteFile(self.0, data[offset..].as_ptr(), to_write, &mut bytes_written, std::ptr::null_mut())
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            offset += bytes_written as usize;
        }
        Ok(())
    }

    fn flush(&self) -> io::Result<()> {
        let ok = unsafe { FlushFileBuffers(self.0) };
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }

    fn close(&self) {
        unsafe { CloseHandle(self.0); }
    }
}

// ── SMB Named Pipe Transport ─────────────────────────────────────────────────

pub struct SmbP2PTransport {
    handle: Mutex<PipeHandle>,
    alive:  AtomicBool,
    peer:   String,
}

impl SmbP2PTransport {
    fn from_handle(handle: isize, peer: String) -> Self {
        Self {
            handle: Mutex::new(PipeHandle(handle)),
            alive: AtomicBool::new(true),
            peer,
        }
    }
}

impl P2PTransport for SmbP2PTransport {
    fn send(&self, data: &[u8]) -> io::Result<()> {
        let handle = self.handle.lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "lock poisoned"))?;
        let len = (data.len() as u32).to_le_bytes();
        handle.write_all(&len)?;
        handle.write_all(data)?;
        handle.flush()
    }

    fn recv(&self) -> io::Result<Vec<u8>> {
        let handle = self.handle.lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "lock poisoned"))?;
        let mut len_buf = [0u8; 4];
        handle.read_exact(&mut len_buf)?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > MAX_FRAME_SIZE {
            self.alive.store(false, Ordering::SeqCst);
            return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
        }
        if len == 0 {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; len];
        handle.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn close(&self) {
        self.alive.store(false, Ordering::SeqCst);
        if let Ok(handle) = self.handle.lock() {
            unsafe { DisconnectNamedPipe(handle.0); }
            handle.close();
        }
    }

    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }

    fn peer_addr(&self) -> String {
        self.peer.clone()
    }
}

// ── Named Pipe Server (child creates pipe, waits for parent) ─────────────────

pub struct SmbP2PListener {
    pipe_name: String,
    alive:     AtomicBool,
}

impl SmbP2PListener {
    pub fn new(pipe_name: &str) -> Self {
        let full_name = if pipe_name.starts_with(r"\\.\pipe\") {
            pipe_name.to_string()
        } else {
            format!(r"\\.\pipe\{}", pipe_name)
        };
        Self {
            pipe_name: full_name,
            alive: AtomicBool::new(true),
        }
    }

    pub fn pipe_name(&self) -> &str {
        &self.pipe_name
    }

    pub fn accept(&self) -> io::Result<SmbP2PTransport> {
        let mut name_bytes = self.pipe_name.as_bytes().to_vec();
        name_bytes.push(0);

        let handle = unsafe {
            CreateNamedPipeA(
                name_bytes.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                PIPE_BUFFER_SIZE,
                PIPE_BUFFER_SIZE,
                0,
                std::ptr::null_mut(),
            )
        };

        if handle == INVALID_HANDLE {
            return Err(io::Error::last_os_error());
        }

        let connected = unsafe { ConnectNamedPipe(handle, std::ptr::null_mut()) };
        if connected == 0 {
            let err = io::Error::last_os_error();
            // ERROR_PIPE_CONNECTED (535) is ok — client connected between Create and Connect
            if err.raw_os_error() != Some(535) {
                unsafe { CloseHandle(handle); }
                return Err(err);
            }
        }

        Ok(SmbP2PTransport::from_handle(handle, self.pipe_name.clone()))
    }

    pub fn stop(&self) {
        self.alive.store(false, Ordering::SeqCst);
    }

    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }
}

// ── Named Pipe Client (parent connects to child) ─────────────────────────────

pub fn smb_connect(target: &str, pipe_name: &str) -> io::Result<SmbP2PTransport> {
    let full_path = format!(r"\\{}\pipe\{}", target, pipe_name);
    let mut path_bytes = full_path.as_bytes().to_vec();
    path_bytes.push(0);

    let handle = unsafe {
        CreateFileA(
            path_bytes.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            0,
        )
    };

    if handle == INVALID_HANDLE {
        return Err(io::Error::last_os_error());
    }

    Ok(SmbP2PTransport::from_handle(handle, full_path))
}
