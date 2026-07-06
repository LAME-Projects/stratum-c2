//! EXE entry point — thin shim; all logic lives in the library crate (lib.rs).

// Production: no console window (silent, no visible process).
// Debug builds (STRATUM_DEBUG=true): console subsystem so eprintln! is visible.
#![cfg_attr(all(windows, not(stratum_debug)), windows_subsystem = "windows")]

fn main() {
    if cfg!(stratum_debug) { eprintln!("[main] starting"); }
    agent::agent_loop();
    // agent_loop() returns only on KILL or kill-date expiry — exit cleanly.
    std::process::exit(0);
}
