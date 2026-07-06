fn main() {
    let path = std::env::var("STRATUM_PE_PATH")
        .expect("STRATUM_PE_PATH must point to the compiled agent.exe (x86_64-pc-windows-msvc)");
    println!("cargo:rerun-if-changed={}", path);
    println!("cargo:rerun-if-env-changed=STRATUM_PE_PATH");
    // Propagate to rustc so that include_bytes!(env!("STRATUM_PE_PATH")) resolves correctly.
    println!("cargo:rustc-env=STRATUM_PE_PATH={}", path);

    // Flat binary output: custom linker script + no stdlib
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-arg=-T{}/link.ld", manifest);
    println!("cargo:rustc-link-arg=-nostdlib");
    println!("cargo:rustc-link-arg=-e_start");
}
