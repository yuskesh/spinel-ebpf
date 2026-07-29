// Host-AOT driver: sixty lines that turn verified bytecode into a Thumb blob.
//
// The compilation itself is not ours. It is the JIT from the micro-bpf fork of
// rbpf, called here **on the build host** rather than on the device -- a JIT is a
// pure function from bytes to bytes, so running it early makes it an ahead-of-time
// compiler and leaves the real-time core carrying no VM and no JIT at all.
//
// The dependency is `../rbpf-for-microcontrollers`, fetched by scripts/setup.sh
// with SPNL_WITH_AMP=1. It has to be that fork: upstream rbpf ships an x86-64 JIT
// and a Cranelift backend and no ARM or Thumb backend, so upstream cannot emit a
// single byte for these targets. The fork keeps upstream's package metadata, so
// the Cargo dependency alone will not tell you which one you have. The tell is a
// Thumb emitter source file in the checkout's src directory; setup.sh checks for it.
//
//  - interp oracle uses REAL host helpers (id 1 = amp_emit +100, id 2 = amp_ktime).
//  - AOT bakes M7 helper addresses from env AMP_HELPER_1..8 = 0x... (transmuted;
//    the JIT only reads each as an address, never calls it at compile time).
//    The CLI passes AMP_HELPER_1 = AMP_HELPER_SLOT(1) and AMP_HELPER_2 =
//    AMP_HELPER_SLOT(2) so ktime-using probes (call 2) resolve too.
use std::collections::BTreeMap;
use std::fs;

#[repr(C, align(4))]
struct Aligned([u8; 65536]);

// Host helpers for the interpreter oracle. Match rbpf::ebpf::Helper.
fn host_amp_emit(a: u64, _b: u64, _c: u64, _d: u64, _e: u64) -> u64 {
    a + 100
}
fn host_amp_ktime(_a: u64, _b: u64, _c: u64, _d: u64, _e: u64) -> u64 {
    1_000_000 // fixed ns so a ktime-using program's oracle is deterministic
}

fn main() {
    env_logger::init();
    let path = std::env::args().nth(1).expect("usage: aot-driver <bpf.o> [out.bin]");
    let out = std::env::args().nth(2).unwrap_or_else(|| "blob.bin".into());
    let prog = fs::read(&path).unwrap();

    // --- interpreter reference (oracle) with real host helper ---
    let mut interp_helpers: BTreeMap<u32, rbpf::ebpf::Helper> = BTreeMap::new();
    interp_helpers.insert(1, host_amp_emit);
    interp_helpers.insert(2, host_amp_ktime);
    let mut vm = rbpf::EbpfVmMbuff::new(Some(&prog), rbpf::InterpreterVariant::RawObjectFile).unwrap();
    for (k, v) in &interp_helpers { vm.register_helper(*k, *v).unwrap(); }
    match vm.execute_program(&[], &[], vec![]) {
        Ok(interp) => println!("interp result = {interp} (0x{interp:x})"),
        Err(e) => println!("interp skipped ({:?}) — M7-address program, QEMU is the check", e),
    }

    // --- host AOT: bake the M7 helper address (from env) ---
    let mut aot_helpers: BTreeMap<u32, rbpf::ebpf::Helper> = BTreeMap::new();
    for n in 1u32..=8 {
        if let Ok(s) = std::env::var(format!("AMP_HELPER_{n}")) {
            let addr = u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap();
            let f: rbpf::ebpf::Helper = unsafe { std::mem::transmute(addr as usize) };
            aot_helpers.insert(n, f);
            println!("AOT: helper id {n} -> {s} (baked)");
        }
    }
    let mut prog_mut = prog.clone();
    let mut buf = Box::new(Aligned([0u8; 65536]));
    let (text_offset, end) = {
        let mem = rbpf::JitMemory::new(
            &mut prog_mut, &mut buf.0, &aot_helpers, false, false,
            rbpf::InterpreterVariant::RawObjectFile,
        ).unwrap();
        (mem.text_offset, mem.offset)
    };
    println!("AOT ok: total={} bytes (text={})", end, end - text_offset);
    fs::write(&out, &buf.0[..end]).unwrap();
    println!("wrote {out} (text starts at {text_offset})");
}
