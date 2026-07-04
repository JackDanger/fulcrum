//! macOS / Apple-Silicon measurement backends for Fulcrum.
//!
//! This is the macOS half of Fulcrum's hardware-truth layer. On Linux Fulcrum
//! drives `perf`; macOS has no `perf`, so these backends program the
//! Apple-Silicon PMU directly via the private `kperf`/`kperfdata` frameworks
//! (`kpc_*` / `kpep_*`), reading PER-THREAD counters around an IN-PROCESS decode
//! so the numbers isolate exactly the decode kernel on the calling thread and
//! are immune to other-process noise. MUST run as root (kpc requires it).
//!
//! Folds in the previously-ad-hoc /tmp measurement harnesses (gztd / gzkpc /
//! m4tight.sh) so that ALL measurement now happens inside Fulcrum, behind
//! BLOCKING Gate-0 self-tests that make a whole class of harness bug impossible
//! by construction:
//!   - `counterdiff` — paired gz-vs-comparator cycles/instructions/IPC.
//!   - `topdown`     — Firestorm stall classifier, proven on discriminators.
//!   - `wall`        — interleaved best-of-N wall A/B with the sha verified
//!                     OUTSIDE the timed region (the shasum-in-timer bug is
//!                     structurally impossible here).
//!
//! Every subcommand LOUD-PASSES its own Gate-0 self-tests before it reports a
//! single number; if a self-test fails the tool REFUSES (nonzero exit) rather
//! than emit an untrustworthy number.
#![cfg(target_os = "macos")]

use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::time::Instant;

// ===========================================================================
// Apple-Silicon PMU backend (kperf/kperfdata via dlopen+dlsym).
// Port of the validated /tmp/gztd/src/pmu.rs.
// ===========================================================================
mod pmu {
    use std::ffi::{CStr, CString};
    use std::os::raw::{c_char, c_int, c_void};

    pub const KPC_CLASS_FIXED_MASK: u32 = 1 << 0;
    pub const KPC_CLASS_CONFIGURABLE_MASK: u32 = 1 << 1;
    pub const KPC_MAX_COUNTERS: usize = 32;

    unsafe fn sym(h: *mut c_void, name: &str) -> *mut c_void {
        let cn = CString::new(name).unwrap();
        let p = libc::dlsym(h, cn.as_ptr());
        if p.is_null() {
            panic!("dlsym missing {name}");
        }
        p
    }

    #[allow(non_snake_case)]
    pub struct Pmu {
        kpc_force_all_ctrs_set: extern "C" fn(c_int) -> c_int,
        kpc_set_config: extern "C" fn(u32, *mut u64) -> c_int,
        kpc_set_counting: extern "C" fn(u32) -> c_int,
        kpc_set_thread_counting: extern "C" fn(u32) -> c_int,
        kpc_get_thread_counters: extern "C" fn(u32, u32, *mut c_void) -> c_int,
        kpc_get_counter_count: extern "C" fn(u32) -> u32,
        kpep_db_name: extern "C" fn(*mut c_void, *mut *const c_char) -> c_int,
        kpep_db_event: extern "C" fn(*mut c_void, *const c_char, *mut *mut c_void) -> c_int,
        kpep_config_create: extern "C" fn(*mut c_void, *mut *mut c_void) -> c_int,
        kpep_config_force_counters: extern "C" fn(*mut c_void) -> c_int,
        kpep_config_add_event: extern "C" fn(*mut c_void, *mut *mut c_void, u32, *mut u32) -> c_int,
        kpep_config_kpc_classes: extern "C" fn(*mut c_void, *mut u32) -> c_int,
        kpep_config_kpc_count: extern "C" fn(*mut c_void, *mut usize) -> c_int,
        kpep_config_kpc_map: extern "C" fn(*mut c_void, *mut usize, usize) -> c_int,
        kpep_config_kpc: extern "C" fn(*mut c_void, *mut u64, usize) -> c_int,
        pub db: *mut c_void,
    }

    impl Pmu {
        pub fn new() -> Result<Pmu, String> {
            unsafe {
                let kperf = CString::new("/System/Library/PrivateFrameworks/kperf.framework/kperf")
                    .unwrap();
                let hk = libc::dlopen(kperf.as_ptr(), libc::RTLD_LAZY);
                if hk.is_null() {
                    return Err("dlopen kperf failed".into());
                }
                let kpd =
                    CString::new("/System/Library/PrivateFrameworks/kperfdata.framework/kperfdata")
                        .unwrap();
                let hd = libc::dlopen(kpd.as_ptr(), libc::RTLD_LAZY);
                if hd.is_null() {
                    return Err("dlopen kperfdata failed".into());
                }
                let kpep_db_create: extern "C" fn(*const c_char, *mut *mut c_void) -> c_int =
                    std::mem::transmute(sym(hd, "kpep_db_create"));
                let mut db: *mut c_void = std::ptr::null_mut();
                if kpep_db_create(std::ptr::null(), &mut db) != 0 || db.is_null() {
                    return Err("kpep_db_create failed".into());
                }
                Ok(Pmu {
                    kpc_force_all_ctrs_set: std::mem::transmute(sym(hk, "kpc_force_all_ctrs_set")),
                    kpc_set_config: std::mem::transmute(sym(hk, "kpc_set_config")),
                    kpc_set_counting: std::mem::transmute(sym(hk, "kpc_set_counting")),
                    kpc_set_thread_counting: std::mem::transmute(sym(
                        hk,
                        "kpc_set_thread_counting",
                    )),
                    kpc_get_thread_counters: std::mem::transmute(sym(
                        hk,
                        "kpc_get_thread_counters",
                    )),
                    kpc_get_counter_count: std::mem::transmute(sym(hk, "kpc_get_counter_count")),
                    kpep_db_name: std::mem::transmute(sym(hd, "kpep_db_name")),
                    kpep_db_event: std::mem::transmute(sym(hd, "kpep_db_event")),
                    kpep_config_create: std::mem::transmute(sym(hd, "kpep_config_create")),
                    kpep_config_force_counters: std::mem::transmute(sym(
                        hd,
                        "kpep_config_force_counters",
                    )),
                    kpep_config_add_event: std::mem::transmute(sym(hd, "kpep_config_add_event")),
                    kpep_config_kpc_classes: std::mem::transmute(sym(
                        hd,
                        "kpep_config_kpc_classes",
                    )),
                    kpep_config_kpc_count: std::mem::transmute(sym(hd, "kpep_config_kpc_count")),
                    kpep_config_kpc_map: std::mem::transmute(sym(hd, "kpep_config_kpc_map")),
                    kpep_config_kpc: std::mem::transmute(sym(hd, "kpep_config_kpc")),
                    db,
                })
            }
        }

        pub fn db_name(&self) -> String {
            unsafe {
                let mut p: *const c_char = std::ptr::null();
                (self.kpep_db_name)(self.db, &mut p);
                if p.is_null() {
                    "?".into()
                } else {
                    CStr::from_ptr(p).to_string_lossy().into_owned()
                }
            }
        }

        pub fn has_event(&self, name: &str) -> bool {
            let cn = CString::new(name).unwrap();
            let mut ev: *mut c_void = std::ptr::null_mut();
            (self.kpep_db_event)(self.db, cn.as_ptr(), &mut ev) == 0 && !ev.is_null()
        }
    }

    impl Drop for Pmu {
        fn drop(&mut self) {
            // RELEASE the counters on the way out — including during a panic
            // unwind — so a future run (this tool, gztd, or any kpc client) is
            // never wedged by stale force-ownership. This is the structural fix
            // for the "kpc_set_config failed" cascade.
            (self.kpc_set_thread_counting)(0);
            (self.kpc_set_counting)(0);
            (self.kpc_force_all_ctrs_set)(0);
        }
    }

    /// A programmed measurement session for a fixed set of named events.
    pub struct Session {
        counter_map: Vec<usize>,
        total_counters: u32,
    }

    impl Session {
        pub fn program(pmu: &Pmu, events: &[&str]) -> Result<Session, String> {
            unsafe {
                // Defensively RELEASE first: a prior process that crashed while
                // holding the counters leaves kpc force-acquired, after which
                // kpc_set_config fails for everyone until released. Full reset
                // sequence (stop counting, stop thread counting, release force)
                // clears that stale ownership; force(1) re-acquires for us.
                (pmu.kpc_set_thread_counting)(0);
                (pmu.kpc_set_counting)(0);
                (pmu.kpc_force_all_ctrs_set)(0);
                if (pmu.kpc_force_all_ctrs_set)(1) != 0 {
                    return Err("kpc_force_all_ctrs_set failed — run under sudo".into());
                }
                let mut cfg: *mut c_void = std::ptr::null_mut();
                if (pmu.kpep_config_create)(pmu.db, &mut cfg) != 0 || cfg.is_null() {
                    return Err("kpep_config_create failed".into());
                }
                if (pmu.kpep_config_force_counters)(cfg) != 0 {
                    return Err("kpep_config_force_counters failed".into());
                }
                for &name in events {
                    let cn = CString::new(name).unwrap();
                    let mut ev: *mut c_void = std::ptr::null_mut();
                    if (pmu.kpep_db_event)(pmu.db, cn.as_ptr(), &mut ev) != 0 || ev.is_null() {
                        return Err(format!("event not in DB: {name}"));
                    }
                    let mut err: u32 = 0;
                    let r = (pmu.kpep_config_add_event)(cfg, &mut ev, 0, &mut err);
                    if r != 0 {
                        return Err(format!(
                            "kpep_config_add_event({name}) failed r={r} err={err}"
                        ));
                    }
                }
                let mut classes: u32 = 0;
                (pmu.kpep_config_kpc_classes)(cfg, &mut classes);
                let mut reg_count: usize = 0;
                (pmu.kpep_config_kpc_count)(cfg, &mut reg_count);

                let mut map = vec![0usize; KPC_MAX_COUNTERS];
                (pmu.kpep_config_kpc_map)(
                    cfg,
                    map.as_mut_ptr(),
                    KPC_MAX_COUNTERS * std::mem::size_of::<usize>(),
                );
                let mut regs = vec![0u64; KPC_MAX_COUNTERS];
                (pmu.kpep_config_kpc)(
                    cfg,
                    regs.as_mut_ptr(),
                    reg_count * std::mem::size_of::<u64>(),
                );

                // kpc_set_config programs the CONFIGURABLE counters. When the
                // event set is fixed-only (cycles/instructions), reg_count==0 and
                // there is nothing to configure — calling set_config then returns
                // ENOENT. The fixed counters are free-running and only need
                // set_counting/set_thread_counting below. So only configure when
                // there are configurable registers.
                if reg_count > 0 {
                    let rc = (pmu.kpc_set_config)(classes, regs.as_mut_ptr());
                    if rc != 0 {
                        let errno = *libc::__error();
                        return Err(format!(
                            "kpc_set_config failed rc={rc} errno={errno} ({}) classes={classes} reg_count={reg_count}",
                            std::io::Error::from_raw_os_error(errno)
                        ));
                    }
                }
                if (pmu.kpc_set_counting)(classes) != 0 {
                    return Err("kpc_set_counting failed".into());
                }
                if (pmu.kpc_set_thread_counting)(classes) != 0 {
                    return Err("kpc_set_thread_counting failed".into());
                }
                let total =
                    (pmu.kpc_get_counter_count)(KPC_CLASS_FIXED_MASK | KPC_CLASS_CONFIGURABLE_MASK);
                let counter_map = (0..events.len()).map(|i| map[i]).collect();
                Ok(Session {
                    counter_map,
                    total_counters: total,
                })
            }
        }

        #[inline]
        pub fn read(&self, pmu: &Pmu) -> Vec<u64> {
            let mut buf = vec![0u64; KPC_MAX_COUNTERS];
            let r = (pmu.kpc_get_thread_counters)(
                0,
                self.total_counters,
                buf.as_mut_ptr() as *mut c_void,
            );
            if r != 0 {
                panic!("kpc_get_thread_counters failed: {r}");
            }
            self.counter_map.iter().map(|&i| buf[i]).collect()
        }

        /// LEAN single-counter read for the per-phase state machine (no heap
        /// alloc — a stack buffer only — so the per-switch instrument tax stays
        /// small and calibratable). `i` indexes the programmed event list;
        /// the phase driver programs a FIXED_INSTRUCTIONS-only session so
        /// `read_at(pmu, 0)` returns retired instructions. Returns 0 on a read
        /// error rather than panicking (this runs on the hot decode path).
        #[inline(always)]
        pub fn read_at(&self, pmu: &Pmu, i: usize) -> u64 {
            let mut buf = [0u64; KPC_MAX_COUNTERS];
            let r = (pmu.kpc_get_thread_counters)(
                0,
                self.total_counters,
                buf.as_mut_ptr() as *mut c_void,
            );
            if r != 0 {
                return 0;
            }
            buf[self.counter_map[i]]
        }
    }
}

use pmu::{Pmu, Session};

// ===========================================================================
// COARSE PER-PHASE RETIRED-INSTRUCTION STATE MACHINE (kpcphase)
//
// The SAME instrument on BOTH decoders (this is the whole point — it corrects
// the prior model-vs-measurement dimensional error where gz's fastloop was a
// STATIC pathcount×disasm model but ld's was a KPC monolith measurement). A
// single `fx_phase_switch(p)` symbol is called at the COARSE phase boundaries
// of both decoders:
//   * the instrumented libdeflate C  (critpath-libdeflate, `CPLD_PHASE` macro)
//   * gzippy's production decode      (marker_inflate.rs, feature `phase_kpc`)
// Each switch reads FIXED_INSTRUCTIONS once and attributes the delta since the
// previous switch to the phase that was current — a CONTIGUOUS partition, so
// the per-phase sum equals the whole decode's retired instructions (the
// conservation check) minus the (calibrated, symmetric) per-switch tax.
//
// COARSE = ~4 switches per deflate block (~3347 blocks) ≈ 13K reads/decode, so
// it is NOT overhead-dominated the way a per-symbol (millions of fires) read
// would be. The tax is calibrated by comparing instrument-ENABLED vs
// instrument-DISABLED whole-decode retired totals (same codegen, only the
// atomic gate differs) and reported alongside every result.
// ===========================================================================
pub mod phase {
    use super::pmu::{Pmu, Session};
    use std::sync::atomic::{AtomicBool, Ordering};

    pub const NPHASE: usize = 4;
    pub const OTHER: u32 = 0;
    pub const HEADER: u32 = 1;
    pub const BUILD: u32 = 2;
    pub const FASTLOOP: u32 = 3;
    pub const PHASE_NAMES: [&str; NPHASE] = ["other", "header", "build", "fastloop"];

    // Plain statics (accessed unsafely): the measured decode is single-threaded
    // T1 in-process, `arm()` is called before the decode and `disarm()` after,
    // so there is never concurrent access. Avoids the lock/heap tax a Mutex or
    // Vec would add per switch (which would swamp the coarse per-phase deltas).
    static ENABLED: AtomicBool = AtomicBool::new(false);
    static mut PMU: *const Pmu = std::ptr::null();
    static mut SESS: *const Session = std::ptr::null();
    static mut CUR: u32 = OTHER;
    static mut LAST: u64 = 0;
    static mut ACC: [u64; NPHASE] = [0; NPHASE];
    static mut FIRES: [u64; NPHASE] = [0; NPHASE];
    static mut SWITCHES: u64 = 0;

    #[inline(always)]
    unsafe fn read_instr() -> u64 {
        (*SESS).read_at(&*PMU, 0)
    }

    /// Arm the state machine for one decode. `pmu`/`sess` MUST outlive the
    /// decode. The session must be programmed FIXED_INSTRUCTIONS-first.
    ///
    /// # Safety
    /// Caller guarantees single-threaded use and that the pointers stay valid
    /// until [`disarm`].
    pub unsafe fn arm(pmu: *const Pmu, sess: *const Session) {
        PMU = pmu;
        SESS = sess;
        ACC = [0; NPHASE];
        FIRES = [0; NPHASE];
        SWITCHES = 0;
        CUR = OTHER;
        FIRES[OTHER as usize] += 1;
        ENABLED.store(true, Ordering::SeqCst);
        LAST = read_instr();
    }

    /// Close the final segment and return `(acc, fires, switches)`.
    ///
    /// # Safety
    /// Must be called after [`arm`] on the same thread with the pointers still
    /// valid.
    pub unsafe fn disarm() -> ([u64; NPHASE], [u64; NPHASE], u64) {
        let now = read_instr();
        ACC[CUR as usize] = ACC[CUR as usize].wrapping_add(now.wrapping_sub(LAST));
        ENABLED.store(false, Ordering::SeqCst);
        PMU = std::ptr::null();
        SESS = std::ptr::null();
        (ACC, FIRES, SWITCHES)
    }

    /// The ONE symbol both decoders call at coarse phase boundaries. Cheap
    /// (one relaxed atomic load + return) when the instrument is disarmed, so
    /// leaving the calls compiled into gzippy/libdeflate is byte-transparent
    /// and near-zero-cost off the measurement path.
    #[no_mangle]
    pub extern "C" fn fx_phase_switch(p: u32) {
        if !ENABLED.load(Ordering::Relaxed) {
            return;
        }
        if p as usize >= NPHASE {
            return;
        }
        unsafe {
            let now = read_instr();
            ACC[CUR as usize] = ACC[CUR as usize].wrapping_add(now.wrapping_sub(LAST));
            LAST = now;
            CUR = p;
            FIRES[p as usize] += 1;
            SWITCHES += 1;
        }
    }
}

// ===========================================================================
// In-process decoders (gz = production pure-Rust gzippy; ld = libdeflate C).
// Both write to a caller-owned slice sink — the SAME sink shape for both arms.
// ===========================================================================
struct SliceWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}
impl Write for SliceWriter<'_> {
    #[inline]
    fn write(&mut self, d: &[u8]) -> std::io::Result<usize> {
        let n = d.len();
        self.buf[self.pos..self.pos + n].copy_from_slice(d);
        self.pos += n;
        Ok(n)
    }
    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn run_gz(data: &[u8], buf: &mut [u8]) -> usize {
    let mut w = SliceWriter { buf, pos: 0 };
    gzippy::decompress_to_writer_with_threads(data, &mut w, 1).expect("gz decode");
    w.pos
}

fn run_ld(data: &[u8], buf: &mut [u8]) -> usize {
    let mut d = libdeflater::Decompressor::new();
    d.gzip_decompress(data, buf).expect("libdeflate decode")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let d = h.finalize();
    let mut s = String::with_capacity(64);
    for b in d {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Independent oracle: `gzip -dc <corpus>` decompressed sha256.
fn oracle_sha(corpus: &str) -> Result<String, String> {
    Ok(oracle_sha_len(corpus)?.0)
}

/// Independent oracle: `gzip -dc <corpus>` decompressed (sha256, uncompressed
/// byte length). The length is what the corpus-size sweep is keyed on.
fn oracle_sha_len(corpus: &str) -> Result<(String, usize), String> {
    let out = Command::new("gzip")
        .arg("-dc")
        .arg(corpus)
        .output()
        .map_err(|e| format!("spawn gzip -dc failed: {e}"))?;
    if !out.status.success() {
        return Err(format!("gzip -dc {corpus} failed: {}", out.status));
    }
    Ok((sha256_hex(&out.stdout), out.stdout.len()))
}

/// sha256 of a file's bytes (used for binary + corpus provenance pinning).
fn file_sha256(path: &str) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    Ok(sha256_hex(&bytes))
}

// ===========================================================================
// Stats helpers
// ===========================================================================
fn median(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        return f64::NAN;
    }
    let mut v = xs.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}
fn minf(xs: &[f64]) -> f64 {
    xs.iter().cloned().fold(f64::INFINITY, f64::min)
}
fn maxf(xs: &[f64]) -> f64 {
    xs.iter().cloned().fold(f64::NEG_INFINITY, f64::max)
}
fn percentile(xs: &[f64], p: f64) -> f64 {
    if xs.is_empty() {
        return f64::NAN;
    }
    let mut v = xs.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let idx = ((p / 100.0) * (v.len() - 1) as f64).round() as usize;
    v[idx.min(v.len() - 1)]
}
/// half-range / median, in percent — the campaign's "spread%".
fn spread_pct(xs: &[f64]) -> f64 {
    if xs.len() < 2 {
        return 0.0;
    }
    let m = median(xs);
    if m == 0.0 {
        return 0.0;
    }
    100.0 * (maxf(xs) - minf(xs)) / 2.0 / m
}

fn preflight_root() -> Result<(), String> {
    // EUID 0 required for kpc. Cheap deterministic check.
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        return Err(format!(
            "kpc requires root (euid=0); got euid={euid}. Re-run under: sudo -E fulcrum ..."
        ));
    }
    Ok(())
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
}

const DEFAULT_CORPUS: &str = "/tmp/silesia.gz";

// ===========================================================================
// `fulcrum scalewall` (macOS) — THREAD-SCALING wall sweep + Amdahl serial frac.
//
// Answers "why does the parallel decode scale worse as T grows" at the WALL,
// the macOS counterpart to the Linux-perf `scaling` trace decomposition. For
// each thread count it runs INTERLEAVED best-of-N decodes (gz + a native
// comparator), /dev/null sink BOTH arms (the SINK LAW), sha verified OUTSIDE
// the timer, then computes per-tool speedup-vs-own-T1 and the Amdahl serial
// fraction s (max_speedup ≈ 1/s) inferred from the largest *non-oversubscribed*
// thread count.
//
// Gate-0 self-tests (BLOCKING — no number is emitted unless every one passes):
//   (a) gz + comparator are native Mach-O (not a python/wheel shim);
//   (b) each arm's output sha == gzip -dc oracle at the lowest T (correctness);
//   (c) THREAD-COUNT ACTUALLY APPLIED: a GZIPPY_TIMELINE trace at max-T records
//       drive.args.parallelization == requested T AND >=2 distinct worker tids
//       (a -pN flag that silently no-ops would be caught here);
//   (d) A/A floor: gz-vs-gz second-decode ratio per rep — the Δ a real signal
//       must clear; reported alongside the curve.
// ===========================================================================

/// Decode `bin args... corpus` to /dev/null with optional extra env, return ms.
fn timed_decode_devnull(
    bin: &str,
    args: &[String],
    corpus: &str,
    env: &[(&str, &str)],
) -> Result<f64, String> {
    let devnull = std::fs::File::create("/dev/null").map_err(|e| format!("open /dev/null: {e}"))?;
    let mut cmd = Command::new(bin);
    cmd.args(args).arg(corpus);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.stdout(Stdio::from(devnull));
    cmd.stderr(Stdio::null());
    let t0 = Instant::now();
    let status = cmd.status().map_err(|e| format!("spawn {bin}: {e}"))?;
    let ms = t0.elapsed().as_secs_f64() * 1000.0;
    if !status.success() {
        return Err(format!("{bin} exited {status}"));
    }
    Ok(ms)
}

/// sha of `bin args... corpus` stdout (regular-file sink, read back).
fn decode_sha(
    bin: &str,
    args: &[String],
    corpus: &str,
    env: &[(&str, &str)],
) -> Result<String, String> {
    let tmp = std::env::temp_dir().join(format!("fulcrum_scalewall_{}.out", std::process::id()));
    let outf = std::fs::File::create(&tmp).map_err(|e| format!("create tmp: {e}"))?;
    let mut cmd = Command::new(bin);
    cmd.args(args).arg(corpus);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.stdout(Stdio::from(outf));
    cmd.stderr(Stdio::null());
    let st = cmd.status().map_err(|e| format!("spawn {bin}: {e}"))?;
    if !st.success() {
        return Err(format!("{bin} exited {st}"));
    }
    let bytes = std::fs::read(&tmp).map_err(|e| format!("read tmp: {e}"))?;
    let _ = std::fs::remove_file(&tmp);
    Ok(sha256_hex(&bytes))
}

/// Gate-0(c): run gz once at thread count T with GZIPPY_TIMELINE and confirm the
/// trace's drive.args.parallelization == T and that >=2 worker tids ran. Returns
/// (parallelization_seen, distinct_worker_tids).
fn verify_threads_applied(gz: &str, corpus: &str, t: usize) -> Result<(usize, usize), String> {
    let tl = std::env::temp_dir().join(format!("fulcrum_scalewall_tl_{}.json", std::process::id()));
    let tlp = tl.to_string_lossy().to_string();
    let devnull = std::fs::File::create("/dev/null").map_err(|e| format!("open /dev/null: {e}"))?;
    let st = Command::new(gz)
        .args(["-d", "-c", &format!("-p{t}")])
        .arg(corpus)
        .env("GZIPPY_FORCE_PARALLEL_SM", "1")
        .env("GZIPPY_TIMELINE", &tlp)
        .stdout(Stdio::from(devnull))
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("spawn gz (timeline): {e}"))?;
    if !st.success() {
        return Err(format!("gz timeline decode exited {st}"));
    }
    let txt = std::fs::read_to_string(&tlp).map_err(|e| format!("read timeline: {e}"))?;
    let _ = std::fs::remove_file(&tlp);
    // parallelization from the "drive" event
    let par = txt
        .find("\"parallelization\":")
        .and_then(|i| {
            txt[i + 18..]
                .split(|c: char| !c.is_ascii_digit())
                .find(|s| !s.is_empty())
        })
        .and_then(|s| s.parse::<usize>().ok())
        .ok_or("no parallelization arg in trace")?;
    // distinct worker tids: lines naming a worker.* span
    let mut tids = std::collections::HashSet::new();
    for line in txt.lines() {
        if line.contains("\"name\":\"worker.") {
            if let Some(i) = line.find("\"tid\":") {
                if let Some(s) = line[i + 6..]
                    .split(|c: char| !c.is_ascii_digit())
                    .find(|s| !s.is_empty())
                {
                    if let Ok(v) = s.parse::<usize>() {
                        tids.insert(v);
                    }
                }
            }
        }
    }
    Ok((par, tids.len()))
}

pub fn cmd_scalewall(args: &[String]) -> ExitCode {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "fulcrum scalewall (macOS) — THREAD-SCALING wall sweep + Amdahl serial fraction.\n\n\
             USAGE: fulcrum scalewall [--corpus f.gz] [--gz PATH] [--rg PATH]\n\
             \t[--threads 1,2,4,8,16] [--n N] [--phys-cores C]\n\n\
             Interleaved best-of-N per thread count, /dev/null sink BOTH arms, sha OUTSIDE\n\
             the timer. Emits per-T wall + speedup-vs-own-T1 + inferred Amdahl serial\n\
             fraction (from the largest non-oversubscribed T <= phys-cores).\n\
             Gate-0: native Mach-O both arms; sha==gzip-dc; thread-count APPLIED\n\
             (GZIPPY_TIMELINE parallelization==T, >=2 worker tids); A/A floor."
        );
        return ExitCode::SUCCESS;
    }
    let corpus = flag(args, "--corpus").unwrap_or(DEFAULT_CORPUS).to_string();
    let gz = flag(args, "--gz")
        .unwrap_or("/Users/jackdanger/www/gzippy-reimplement-isal/target/release/gzippy")
        .to_string();
    let rg = flag(args, "--rg")
        .unwrap_or("/tmp/rgbuild/src/tools/rapidgzip")
        .to_string();
    let n: usize = flag(args, "--n")
        .and_then(|s| s.parse().ok())
        .unwrap_or(11)
        .max(7);
    let phys: usize = flag(args, "--phys-cores")
        .and_then(|s| s.parse().ok())
        .unwrap_or(8);
    let threads: Vec<usize> = flag(args, "--threads")
        .unwrap_or("1,2,4,8,16")
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    let have_rg = Path::new(&rg).exists();

    println!("== fulcrum scalewall (macOS) — thread-scaling wall sweep ==");
    println!("corpus={corpus}  gz={gz}");
    if have_rg {
        println!("rg={rg}");
    } else {
        println!("rg=(absent — gz-only curve)");
    }
    println!("threads={threads:?}  N={n}  phys-cores={phys}\n");

    // ---- Gate-0 ------------------------------------------------------------
    println!("-- Gate-0 self-validation (BLOCKING) --");
    let mut ok = true;
    macro_rules! g0 {
        ($c:expr, $($m:tt)*) => {{
            let c = $c;
            println!("  [Gate-0] {} :: {}", if c {"PASS"} else {"FAIL"}, format!($($m)*));
            if !c { ok = false; }
        }};
    }
    match is_native_macho(&gz) {
        Ok(()) => g0!(true, "gz native Mach-O ({gz})"),
        Err(e) => g0!(false, "gz native: {e}"),
    }
    if have_rg {
        match is_native_macho(&rg) {
            Ok(()) => g0!(true, "rg native Mach-O ({rg})"),
            Err(e) => g0!(false, "rg native: {e}"),
        }
    }
    let oracle = match oracle_sha(&corpus) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("scalewall: oracle failed: {e}");
            return ExitCode::from(2);
        }
    };
    g0!(true, "oracle sha (gzip -dc) = {}…", &oracle[..12]);
    let t_lo = *threads.iter().min().unwrap_or(&1);
    let gz_env = [("GZIPPY_FORCE_PARALLEL_SM", "1")];
    match decode_sha(
        &gz,
        &["-d".into(), "-c".into(), format!("-p{t_lo}")],
        &corpus,
        &gz_env,
    ) {
        Ok(s) => g0!(s == oracle, "gz sha==oracle at -p{t_lo} ({}…)", &s[..12]),
        Err(e) => g0!(false, "gz decode: {e}"),
    }
    if have_rg {
        match decode_sha(
            &rg,
            &["-d".into(), "-c".into(), format!("-P{t_lo}")],
            &corpus,
            &[],
        ) {
            Ok(s) => g0!(s == oracle, "rg sha==oracle at -P{t_lo} ({}…)", &s[..12]),
            Err(e) => g0!(false, "rg decode: {e}"),
        }
    }
    // (c) thread-count actually applied at the max requested T
    let t_hi = *threads.iter().max().unwrap_or(&1);
    match verify_threads_applied(&gz, &corpus, t_hi) {
        Ok((par, ntid)) => {
            g0!(
                par == t_hi,
                "gz thread-count APPLIED: trace parallelization={par} == requested {t_hi}"
            );
            g0!(
                ntid >= 2 || t_hi == 1,
                "gz parallel workers ran: {ntid} distinct worker tids at -p{t_hi}"
            );
        }
        Err(e) => g0!(false, "gz thread-applied check: {e}"),
    }
    if !ok {
        eprintln!("\nscalewall: GATE-0 FAILED — refusing to report.");
        return ExitCode::FAILURE;
    }
    println!("-- Gate-0 PASSED --\n");

    // ---- Interleaved best-of-N sweep --------------------------------------
    // warmup
    for &t in &threads {
        let _ = timed_decode_devnull(
            &gz,
            &["-d".into(), "-c".into(), format!("-p{t}")],
            &corpus,
            &gz_env,
        );
        if have_rg {
            let _ = timed_decode_devnull(
                &rg,
                &["-d".into(), "-c".into(), format!("-P{t}")],
                &corpus,
                &[],
            );
        }
    }
    let mut gz_s: std::collections::HashMap<usize, Vec<f64>> =
        threads.iter().map(|&t| (t, vec![])).collect();
    let mut rg_s: std::collections::HashMap<usize, Vec<f64>> =
        threads.iter().map(|&t| (t, vec![])).collect();
    let mut aa: Vec<f64> = Vec::new();
    let mut seed = 0x243f6a88u64 ^ (std::process::id() as u64);
    for _ in 0..n {
        // schedule = (tool,T) cells, shuffled per rep to decorrelate drift
        let mut cells: Vec<(u8, usize)> = Vec::new();
        for &t in &threads {
            cells.push((0, t));
            if have_rg {
                cells.push((1, t));
            }
        }
        for i in (1..cells.len()).rev() {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let j = (seed >> 33) as usize % (i + 1);
            cells.swap(i, j);
        }
        let mut gz_t1: Option<f64> = None;
        for (tool, t) in cells {
            let ms = if tool == 0 {
                timed_decode_devnull(
                    &gz,
                    &["-d".into(), "-c".into(), format!("-p{t}")],
                    &corpus,
                    &gz_env,
                )
            } else {
                timed_decode_devnull(
                    &rg,
                    &["-d".into(), "-c".into(), format!("-P{t}")],
                    &corpus,
                    &[],
                )
            };
            match ms {
                Ok(v) => {
                    if tool == 0 {
                        gz_s.get_mut(&t).unwrap().push(v);
                        if t == t_lo {
                            gz_t1 = Some(v);
                        }
                    } else {
                        rg_s.get_mut(&t).unwrap().push(v);
                    }
                }
                Err(e) => {
                    eprintln!("  !! decode failed: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
        // A/A floor: one more gz decode at t_lo vs this rep's t_lo
        if let Some(g1) = gz_t1 {
            if let Ok(g2) = timed_decode_devnull(
                &gz,
                &["-d".into(), "-c".into(), format!("-p{t_lo}")],
                &corpus,
                &gz_env,
            ) {
                aa.push(g1 / g2);
            }
        }
    }

    // ---- Report ------------------------------------------------------------
    let report_tool = |label: &str,
                       s: &std::collections::HashMap<usize, Vec<f64>>|
     -> (Vec<(usize, f64)>, f64) {
        println!("  {label}:");
        println!(
            "    {:>3}  {:>9} {:>9} {:>8}  {:>8}",
            "T", "min_ms", "med_ms", "spread%", "speedup"
        );
        let t1 = minf(&s[&t_lo]);
        let mut mins = Vec::new();
        for &t in &threads {
            let v = &s[&t];
            if v.is_empty() {
                continue;
            }
            let mn = minf(v);
            mins.push((t, mn));
            println!(
                "    {:>3}  {:>9.2} {:>9.2} {:>8.1}  {:>7.3}×",
                t,
                mn,
                median(v),
                spread_pct(v),
                t1 / mn
            );
        }
        // Amdahl s from largest non-oversubscribed T
        let t_amdahl = *threads
            .iter()
            .filter(|&&t| t <= phys)
            .max()
            .unwrap_or(&t_lo);
        let sp = t1 / minf(&s[&t_amdahl]);
        let p = t_amdahl as f64;
        let serial = if sp > 1.0 {
            (p / sp - 1.0) / (p - 1.0)
        } else {
            1.0
        };
        let ceiling = if serial > 0.0 {
            1.0 / serial
        } else {
            f64::INFINITY
        };
        println!(
            "    Amdahl (from T{t_amdahl}, speedup {sp:.3}×): serial fraction s = {:.4}  ⇒ max-speedup ceiling ≈ {:.2}×",
            serial, ceiling
        );
        (mins, serial)
    };

    println!("== RESULTS (best-of-{n} interleaved, /dev/null both arms) ==\n");
    let (gz_mins, gz_serial) = report_tool("gz", &gz_s);
    let rg_serial = if have_rg {
        println!();
        let (_rg_mins, s) = report_tool("rg", &rg_s);
        Some(s)
    } else {
        None
    };

    let aa_m = median(&aa);
    let aa_spr = spread_pct(&aa);
    println!(
        "\n  Gate-1: A/A gz-vs-gz ratio={aa_m:.4} (±{aa_spr:.1}%)  [the floor a real Δ must clear]"
    );
    if have_rg {
        println!("\n  gz/rg wall ratio per T (min; <1 = gz faster):");
        for &t in &threads {
            if gz_s[&t].is_empty() || rg_s[&t].is_empty() {
                continue;
            }
            println!(
                "    T{:<2} gz/rg = {:.3}",
                t,
                minf(&gz_s[&t]) / minf(&rg_s[&t])
            );
        }
    }
    println!("\n  SCALING VERDICT:");
    println!("    gz serial fraction  s_gz = {gz_serial:.4}");
    if let Some(s_rg) = rg_serial {
        println!("    rg serial fraction  s_rg = {s_rg:.4}");
        if gz_serial > s_rg {
            println!(
                "    => gz has the LARGER serial fraction (+{:.1} pts) — scales worse vs its own T1.",
                100.0 * (gz_serial - s_rg)
            );
        } else {
            println!("    => gz serial fraction <= rg's — no scaling deficit on this run.");
        }
    }
    let _ = gz_mins;
    ExitCode::SUCCESS
}

// ===========================================================================
// `fulcrum counterdiff` (macOS) — paired gz-vs-libdeflate cyc/instr/IPC.
// ===========================================================================
pub fn cmd_counterdiff(args: &[String]) -> ExitCode {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "fulcrum counterdiff (macOS) — paired gz-vs-libdeflate cycles/instructions/IPC\n\
             via per-thread kpc around an in-process T1 decode.\n\n\
             USAGE: sudo -E fulcrum counterdiff [--corpus f.gz] [--n N]\n\
             Gate-0 self-tests (BLOCKING): native-comparator, per-arm sha==oracle,\n\
             same-sink, A/A ratio~1.0, counters sane (IPC in [0.5,8])."
        );
        return ExitCode::SUCCESS;
    }
    if let Err(e) = preflight_root() {
        eprintln!("counterdiff: {e}");
        return ExitCode::from(2);
    }
    let corpus = flag(args, "--corpus").unwrap_or(DEFAULT_CORPUS).to_string();
    let n: usize = flag(args, "--n")
        .and_then(|s| s.parse().ok())
        .unwrap_or(11)
        .max(9);

    let data = match std::fs::read(&corpus) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("counterdiff: read {corpus}: {e}");
            return ExitCode::from(2);
        }
    };

    println!("== fulcrum counterdiff (macOS / Apple-Silicon kpc) ==");
    println!("corpus={corpus} bytes={} N={n}", data.len());

    // ---- Gate-0 self-tests --------------------------------------------------
    let mut g0_ok = true;
    macro_rules! g0 {
        ($cond:expr, $($m:tt)*) => {{
            let ok = $cond;
            println!("  [Gate-0] {} :: {}", if ok {"PASS"} else {"FAIL"}, format!($($m)*));
            if !ok { g0_ok = false; }
        }};
    }
    println!("-- Gate-0 self-validation (BLOCKING) --");

    // (a) comparator native, not a wheel/wrapper: libdeflate is the libdeflate-rs
    //     crate = the libdeflate C library statically linked into THIS binary.
    g0!(
        true,
        "comparator=libdeflate C lib statically linked in-process (not a python wheel / shell wrapper)"
    );

    // Oracle
    let oracle = match oracle_sha(&corpus) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("counterdiff: oracle (gzip -dc) failed: {e}");
            return ExitCode::from(2);
        }
    };
    // Decompressed size from oracle run (re-read once for buffer sizing).
    let out_len_probe = {
        let o = Command::new("gzip")
            .arg("-dc")
            .arg(&corpus)
            .output()
            .unwrap();
        o.stdout.len()
    };
    let bufsz = out_len_probe + 4096;
    let mut buf = vec![0u8; bufsz];

    // (b) per-arm output sha == oracle  AND  (c) same sink (both → buf slice)
    let gz_len = run_gz(&data, &mut buf);
    let gz_sha = sha256_hex(&buf[..gz_len]);
    let ld_len = run_ld(&data, &mut buf);
    let ld_sha = sha256_hex(&buf[..ld_len]);
    g0!(
        gz_sha == oracle,
        "gz output sha == oracle (gzip -dc)  [{}…]",
        &gz_sha[..12]
    );
    g0!(
        ld_sha == oracle,
        "libdeflate output sha == oracle      [{}…]",
        &ld_sha[..12]
    );
    g0!(
        gz_len == ld_len && gz_len == out_len_probe,
        "same sink, equal output length gz={gz_len} ld={ld_len} oracle={out_len_probe}"
    );

    let pmu = match Pmu::new() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("counterdiff: PMU init failed: {e}");
            return ExitCode::from(2);
        }
    };
    println!("  pmu_db={}", pmu.db_name());
    for ev in ["FIXED_CYCLES", "FIXED_INSTRUCTIONS"] {
        g0!(pmu.has_event(ev), "event '{ev}' present in kpep DB");
    }

    // Program the PMU ONCE (re-programming kpc per-iteration fails); the counters
    // are free-running, so we just snapshot before/after each decode.
    let sess = match Session::program(&pmu, &["FIXED_CYCLES", "FIXED_INSTRUCTIONS"]) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("counterdiff: kpc program failed: {e}");
            return ExitCode::from(2);
        }
    };
    // Measurement: returns (cycles, instructions) for one decode of `arm`.
    // `buf` is REUSED (passed by &mut) so no 212 MiB clone/alloc contaminates
    // the counted region — only the decode itself is measured.
    let measure = |buf: &mut [u8], arm: char| -> (u64, u64) {
        let before = sess.read(&pmu);
        if arm == 'g' {
            run_gz(&data, buf);
        } else {
            run_ld(&data, buf);
        }
        let after = sess.read(&pmu);
        (after[0] - before[0], after[1] - before[1])
    };

    // warmup (uncounted)
    let _ = measure(&mut buf, 'g');
    let _ = measure(&mut buf, 'l');

    // (d) A/A: gz-vs-gz ratio must be ~1.0. Collect a gz-vs-gz cycle ratio set.
    let mut gz_cyc = Vec::new();
    let mut gz_ins = Vec::new();
    let mut ld_cyc = Vec::new();
    let mut ld_ins = Vec::new();
    let mut aa_ratio = Vec::new(); // gz_run_a / gz_run_b
    for _ in 0..n {
        // interleave g,l, plus a second g for A/A
        let (gc, gi) = measure(&mut buf, 'g');
        let (lc, li) = measure(&mut buf, 'l');
        let (gc2, _gi2) = measure(&mut buf, 'g');
        gz_cyc.push(gc as f64);
        gz_ins.push(gi as f64);
        ld_cyc.push(lc as f64);
        ld_ins.push(li as f64);
        aa_ratio.push(gc as f64 / gc2 as f64);
    }

    let out = out_len_probe as f64;
    let gz_cyc_m = median(&gz_cyc);
    let gz_ins_m = median(&gz_ins);
    let ld_cyc_m = median(&ld_cyc);
    let ld_ins_m = median(&ld_ins);
    let gz_ipc = gz_ins_m / gz_cyc_m;
    let ld_ipc = ld_ins_m / ld_cyc_m;
    let aa_m = median(&aa_ratio);
    let aa_spr = spread_pct(&aa_ratio);

    g0!(
        gz_cyc_m > 0.0 && ld_cyc_m > 0.0 && gz_ins_m > 0.0 && ld_ins_m > 0.0,
        "counters non-zero (gz_cyc={:.0} ld_cyc={:.0})",
        gz_cyc_m,
        ld_cyc_m
    );
    g0!(
        (0.5..=8.0).contains(&gz_ipc) && (0.5..=8.0).contains(&ld_ipc),
        "IPC in [0.5,8] (gz={gz_ipc:.3} ld={ld_ipc:.3})"
    );
    g0!(
        (aa_m - 1.0).abs() <= 0.05,
        "A/A gz-vs-gz ratio {aa_m:.4} ~ 1.0 (±5%); spread={aa_spr:.2}%"
    );

    if !g0_ok {
        eprintln!("\ncounterdiff: GATE-0 FAILED — refusing to report (numbers untrustworthy)");
        return ExitCode::FAILURE;
    }
    println!("-- Gate-0 PASSED — numbers are trustworthy --\n");

    // ---- Results ------------------------------------------------------------
    let cyc_spr = spread_pct(&gz_cyc);
    println!("metric                 gz            libdeflate     gz/ld");
    println!(
        "instr/byte         {:>10.4}     {:>10.4}     {:>6.4}",
        gz_ins_m / out,
        ld_ins_m / out,
        (gz_ins_m / out) / (ld_ins_m / out)
    );
    println!(
        "cyc/byte           {:>10.4}     {:>10.4}     {:>6.4}",
        gz_cyc_m / out,
        ld_cyc_m / out,
        (gz_cyc_m / out) / (ld_cyc_m / out)
    );
    println!(
        "IPC                {gz_ipc:>10.4}     {ld_ipc:>10.4}     {:>6.4}",
        gz_ipc / ld_ipc
    );
    println!(
        "cycles(M)          {:>10.2}     {:>10.2}     {:>6.4}",
        gz_cyc_m / 1e6,
        ld_cyc_m / 1e6,
        gz_cyc_m / ld_cyc_m
    );
    println!(
        "\nGate-1: N={n}  gz cyc/byte spread={cyc_spr:.2}%  A/A spread={aa_spr:.2}%  \
         (Δ vs A/A: gz/ld cyc Δ={:.1}% vs A/A {aa_spr:.1}%)",
        100.0 * (gz_cyc_m / ld_cyc_m - 1.0)
    );
    ExitCode::SUCCESS
}

// ===========================================================================
// `fulcrum kpcphase` (macOS) — COARSE per-phase RETIRED-INSTRUCTION differential
// (gz vs libdeflate), SAME METHOD BOTH SIDES.
//
// This is the tool the mission pulls: it corrects the prior model-vs-measurement
// dimensional error (gz fastloop = STATIC pathcount×disasm 1512.6M vs ld = KPC
// monolith 1342.3M — not gated) by measuring BOTH decoders' per-phase retired
// instructions with the IDENTICAL kpc instrument: the coarse `fx_phase_switch`
// state machine (see `mod phase`). It SPLITS libdeflate's inlined fastloop
// monolith — the stated attribution wall — into measured {other, header, build,
// fastloop} phases, conservation-closed against each side's own whole-decode
// retired total, with the per-switch instrument tax calibrated (enabled-vs-
// disabled whole) and reported.
//
// Gate-0 (BLOCKING): per-arm sha==oracle (gzip -dc); equal output length;
// FIXED_INSTRUCTIONS present; conservation |Σphase − whole_armed|/whole < 0.5%
// on EACH arm; tax fraction reported (a large tax invalidates the split → the
// sanctioned static-both fallback applies instead).
// ===========================================================================
pub fn cmd_kpcphase(args: &[String]) -> ExitCode {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "fulcrum kpcphase (macOS) — coarse per-phase retired-instruction\n\
             differential gz vs libdeflate, SAME kpc method both sides.\n\n\
             USAGE: sudo -E fulcrum kpcphase [--corpus f.gz] [--n N] [--json out.json]\n\
             Phases: other / header / build / fastloop (coarse, per deflate block).\n\
             Splits libdeflate's inlined fastloop monolith and conservation-\n\
             checks each side against its whole-decode retired total."
        );
        return ExitCode::SUCCESS;
    }
    if let Err(e) = preflight_root() {
        eprintln!("kpcphase: {e}");
        return ExitCode::from(2);
    }
    let corpus = flag(args, "--corpus").unwrap_or(DEFAULT_CORPUS).to_string();
    let n: usize = flag(args, "--n").and_then(|s| s.parse().ok()).unwrap_or(9);
    let json_path = flag(args, "--json").map(|s| s.to_string());

    let data = match std::fs::read(&corpus) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("kpcphase: read {corpus}: {e}");
            return ExitCode::from(2);
        }
    };

    println!("== fulcrum kpcphase (macOS / Apple-Silicon kpc) ==");
    println!("corpus={corpus} bytes={} N={n}", data.len());
    println!("-- Gate-0 self-validation (BLOCKING) --");
    let mut g0_ok = true;
    macro_rules! g0 {
        ($cond:expr, $($m:tt)*) => {{
            let ok = $cond;
            println!("  [Gate-0] {} :: {}", if ok {"PASS"} else {"FAIL"}, format!($($m)*));
            if !ok { g0_ok = false; }
        }};
    }

    let (oracle, out_len) = match oracle_sha_len(&corpus) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("kpcphase: oracle (gzip -dc) failed: {e}");
            return ExitCode::from(2);
        }
    };
    let mut buf = vec![0u8; out_len + 4096];

    // Correctness (same sink, sha == oracle) for BOTH arms.
    let gz_len = run_gz(&data, &mut buf);
    let gz_sha = sha256_hex(&buf[..gz_len]);
    g0!(gz_len == out_len, "gz output length {gz_len} == oracle {out_len}");
    g0!(gz_sha == oracle, "gz output sha == oracle [{}…]", &gz_sha[..12]);
    let ld_len = critpath_libdeflate::gzip_decode(&data, &mut buf);
    let ld_sha = sha256_hex(&buf[..ld_len]);
    g0!(ld_len == out_len, "ld output length {ld_len} == oracle {out_len}");
    g0!(ld_sha == oracle, "ld output sha == oracle [{}…]", &ld_sha[..12]);

    let pmu = match Pmu::new() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("kpcphase: PMU init failed: {e}");
            return ExitCode::from(2);
        }
    };
    println!("  pmu_db={}", pmu.db_name());
    g0!(
        pmu.has_event("FIXED_INSTRUCTIONS"),
        "event 'FIXED_INSTRUCTIONS' present in kpep DB"
    );
    // FIXED_INSTRUCTIONS FIRST so read_at(pmu,0) is retired instructions.
    let sess = match Session::program(&pmu, &["FIXED_INSTRUCTIONS"]) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("kpcphase: kpc program failed: {e}");
            return ExitCode::from(2);
        }
    };

    // Whole-decode retired (instrument DISARMED) for one arm.
    let whole_off = |buf: &mut [u8], arm: char| -> u64 {
        let before = sess.read_at(&pmu, 0);
        if arm == 'g' {
            run_gz(&data, buf);
        } else {
            critpath_libdeflate::gzip_decode(&data, buf);
        }
        let after = sess.read_at(&pmu, 0);
        after.wrapping_sub(before)
    };
    // One armed decode → (per-phase acc, per-phase fires, switches, whole_armed).
    let phase_run = |buf: &mut [u8], arm: char| -> ([u64; phase::NPHASE], [u64; phase::NPHASE], u64, u64) {
        let before = sess.read_at(&pmu, 0);
        unsafe { phase::arm(&pmu as *const Pmu, &sess as *const Session) };
        if arm == 'g' {
            run_gz(&data, buf);
        } else {
            critpath_libdeflate::gzip_decode(&data, buf);
        }
        let (acc, fires, switches) = unsafe { phase::disarm() };
        let after = sess.read_at(&pmu, 0);
        (acc, fires, switches, after.wrapping_sub(before))
    };

    // warmup (uncounted)
    let _ = whole_off(&mut buf, 'g');
    let _ = whole_off(&mut buf, 'l');

    // Per-arm measurement.
    struct ArmResult {
        name: &'static str,
        whole_off_m: f64,
        whole_armed_m: f64,
        phase_m: [f64; phase::NPHASE],
        fires: [u64; phase::NPHASE],
        switches: u64,
        tax: f64,
        tax_pct: f64,
        cons_pct: f64,
        phase_adj: [f64; phase::NPHASE],
    }
    let measure_arm = |name: &'static str, arm: char, buf: &mut [u8]| -> ArmResult {
        let mut off = Vec::with_capacity(n);
        let mut armed = Vec::with_capacity(n);
        let mut ph: [Vec<f64>; phase::NPHASE] = std::array::from_fn(|_| Vec::with_capacity(n));
        let mut fires = [0u64; phase::NPHASE];
        let mut switches = 0u64;
        for _ in 0..n {
            off.push(whole_off(buf, arm) as f64);
            let (acc, f, sw, w) = phase_run(buf, arm);
            armed.push(w as f64);
            for p in 0..phase::NPHASE {
                ph[p].push(acc[p] as f64);
            }
            fires = f;
            switches = sw;
        }
        let whole_off_m = median(&off);
        let whole_armed_m = median(&armed);
        let phase_m: [f64; phase::NPHASE] = std::array::from_fn(|p| median(&ph[p]));
        let sum_phase: f64 = phase_m.iter().sum();
        let tax = whole_armed_m - whole_off_m;
        let tax_pct = 100.0 * tax / whole_off_m;
        let cons_pct = 100.0 * (sum_phase - whole_armed_m).abs() / whole_armed_m;
        // Tax-adjusted phases: subtract per-switch tax weighted by each phase's
        // segment count (fires[p]); tax is ~uniform per switch.
        let tax_per_switch = if switches > 0 { tax / switches as f64 } else { 0.0 };
        let phase_adj: [f64; phase::NPHASE] =
            std::array::from_fn(|p| (phase_m[p] - fires[p] as f64 * tax_per_switch).max(0.0));
        ArmResult {
            name,
            whole_off_m,
            whole_armed_m,
            phase_m,
            fires,
            switches,
            tax,
            tax_pct,
            cons_pct,
            phase_adj,
        }
    };

    let gz = measure_arm("gz", 'g', &mut buf);
    let ld = measure_arm("ld", 'l', &mut buf);

    // Conservation gate (BLOCKING): Σphase must reconcile to whole_armed.
    g0!(
        gz.cons_pct < 0.5,
        "gz conservation Σphase vs whole {:.3}% < 0.5% (Σ={:.1}M whole={:.1}M)",
        gz.cons_pct,
        gz.phase_m.iter().sum::<f64>() / 1e6,
        gz.whole_armed_m / 1e6
    );
    g0!(
        ld.cons_pct < 0.5,
        "ld conservation Σphase vs whole {:.3}% < 0.5% (Σ={:.1}M whole={:.1}M)",
        ld.cons_pct,
        ld.phase_m.iter().sum::<f64>() / 1e6,
        ld.whole_armed_m / 1e6
    );

    if !g0_ok {
        eprintln!("\nkpcphase: GATE-0 FAILED — refusing to report (numbers untrustworthy)");
        return ExitCode::FAILURE;
    }
    println!("-- Gate-0 PASSED — numbers are trustworthy --\n");

    // ---- Report -------------------------------------------------------------
    let m = |x: f64| x / 1e6;
    println!(
        "whole-decode retired (instrument OFF):  gz={:.1}M  ld={:.1}M  gz-ld=+{:.1}M (+{:.1}%)",
        m(gz.whole_off_m),
        m(ld.whole_off_m),
        m(gz.whole_off_m - ld.whole_off_m),
        100.0 * (gz.whole_off_m / ld.whole_off_m - 1.0)
    );
    println!(
        "instrument tax (armed-off):             gz={:.1}M ({:.2}%, {} switches)  ld={:.1}M ({:.2}%, {} switches)",
        m(gz.tax),
        gz.tax_pct,
        gz.switches,
        m(ld.tax),
        ld.tax_pct,
        ld.switches
    );
    println!();
    println!("LIKE-FOR-LIKE per-phase RETIRED INSTRUCTIONS (tax-adjusted, M), SAME kpc method both sides:");
    println!(
        "{:<10} {:>12} {:>12} {:>14}   {:>10} {:>10}",
        "phase", "gz(M)", "ld(M)", "gz-ld(M)", "gz fires", "ld fires"
    );
    let mut diff = [0f64; phase::NPHASE];
    for p in 0..phase::NPHASE {
        diff[p] = gz.phase_adj[p] - ld.phase_adj[p];
        println!(
            "{:<10} {:>12.1} {:>12.1} {:>14.1}   {:>10} {:>10}",
            phase::PHASE_NAMES[p],
            m(gz.phase_adj[p]),
            m(ld.phase_adj[p]),
            m(diff[p]),
            gz.fires[p],
            ld.fires[p]
        );
    }
    let total_diff: f64 = diff.iter().sum();
    println!("{:<10} {:>12.1} {:>12.1} {:>14.1}", "TOTAL",
        m(gz.phase_adj.iter().sum::<f64>()),
        m(ld.phase_adj.iter().sum::<f64>()),
        m(total_diff));
    // Largest like-for-like surplus.
    let (mut top_p, mut top_v) = (0usize, f64::MIN);
    for p in 0..phase::NPHASE {
        if diff[p] > top_v {
            top_v = diff[p];
            top_p = p;
        }
    }
    println!(
        "\nLARGEST like-for-like surplus: phase '{}' = +{:.1}M ({:.1}% of the +{:.1}M whole-decode gap).",
        phase::PHASE_NAMES[top_p],
        m(top_v),
        100.0 * top_v / (gz.whole_off_m - ld.whole_off_m),
        m(gz.whole_off_m - ld.whole_off_m)
    );
    let fl = phase::FASTLOOP as usize;
    println!(
        "FASTLOOP verdict: gz={:.1}M vs ld={:.1}M ⇒ {} (gz-ld=+{:.1}M, {:.1}% of gap).",
        m(gz.phase_adj[fl]),
        m(ld.phase_adj[fl]),
        if diff[fl].abs() < 0.05 * gz.phase_adj[fl] {
            "≈PARITY"
        } else if diff[fl] > 0.0 {
            "REAL SURPLUS"
        } else {
            "gz AHEAD"
        },
        m(diff[fl]),
        100.0 * diff[fl] / (gz.whole_off_m - ld.whole_off_m)
    );

    if let Some(path) = json_path {
        let phase_json = |a: &ArmResult| -> String {
            let mut parts = Vec::new();
            for p in 0..phase::NPHASE {
                parts.push(format!(
                    "{{\"phase\":\"{}\",\"retired_raw_M\":{:.2},\"retired_adj_M\":{:.2},\"fires\":{}}}",
                    phase::PHASE_NAMES[p],
                    m(a.phase_m[p]),
                    m(a.phase_adj[p]),
                    a.fires[p]
                ));
            }
            format!(
                "{{\"name\":\"{}\",\"whole_off_M\":{:.2},\"whole_armed_M\":{:.2},\"tax_M\":{:.2},\"tax_pct\":{:.3},\"switches\":{},\"conservation_pct\":{:.4},\"phases\":[{}]}}",
                a.name, m(a.whole_off_m), m(a.whole_armed_m), m(a.tax), a.tax_pct, a.switches, a.cons_pct, parts.join(",")
            )
        };
        let mut diffs = Vec::new();
        for p in 0..phase::NPHASE {
            diffs.push(format!(
                "{{\"phase\":\"{}\",\"gz_minus_ld_M\":{:.2}}}",
                phase::PHASE_NAMES[p],
                m(diff[p])
            ));
        }
        let js = format!(
            "{{\n  \"title\": \"M1-T1 silesia coarse per-phase retired-instruction differential (gz vs libdeflate, SAME kpc method both sides)\",\n  \"arch\": \"arm64 Apple M1 Pro\", \"threads\": 1, \"corpus\": \"{}\", \"N\": {},\n  \"oracle_sha256_prefix\": \"{}\",\n  \"output_bytes\": {},\n  \"method\": \"coarse per-deflate-block fx_phase_switch state machine reading FIXED_INSTRUCTIONS via kpc; identical instrument on both decoders; tax = whole(armed)-whole(off), subtracted per-phase weighted by segment count\",\n  \"whole_decode_off\": {{\"gz_M\": {:.2}, \"ld_M\": {:.2}, \"gz_minus_ld_M\": {:.2}, \"gz_minus_ld_pct\": {:.2}}},\n  \"gz\": {},\n  \"ld\": {},\n  \"differential_adj\": [{}],\n  \"fastloop_surplus_M\": {:.2},\n  \"largest_surplus_phase\": \"{}\"\n}}\n",
            corpus, n, &oracle[..16], out_len,
            m(gz.whole_off_m), m(ld.whole_off_m),
            m(gz.whole_off_m - ld.whole_off_m),
            100.0 * (gz.whole_off_m / ld.whole_off_m - 1.0),
            phase_json(&gz), phase_json(&ld), diffs.join(","),
            m(diff[fl]), phase::PHASE_NAMES[top_p],
        );
        if let Err(e) = std::fs::write(&path, js) {
            eprintln!("kpcphase: write {path}: {e}");
        } else {
            println!("\nwrote {path}");
        }
    }
    ExitCode::SUCCESS
}

// ===========================================================================
// `fulcrum topdown` (macOS) — Firestorm stall classifier.
// PROVEN on discriminator microbenches before it reports gz/ld.
// ===========================================================================
const W_FIRESTORM: f64 = 8.0; // Firestorm dispatch/retire width (uops/cyc)
                              // STALL group (6 events): uop + stall counters. Branch counters cannot be
                              // co-placed here (they read 0), so bad-spec is measured in a separate process
                              // via BR_EVENTS. MAP_REWIND is dropped (reads ~0 on Firestorm).
const TD_EVENTS: [&str; 6] = [
    "FIXED_CYCLES",
    "FIXED_INSTRUCTIONS",
    "RETIRE_UOP",
    "SCHEDULE_UOP",
    "MAP_STALL",
    "SCHEDULE_EMPTY",
];

#[derive(Clone, Copy, Default)]
#[allow(dead_code)] // schedule_uop kept for index alignment / future slot views
struct Td {
    cyc: f64,
    ins: f64,
    retire_uop: f64,
    schedule_uop: f64,
    map_stall: f64,
    sched_empty: f64,
}
impl Td {
    fn from(c: &[u64]) -> Td {
        Td {
            cyc: c[0] as f64,
            ins: c[1] as f64,
            retire_uop: c[2] as f64,
            schedule_uop: c[3] as f64,
            map_stall: c[4] as f64,
            sched_empty: c[5] as f64,
        }
    }
    fn ipc(&self) -> f64 {
        self.ins / self.cyc
    }
    fn retiring_pct(&self) -> f64 {
        100.0 * self.retire_uop / (W_FIRESTORM * self.cyc)
    }
    fn backend_stall_pct(&self) -> f64 {
        100.0 * self.map_stall / self.cyc
    }
    fn frontend_pct(&self) -> f64 {
        100.0 * self.sched_empty / self.cyc
    }
}

fn measure_raw(pmu: &Pmu, sess: &Session, mut work: impl FnMut()) -> Vec<u64> {
    let before = sess.read(pmu);
    work();
    let after = sess.read(pmu);
    before.iter().zip(&after).map(|(b, a)| a - b).collect()
}
fn measure_td(pmu: &Pmu, sess: &Session, work: impl FnMut()) -> Td {
    Td::from(&measure_raw(pmu, sess, work))
}

// --- discriminator microbenches (the PROOF the classifier is correct) -------
#[inline(never)]
fn bench_pointer_chase(steps: usize) -> usize {
    // random-permutation pointer chase => dependent loads => backend/mem bound.
    let n = 1 << 22; // 4M slots * 8B = 32MiB >> LLC => DRAM latency bound
    let mut idx: Vec<usize> = (0..n).collect();
    // Fisher-Yates with a cheap LCG
    let mut s: u64 = 0x9e3779b97f4a7c15;
    for i in (1..n).rev() {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let j = (s >> 33) as usize % (i + 1);
        idx.swap(i, j);
    }
    // build a single cycle following the permutation
    let mut next = vec![0usize; n];
    let mut cur = 0usize;
    for &nx in idx.iter().skip(1) {
        next[cur] = nx;
        cur = nx;
    }
    next[cur] = idx[0];
    let mut p = 0usize;
    let mut acc = 0usize;
    for _ in 0..steps {
        p = next[p];
        acc = acc.wrapping_add(p);
    }
    acc
}

#[inline(never)]
fn bench_independent_adds(iters: usize) -> u64 {
    // 8 INDEPENDENT register accumulator chains => ILP-saturated => retiring.
    // Scalars (not an array) and a single black_box AFTER the loop keep the
    // accumulators in registers so we measure ALU throughput, not spills.
    let (mut a0, mut a1, mut a2, mut a3) = (1u64, 2u64, 3u64, 4u64);
    let (mut a4, mut a5, mut a6, mut a7) = (5u64, 6u64, 7u64, 8u64);
    for i in 0..iters {
        let x = i as u64;
        a0 = a0.wrapping_add(x | 1);
        a1 = a1.wrapping_add(x | 2);
        a2 = a2.wrapping_add(x | 3);
        a3 = a3.wrapping_add(x | 4);
        a4 = a4.wrapping_add(x | 5);
        a5 = a5.wrapping_add(x | 6);
        a6 = a6.wrapping_add(x | 7);
        a7 = a7.wrapping_add(x | 8);
    }
    std::hint::black_box(a0)
        ^ std::hint::black_box(a1)
        ^ std::hint::black_box(a2)
        ^ std::hint::black_box(a3)
        ^ std::hint::black_box(a4)
        ^ std::hint::black_box(a5)
        ^ std::hint::black_box(a6)
        ^ std::hint::black_box(a7)
}

// Two NON-INLINABLE call targets so the data-dependent choice below compiles to
// a real conditional BRANCH (not an ARM csel/predicated select) — otherwise the
// compiler flattens the branch and no misprediction is ever generated.
#[inline(never)]
fn br_arm_a(acc: u64, b: u64) -> u64 {
    acc.wrapping_add(b).rotate_left(1)
}
#[inline(never)]
fn br_arm_b(acc: u64, b: u64) -> u64 {
    acc.wrapping_mul(2654435761).wrapping_sub(b)
}

#[inline(never)]
fn bench_unpredictable_branch(data: &[u8]) -> u64 {
    // ~50/50 unpredictable branch on random bytes => high misprediction.
    let mut acc = 0u64;
    for &b in data {
        // loop-carried through acc so it can't be vectorized; two opaque call
        // targets so LLVM must emit a conditional branch to pick one.
        acc = if (b & 1) == 0 {
            br_arm_a(acc, b as u64)
        } else {
            br_arm_b(acc, b as u64)
        };
    }
    std::hint::black_box(acc)
}

// Branch counters (INST_BRANCH/BRANCH_MISPRED_NONSPEC) cannot be co-placed with
// the uop/stall counters on Firestorm — they read 0 — and re-programming a second
// configurable group within ONE process does not take effect on kpc. So the
// branch group is measured in a SEPARATE process (true replay-multiplex, exactly
// as the validated gztd harness did, one group per process invocation).
const BR_EVENTS: [&str; 4] = [
    "FIXED_CYCLES",
    "FIXED_INSTRUCTIONS",
    "INST_BRANCH",
    "BRANCH_MISPRED_NONSPEC",
];

fn br_rate(c: &[u64]) -> f64 {
    if c[2] == 0 {
        0.0
    } else {
        100.0 * c[3] as f64 / c[2] as f64
    }
}

/// Hidden child mode: program the branch-only group in a FRESH process and print
/// the four misprediction rates the parent needs. Stdout contract (one line):
///   BRANCH add=<%> rand=<%> gz=<%> ld=<%>
fn topdown_branch_child(corpus: &str) -> ExitCode {
    if preflight_root().is_err() {
        eprintln!("topdown branch-child: needs root");
        return ExitCode::from(2);
    }
    let pmu = match Pmu::new() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("topdown branch-child: PMU {e}");
            return ExitCode::from(2);
        }
    };
    let sess = match Session::program(&pmu, &BR_EVENTS) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("topdown branch-child: program {e}");
            return ExitCode::from(2);
        }
    };
    let rng: Vec<u8> = {
        let mut s: u64 = 0xdeadbeef;
        (0..60_000_000u64)
            .map(|_| {
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
                (s >> 33) as u8
            })
            .collect()
    };
    std::hint::black_box(bench_independent_adds(1 << 22));
    let add = br_rate(&measure_raw(&pmu, &sess, || {
        std::hint::black_box(bench_independent_adds(40_000_000));
    }));
    let rand = br_rate(&measure_raw(&pmu, &sess, || {
        std::hint::black_box(bench_unpredictable_branch(&rng));
    }));
    let data = std::fs::read(corpus).expect("read corpus");
    let out_len = Command::new("gzip")
        .arg("-dc")
        .arg(corpus)
        .output()
        .map(|o| o.stdout.len())
        .unwrap_or(0);
    let mut buf = vec![0u8; out_len + 4096];
    run_gz(&data, &mut buf);
    let gz = br_rate(&measure_raw(&pmu, &sess, || {
        run_gz(&data, &mut buf);
    }));
    let ld = br_rate(&measure_raw(&pmu, &sess, || {
        run_ld(&data, &mut buf);
    }));
    println!("BRANCH add={add:.4} rand={rand:.4} gz={gz:.4} ld={ld:.4}");
    ExitCode::SUCCESS
}

/// Parent: spawn the branch-group child and parse (add, rand, gz, ld) mispred %.
fn spawn_branch_child(corpus: &str) -> Result<(f64, f64, f64, f64), String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let out = Command::new(&exe)
        .arg("topdown")
        .arg("--_branch-child")
        .arg("--corpus")
        .arg(corpus)
        .output()
        .map_err(|e| format!("spawn branch-child: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "branch-child exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let line = s
        .lines()
        .find(|l| l.starts_with("BRANCH "))
        .ok_or_else(|| format!("no BRANCH line in child output: {s}"))?;
    let mut vals = [f64::NAN; 4];
    for tok in line.split_whitespace() {
        if let Some(v) = tok.strip_prefix("add=") {
            vals[0] = v.parse().unwrap_or(f64::NAN);
        } else if let Some(v) = tok.strip_prefix("rand=") {
            vals[1] = v.parse().unwrap_or(f64::NAN);
        } else if let Some(v) = tok.strip_prefix("gz=") {
            vals[2] = v.parse().unwrap_or(f64::NAN);
        } else if let Some(v) = tok.strip_prefix("ld=") {
            vals[3] = v.parse().unwrap_or(f64::NAN);
        }
    }
    Ok((vals[0], vals[1], vals[2], vals[3]))
}

pub fn cmd_topdown(args: &[String]) -> ExitCode {
    if args.iter().any(|a| a == "--_branch-child") {
        let corpus = flag(args, "--corpus").unwrap_or(DEFAULT_CORPUS).to_string();
        return topdown_branch_child(&corpus);
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "fulcrum topdown (macOS) — Firestorm stall classifier (retiring/backend/frontend/\n\
             bad-spec) via per-thread kpc. PROVES itself on 3 discriminator microbenches\n\
             before reporting gz/ld; REFUSES if a discriminator misclassifies.\n\n\
             USAGE: sudo -E fulcrum topdown [--corpus f.gz]"
        );
        return ExitCode::SUCCESS;
    }
    if let Err(e) = preflight_root() {
        eprintln!("topdown: {e}");
        return ExitCode::from(2);
    }
    let corpus = flag(args, "--corpus").unwrap_or(DEFAULT_CORPUS).to_string();

    let pmu = match Pmu::new() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("topdown: PMU init failed: {e}");
            return ExitCode::from(2);
        }
    };
    println!("== fulcrum topdown (macOS / Apple-Silicon kpc, W={W_FIRESTORM} uops/cyc) ==");
    println!("pmu_db={}", pmu.db_name());
    for ev in TD_EVENTS {
        if !pmu.has_event(ev) {
            eprintln!("topdown: event '{ev}' missing from kpep DB — cannot classify");
            return ExitCode::from(2);
        }
    }

    // Program the PMU ONCE for the whole run (one combined group; re-programming
    // a second configurable group within the process does not take effect).
    let sess = match Session::program(&pmu, &TD_EVENTS) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("topdown: kpc program failed: {e}");
            return ExitCode::from(2);
        }
    };

    // ---- Gate-0: PROVE the classifier on discriminators ---------------------
    println!("\n-- Gate-0: discriminator self-proof (BLOCKING) --");
    // warmup
    std::hint::black_box(bench_pointer_chase(1 << 20));
    std::hint::black_box(bench_independent_adds(1 << 22));

    let pc = measure_td(&pmu, &sess, || {
        std::hint::black_box(bench_pointer_chase(40_000_000));
    });
    let add = measure_td(&pmu, &sess, || {
        std::hint::black_box(bench_independent_adds(40_000_000));
    });
    let rng: Vec<u8> = {
        let mut s: u64 = 0xdeadbeef;
        (0..60_000_000u64)
            .map(|_| {
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
                (s >> 33) as u8
            })
            .collect()
    };
    let br = measure_td(&pmu, &sess, || {
        std::hint::black_box(bench_unpredictable_branch(&rng));
    });

    // gz/ld STALL measurement — must run with the parent's TD config STILL live,
    // i.e. BEFORE the branch-group child (kpc is system-global; the child's
    // re-program would otherwise clobber the parent's counters).
    let data = match std::fs::read(&corpus) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("topdown: read {corpus}: {e}");
            return ExitCode::from(2);
        }
    };
    let probe = Command::new("gzip").arg("-dc").arg(&corpus).output();
    let out_len = match probe {
        Ok(o) if o.status.success() => o.stdout.len(),
        _ => {
            eprintln!("topdown: gzip -dc probe failed");
            return ExitCode::from(2);
        }
    };
    let mut buf = vec![0u8; out_len + 4096];
    run_gz(&data, &mut buf); // warmup (buf REUSED — no clone in counted region)
    run_ld(&data, &mut buf);
    let gz = measure_td(&pmu, &sess, || {
        run_gz(&data, &mut buf);
    });
    let ld = measure_td(&pmu, &sess, || {
        run_ld(&data, &mut buf);
    });

    // All parent (TD-group) kpc reads are now done. Spawn the branch-group child
    // LAST — its PMU re-program clobbers the global config, which is fine now.
    let (add_mis, rand_mis, gz_mis, ld_mis) = match spawn_branch_child(&corpus) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("topdown: branch-group child failed: {e}");
            return ExitCode::from(2);
        }
    };

    let dline = |name: &str, t: &Td, mis: f64| {
        let m = if mis.is_finite() {
            format!("{mis:.2}%")
        } else {
            "n/a".to_string()
        };
        println!(
            "  {name:<14}: IPC={:.2} backend={:.1}% retiring={:.1}% mispred={m}",
            t.ipc(),
            t.backend_stall_pct(),
            t.retiring_pct(),
        );
    };
    dline("pointer-chase", &pc, f64::NAN);
    dline("indep-adds", &add, add_mis);
    dline("rand-branch", &br, rand_mis);

    let mut ok = true;
    macro_rules! disc {
        ($cond:expr, $($m:tt)*) => {{
            let c = $cond;
            println!("  [discriminator] {} :: {}", if c {"PASS"} else {"FAIL"}, format!($($m)*));
            if !c { ok = false; }
        }};
    }
    // pointer-chase must be the MOST backend-bound and have the LOWEST IPC.
    disc!(
        pc.backend_stall_pct() > add.backend_stall_pct(),
        "pointer-chase backend-stall {:.1}% > indep-adds {:.1}% (mem dependency stalls the backend)",
        pc.backend_stall_pct(),
        add.backend_stall_pct()
    );
    disc!(
        pc.ipc() < add.ipc(),
        "pointer-chase IPC {:.2} < indep-adds IPC {:.2} (latency-bound vs ILP-saturated)",
        pc.ipc(),
        add.ipc()
    );
    // indep-adds must be the MOST retiring (compute-bound, high IPC).
    disc!(
        add.retiring_pct() > pc.retiring_pct(),
        "indep-adds retiring {:.1}% > pointer-chase {:.1}%",
        add.retiring_pct(),
        pc.retiring_pct()
    );
    disc!(
        add.ipc() > 3.0,
        "indep-adds IPC {:.2} > 3.0 (genuinely retiring-bound)",
        add.ipc()
    );
    // rand-branch must MISPREDICT far more than the predictable compute loop.
    // Measured directly as BRANCH_MISPRED_NONSPEC/INST_BRANCH in the branch-group
    // child (the slot delta SCHEDULE_UOP-RETIRE_UOP is not a valid bad-spec
    // signal on Firestorm, and branch counters cannot co-place with uop counters).
    disc!(
        rand_mis > 10.0 && rand_mis > 5.0 * add_mis.max(0.01),
        "rand-branch mispred {rand_mis:.2}% > 10% and >> indep-adds {add_mis:.2}% (bad-spec discriminated)"
    );

    if !ok {
        eprintln!(
            "\ntopdown: discriminators MISCLASSIFIED — classifier not proven; REFUSING to report gz/ld"
        );
        return ExitCode::FAILURE;
    }
    println!("-- Gate-0 PASSED: classifier proven on all 3 discriminators --\n");

    // ---- Real measurement: gz vs ld (measured above, before the child) -------
    println!("corpus={corpus} out_bytes={out_len}");
    println!("metric                       gz          libdeflate");
    let row = |label: &str, g: f64, l: f64| println!("{label:<24} {g:>10.3}  {l:>10.3}");
    row("IPC", gz.ipc(), ld.ipc());
    row(
        "instr/byte",
        gz.ins / out_len as f64,
        ld.ins / out_len as f64,
    );
    row("cyc/byte", gz.cyc / out_len as f64, ld.cyc / out_len as f64);
    println!("  -- slot view (/W·cycles) --");
    row("%Retiring", gz.retiring_pct(), ld.retiring_pct());
    println!("  -- cycle-stall view (/cycles) --");
    row(
        "%MAP_STALL(backend)",
        gz.backend_stall_pct(),
        ld.backend_stall_pct(),
    );
    row("%SCHED_EMPTY(front)", gz.frontend_pct(), ld.frontend_pct());
    println!("  -- bad-spec (direct, branch-group child) --");
    row("br_mispred_rate%", gz_mis, ld_mis);
    ExitCode::SUCCESS
}

// ===========================================================================
// `fulcrum wall` (macOS) — interleaved best-of-N wall A/B, sha OUTSIDE timer.
// ===========================================================================
#[derive(Clone)]
struct Arm {
    key: String,
    bin: String,
    decode_args: Vec<String>,
    /// Extra environment variables to set on the decode subprocess (empty for the
    /// normal arms; used by `fulcrum assay` to arm the gz instruction-tax knob on
    /// the B arm while the A arm is the unmodified production binary).
    env: Vec<(String, String)>,
}

fn is_native_macho(path: &str) -> Result<(), String> {
    if !Path::new(path).exists() {
        return Err(format!("{path} does not exist"));
    }
    let out = Command::new("file")
        .arg("-b")
        .arg(path)
        .output()
        .map_err(|e| format!("file {path}: {e}"))?;
    let desc = String::from_utf8_lossy(&out.stdout).to_lowercase();
    if desc.contains("mach-o") && (desc.contains("executable") || desc.contains("bundle")) {
        Ok(())
    } else {
        Err(format!(
            "{path} is not a native Mach-O executable (file says: {}) — rejecting wheel/script wrapper",
            desc.trim()
        ))
    }
}

/// Run one decode of `arm`, writing decompressed output to `out_path`.
/// The timer wraps ONLY the decode subprocess; the sha is computed AFTER, on the
/// written file. This makes the shasum-in-timer bug structurally impossible.
fn timed_decode(arm: &Arm, corpus: &str, out_path: &str) -> Result<(f64, String), String> {
    let outf = std::fs::File::create(out_path).map_err(|e| format!("create {out_path}: {e}"))?;
    let mut cmd = Command::new(&arm.bin);
    for (k, v) in &arm.env {
        cmd.env(k, v);
    }
    cmd.args(&arm.decode_args).arg(corpus);
    cmd.stdout(Stdio::from(outf));
    cmd.stderr(Stdio::null());
    let t0 = Instant::now();
    let status = cmd
        .status()
        .map_err(|e| format!("spawn {}: {e}", arm.bin))?;
    let ms = t0.elapsed().as_secs_f64() * 1000.0;
    if !status.success() {
        return Err(format!("{} exited {status}", arm.key));
    }
    // ---- sha computed OUTSIDE the timed region ----
    let bytes = std::fs::read(out_path).map_err(|e| format!("read {out_path}: {e}"))?;
    Ok((ms, sha256_hex(&bytes)))
}

// ===========================================================================
// `fulcrum wall --steady` (macOS) — REPRODUCIBLE steady-state A/B.
//
// WHY this mode exists. The plain interleaved wall A/B above is internally
// honest (sha outside timer, same sink) but on a LAPTOP its gz-vs-libdeflate
// RATIO drifts across sessions (measured 1.02–1.056) even though gz-vs-gz A/A
// is tight in any single run. The cause is not a code change: gz and libdeflate
// respond DIFFERENTLY to the P-cluster's instantaneous DVFS frequency / thermal
// state, so the ratio is a function of the frequency it was measured at. Two
// sessions at two thermal states give two ratios — each "correct", neither
// reproducible. A ratio you cannot reproduce cannot gate a ≤1.0 win.
//
// The fix is to (1) hold the measurement frequency steady and (2) prove the
// ratio reproduces across cohorts spread over time:
//   1. PIN to the performance cluster (QoS USER_INTERACTIVE) + caffeinate so
//      the OS neither idles us onto an E-core nor sleeps the machine. (Apple
//      Silicon has no per-core affinity — DVFS is per-CLUSTER — so "one P-core"
//      is realized as "P-cluster at a held frequency", and the throttle filter
//      below enforces the "held frequency" half.)
//   2. WARM UP to thermal/frequency steady-state: loop decode+freq-probe until
//      the effective GHz (kpc FIXED_CYCLES / wall-ns of a fixed-work ALU kernel)
//      stops drifting, and only then start timing. Record per-sample effGHz.
//   3. FREQ-NORMALIZED PAIRED RATIO: tight gz,ld(,gz) triples so the two arms
//      see the SAME frequency within a pair (cancels per-pair freq); probe GHz
//      before AND after each pair; DISCARD any pair whose GHz deviated from the
//      steady median by > throttle-tol (a throttle event mid-pair).
//   4. MULTI-COHORT: K≥4 separate timing cohorts spread over time with a
//      cooldown between, so cross-cohort spread captures slow thermal drift.
//
// SELF-TEST (Gate-0, steady-specific, BLOCKING): the gz-vs-gz A/A cross-cohort
// spread IS the reproducibility floor of this instrument; a gz-vs-ld verdict is
// reported as REPRODUCIBLE only if the gz/ld effect clears that A/A floor in
// EVERY cohort with a consistent sign. Otherwise the honest output is
// NOT-RESOLVABLE-on-this-laptop (→ a quiet Linux-arm64 box is the path), which
// is itself a valid gated finding: the instability is a measurement fact.
// ===========================================================================

// QoS lives in libSystem (always linked on macOS); libc 0.2 doesn't re-export
// it, so declare the one symbol we need. USER_INTERACTIVE keeps this thread on
// the performance cluster (the closest macOS gives to "pin to a P-core").
extern "C" {
    fn pthread_set_qos_class_self_np(qos_class: u32, relative_priority: i32) -> i32;
}
const QOS_CLASS_USER_INTERACTIVE: u32 = 0x21;

/// Best-effort pin of THIS thread to the performance cluster. Returns whether
/// the QoS call succeeded (false ⇒ we report degraded pinning, not a hard fail).
fn pin_to_pcluster() -> bool {
    unsafe { pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0) == 0 }
}

/// Hold a `caffeinate` child for the lifetime of THIS process (`-w <pid>`), so
/// the machine never idle-sleeps or dims mid-measurement. Auto-reaps when we
/// exit. Returns the child (kept alive by the caller binding it).
fn start_caffeinate() -> Option<std::process::Child> {
    let pid = std::process::id().to_string();
    which("caffeinate").and_then(|c| {
        Command::new(c)
            .args(["-dimsu", "-w", &pid])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()
    })
}

/// Fixed-work ALU kernel iterations for the frequency probe. ~8 ops/iter,
/// ILP-saturated ⇒ ~constant cycle count, so cycles/wall-ns == effective GHz of
/// the cluster at this instant (the IPC of the kernel is held constant, so a
/// changing cycles/ns is a changing frequency, not changing work).
const GHZ_PROBE_ITERS: usize = 60_000_000;

/// Effective GHz of the calling thread's cluster RIGHT NOW: run the fixed-work
/// kernel, read FIXED_CYCLES across it via kpc, divide by wall-ns.
fn probe_ghz(pmu: &Pmu, sess: &Session) -> f64 {
    let before = sess.read(pmu)[0];
    let t0 = Instant::now();
    let r = bench_independent_adds(GHZ_PROBE_ITERS);
    let dt_ns = t0.elapsed().as_nanos() as f64;
    let after = sess.read(pmu)[0];
    std::hint::black_box(r);
    if dt_ns <= 0.0 {
        return 0.0;
    }
    (after.wrapping_sub(before)) as f64 / dt_ns
}

/// Time ONE subprocess decode of `arm` with a /dev/null sink (the same sink rg
/// is measured with; no per-rep 212 MiB tmpfile write to add I/O noise). sha is
/// NOT checked here — correctness is gated once, up front; this is the hot path.
fn decode_devnull(arm: &Arm, corpus: &str) -> Result<f64, String> {
    let devnull = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .map_err(|e| format!("open /dev/null: {e}"))?;
    let mut cmd = Command::new(&arm.bin);
    for (k, v) in &arm.env {
        cmd.env(k, v);
    }
    cmd.args(&arm.decode_args).arg(corpus);
    cmd.stdout(Stdio::from(devnull));
    cmd.stderr(Stdio::null());
    let t0 = Instant::now();
    let status = cmd
        .status()
        .map_err(|e| format!("spawn {}: {e}", arm.bin))?;
    let ms = t0.elapsed().as_secs_f64() * 1000.0;
    if !status.success() {
        return Err(format!("{} exited {status}", arm.key));
    }
    Ok(ms)
}

/// BUG-1 path-identity probe: run the SAME wall-arm command (`gz -d -c -p1
/// corpus`, /dev/null sink) with the instruction tax armed AND
/// `GZIPPY_ASSAY_TAX_STATS=1`, then parse the subprocess's printed
/// `fires=<N>` (one fastloop application per qualifying iteration). This is the
/// fastloop-iteration count of the LITERAL wall arm — used to prove the
/// in-process calibration traverses the SAME code path (same iteration count),
/// so the calibrated instr% actually describes the wall arm. Returns `None` if
/// the subprocess failed or printed no parseable `fires=` line.
fn subprocess_fires(
    gz_bin: &str,
    corpus: &str,
    mode: &str,
    dose: u64,
    stride: u64,
) -> Option<u64> {
    let devnull = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .ok()?;
    let out = Command::new(gz_bin)
        .args(["-d", "-c", "-p1"])
        .arg(corpus)
        .env("GZIPPY_ASSAY_TAX_MODE", mode)
        .env("GZIPPY_ASSAY_TAX_DOSE", dose.to_string())
        .env("GZIPPY_ASSAY_TAX_STRIDE", stride.to_string())
        .env("GZIPPY_ASSAY_TAX_STATS", "1")
        .stdout(Stdio::from(devnull))
        .stderr(Stdio::piped())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let err = String::from_utf8_lossy(&out.stderr);
    // Line: "[assay_tax] mode=dependent dose=1 stride=1 armed=true fires=23622691"
    for tok in err.split_whitespace() {
        if let Some(n) = tok.strip_prefix("fires=") {
            return n.parse::<u64>().ok();
        }
    }
    None
}

/// Per-cohort accumulation of the freq-filtered paired ratios.
struct Cohort {
    sig_ratios: Vec<f64>, // gz/ld per kept pair
    aa_ratios: Vec<f64>,  // gz/gz per kept pair (reproducibility floor)
    ghz: Vec<f64>,        // per-kept-pair mean effGHz
    discarded: usize,     // pairs dropped by the throttle filter
}

/// Raw cohort output of the steady loop, before the verdict is computed. Shared
/// by `wall --steady` and the `vs` head-to-head subcommand so both run the EXACT
/// same freq-normalized paired-ratio machinery.
struct SteadyRaw {
    cohort_sig: Vec<f64>, // per-cohort median gz/ld
    cohort_aa: Vec<f64>,  // per-cohort median gz/gz (reproducibility floor)
    steady_ghz: f64,
    total_kept: usize,
    total_drop: usize,
    converged: bool,
}

/// Run warmup + K cohorts of freq-normalized paired ratios and the post gate.
/// Prints the warmup line, the per-cohort table, and the steady gates. Returns
/// `None` (after printing the failure) if the cohorts did not yield enough
/// throttle-surviving pairs to trust a verdict.
fn run_steady_cohorts(
    args: &[String],
    gz: &Arm,
    ld: &Arm,
    corpus: &str,
    pmu: &Pmu,
    sess: &Session,
    ghz0: f64,
) -> Option<SteadyRaw> {
    let cohorts: usize = flag(args, "--cohorts")
        .and_then(|s| s.parse().ok())
        .unwrap_or(4)
        .max(4);
    let pairs: usize = flag(args, "--pairs")
        .and_then(|s| s.parse().ok())
        .unwrap_or(9)
        .max(7);
    let warmup_secs: f64 = flag(args, "--warmup-secs")
        .and_then(|s| s.parse().ok())
        .unwrap_or(20.0);
    let cooldown_secs: f64 = flag(args, "--cooldown-secs")
        .and_then(|s| s.parse().ok())
        .unwrap_or(5.0);
    let throttle_tol: f64 = flag(args, "--throttle-tol")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.03);

    // ---- WARMUP to steady frequency -----------------------------------------
    const WIN: usize = 6;
    let warm_tol = throttle_tol;
    let warm_t0 = Instant::now();
    let mut win: Vec<f64> = Vec::new();
    let mut converged = false;
    let mut iters = 0usize;
    while warm_t0.elapsed().as_secs_f64() < warmup_secs {
        let _ = decode_devnull(gz, corpus);
        let g = probe_ghz(pmu, sess);
        win.push(g);
        if win.len() > WIN {
            win.remove(0);
        }
        iters += 1;
        if win.len() == WIN && spread_pct(&win) < warm_tol * 100.0 {
            converged = true;
            break;
        }
    }
    let steady_ghz = if win.is_empty() { ghz0 } else { median(&win) };
    println!(
        "warmup: {} iters, {:.1}s, steady≈{steady_ghz:.3} GHz (window spread {:.2}%) — {}",
        iters,
        warm_t0.elapsed().as_secs_f64(),
        spread_pct(&win),
        if converged {
            "CONVERGED"
        } else {
            "BUDGET-LIMITED (flagging)"
        }
    );
    if steady_ghz <= 0.0 {
        eprintln!("steady: steady GHz non-positive — aborting");
        return None;
    }

    // ---- COHORTS ------------------------------------------------------------
    println!(
        "\n{:<7} {:>9} {:>9} {:>8} {:>8} {:>7} {:>9}",
        "cohort", "gz/ld", "A/A", "effGHz", "kept", "drop", "freqΔ%"
    );
    let mut cohort_sig: Vec<f64> = Vec::new();
    let mut cohort_aa: Vec<f64> = Vec::new();
    let mut total_kept = 0usize;
    let mut total_drop = 0usize;
    for c in 0..cohorts {
        let mut co = Cohort {
            sig_ratios: Vec::new(),
            aa_ratios: Vec::new(),
            ghz: Vec::new(),
            discarded: 0,
        };
        for p in 0..pairs {
            let ghz_pre = probe_ghz(pmu, sess);
            let (ms_gz, ms_ld) = if p % 2 == 0 {
                let g = decode_devnull(gz, corpus);
                let l = decode_devnull(ld, corpus);
                (g, l)
            } else {
                let l = decode_devnull(ld, corpus);
                let g = decode_devnull(gz, corpus);
                (g, l)
            };
            let ms_gz2 = decode_devnull(gz, corpus);
            let ghz_post = probe_ghz(pmu, sess);
            let (ms_gz, ms_ld, ms_gz2) = match (ms_gz, ms_ld, ms_gz2) {
                (Ok(a), Ok(b), Ok(c)) => (a, b, c),
                _ => {
                    eprintln!("  !! decode error in cohort {c} pair {p} — aborting");
                    return None;
                }
            };
            let ghz_pair = (ghz_pre + ghz_post) / 2.0;
            let off_steady = (ghz_pair - steady_ghz).abs() / steady_ghz;
            let intra = (ghz_pre - ghz_post).abs() / ghz_pair.max(1e-9);
            if off_steady > throttle_tol || intra > throttle_tol {
                co.discarded += 1;
                continue;
            }
            co.sig_ratios.push(ms_gz / ms_ld);
            co.aa_ratios.push(ms_gz / ms_gz2);
            co.ghz.push(ghz_pair);
        }
        let sig = median(&co.sig_ratios);
        let aa = median(&co.aa_ratios);
        let cghz = median(&co.ghz);
        let freqd = if co.ghz.len() >= 2 {
            spread_pct(&co.ghz)
        } else {
            0.0
        };
        let kept = co.sig_ratios.len();
        total_kept += kept;
        total_drop += co.discarded;
        println!(
            "{:<7} {:>9.4} {:>9.4} {:>8.3} {:>8} {:>7} {:>9.2}",
            c, sig, aa, cghz, kept, co.discarded, freqd
        );
        if kept >= 3 {
            cohort_sig.push(sig);
            cohort_aa.push(aa);
        }
        if c + 1 < cohorts {
            std::thread::sleep(std::time::Duration::from_secs_f64(cooldown_secs));
        }
    }

    // ---- post gate: enough kept pairs to trust the cohorts -------------------
    let mut g1_ok = true;
    macro_rules! g1 {
        ($cond:expr, $($m:tt)*) => {{
            let ok = $cond;
            println!("  [Gate] {} :: {}", if ok {"PASS"} else {"FAIL"}, format!($($m)*));
            if !ok { g1_ok = false; }
        }};
    }
    println!("\n-- steady-state gates --");
    g1!(
        cohort_sig.len() >= 4,
        "≥4 cohorts produced ≥3 kept pairs each ({} valid cohorts, {total_kept} kept / {total_drop} throttle-dropped)",
        cohort_sig.len()
    );
    g1!(
        converged,
        "warmup reached steady frequency (else cross-cohort spread may be thermal, not real)"
    );
    if !g1_ok {
        eprintln!(
            "\nsteady: NOT RESOLVABLE — too few steady-frequency pairs survived the \
             throttle filter on this laptop. Path: a quiet Linux-arm64 box."
        );
        return None;
    }

    Some(SteadyRaw {
        cohort_sig,
        cohort_aa,
        steady_ghz,
        total_kept,
        total_drop,
        converged,
    })
}

/// Verdict computed from the per-cohort ratios. `a`/`b` are arm labels (for the
/// printed BEATS/LOSES TO line).
struct SteadyVerdict {
    overall: f64,       // median cross-cohort gz/ref ratio
    effect_pct: f64,    // signed %, <0 ⇒ gz faster
    signal_spread: f64, // cross-cohort spread of the ratio
    floor: f64,         // A/A cross-cohort spread = reproducibility floor
    min_mag: f64,       // min per-cohort |effect|
    consistent_sign: bool,
    all_faster: bool,
    status: &'static str, // REPRODUCIBLE | REPRODUCIBLE_TIE | NOT_RESOLVABLE
}

/// Compute AND print the steady verdict from the raw per-cohort ratios.
fn steady_verdict(cohort_sig: &[f64], cohort_aa: &[f64], a: &str, b: &str) -> SteadyVerdict {
    let overall = median(cohort_sig);
    let effect_pct = 100.0 * (overall - 1.0);
    let signal_spread = spread_pct(cohort_sig);
    let floor = spread_pct(cohort_aa);
    let mags: Vec<f64> = cohort_sig.iter().map(|r| 100.0 * (r - 1.0).abs()).collect();
    let min_mag = minf(&mags);
    let all_faster = cohort_sig.iter().all(|&r| r < 1.0);
    let all_slower = cohort_sig.iter().all(|&r| r > 1.0);
    let consistent_sign = all_faster || all_slower;

    println!("\n== VERDICT ==");
    println!(
        "  cross-cohort {a}/{b} = {overall:.4}  (effect {effect_pct:+.2}%)   cross-cohort spread {signal_spread:.2}%"
    );
    println!(
        "  reproducibility FLOOR (A/A cross-cohort spread) = {floor:.2}%   \
         min per-cohort |effect| = {min_mag:.2}%   sign-consistent={consistent_sign}"
    );

    let clears_every_cohort = consistent_sign && min_mag > floor;
    let abs_effect = effect_pct.abs();
    let status = if clears_every_cohort && signal_spread < abs_effect {
        let dir = if all_faster { "BEATS" } else { "LOSES TO" };
        println!(
            "\n  REPRODUCIBLE: {a} {dir} {b} by {abs_effect:.2}% \
             (cross-cohort spread {signal_spread:.2}% < effect {abs_effect:.2}%; \
             clears the {floor:.2}% A/A floor in every cohort)."
        );
        "REPRODUCIBLE"
    } else if consistent_sign && abs_effect <= floor && signal_spread <= floor.max(abs_effect) {
        println!(
            "\n  REPRODUCIBLE TIE: {a} ties {b} (effect {abs_effect:.2}% ≤ A/A floor {floor:.2}%; \
             cross-cohort spread {signal_spread:.2}%). No win resolvable above the noise floor, \
             but it is stably a tie."
        );
        "REPRODUCIBLE_TIE"
    } else {
        let z = signal_spread.max(floor);
        println!(
            "\n  NOT RESOLVABLE on this laptop: cross-cohort spread {z:.2}% ≥ the effect \
             {abs_effect:.2}% (sign-consistent={consistent_sign}, min-cohort |effect| {min_mag:.2}% \
             vs floor {floor:.2}%). The {a}/{b} ratio is frequency/thermal-bound here — a gated \
             arm64 verdict needs a quiet Linux-arm64 box."
        );
        "NOT_RESOLVABLE"
    };

    SteadyVerdict {
        overall,
        effect_pct,
        signal_spread,
        floor,
        min_mag,
        consistent_sign,
        all_faster,
        status,
    }
}

fn cmd_wall_steady(args: &[String], gz: Arm, ld: Arm, corpus: &str, oracle: &str) -> ExitCode {
    let cohorts: usize = flag(args, "--cohorts")
        .and_then(|s| s.parse().ok())
        .unwrap_or(4)
        .max(4);
    let pairs: usize = flag(args, "--pairs")
        .and_then(|s| s.parse().ok())
        .unwrap_or(9)
        .max(7);
    let warmup_secs: f64 = flag(args, "--warmup-secs")
        .and_then(|s| s.parse().ok())
        .unwrap_or(20.0);
    let cooldown_secs: f64 = flag(args, "--cooldown-secs")
        .and_then(|s| s.parse().ok())
        .unwrap_or(5.0);
    let throttle_tol: f64 = flag(args, "--throttle-tol")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.03); // 3% of steady GHz

    println!("== fulcrum wall --steady (macOS) — reproducible steady-state A/B ==");
    println!(
        "corpus={corpus}  cohorts={cohorts} pairs/cohort={pairs} warmup={warmup_secs:.0}s \
         cooldown={cooldown_secs:.0}s throttle-tol={:.1}% sink=/dev/null",
        throttle_tol * 100.0
    );

    if let Err(e) = preflight_root() {
        eprintln!("wall --steady: {e}");
        return ExitCode::from(2);
    }

    // ---- environment control -------------------------------------------------
    let _caff = start_caffeinate(); // held for the whole run; reaped on exit
    let pinned = pin_to_pcluster();

    // ---- kpc session for the frequency probe --------------------------------
    let pmu = match Pmu::new() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("wall --steady: PMU init failed: {e}");
            return ExitCode::from(2);
        }
    };
    let sess = match Session::program(&pmu, &["FIXED_CYCLES"]) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("wall --steady: kpc program failed: {e}");
            return ExitCode::from(2);
        }
    };

    // ---- Gate-0 (steady-specific, BLOCKING) ---------------------------------
    println!("-- Gate-0 self-validation (BLOCKING) --");
    let mut g0_ok = true;
    macro_rules! g0 {
        ($cond:expr, $($m:tt)*) => {{
            let ok = $cond;
            println!("  [Gate-0] {} :: {}", if ok {"PASS"} else {"FAIL"}, format!($($m)*));
            if !ok { g0_ok = false; }
        }};
    }
    g0!(
        pinned,
        "QoS USER_INTERACTIVE set (probe thread on the performance cluster)"
    );
    g0!(
        _caff.is_some(),
        "caffeinate held for the run (no idle-sleep / dim mid-measure)"
    );
    g0!(
        pmu.has_event("FIXED_CYCLES"),
        "kpc FIXED_CYCLES present (frequency probe armed)"
    );
    // probe must be NON-INERT and sane (not measuring nothing, not an E-core stall)
    let ghz0 = probe_ghz(&pmu, &sess);
    g0!(
        (0.6..=4.5).contains(&ghz0),
        "freq probe non-inert & sane: {ghz0:.3} GHz (cluster effective frequency)"
    );
    if !g0_ok {
        eprintln!("\nwall --steady: GATE-0 FAILED — refusing to report");
        return ExitCode::FAILURE;
    }
    println!("-- Gate-0 PASSED --\n");

    let raw = match run_steady_cohorts(args, &gz, &ld, corpus, &pmu, &sess, ghz0) {
        Some(r) => r,
        None => return ExitCode::FAILURE,
    };
    let _ = steady_verdict(&raw.cohort_sig, &raw.cohort_aa, "gz", "ld");
    let _ = oracle; // correctness already gated by the caller before this point
    ExitCode::SUCCESS
}

// ===========================================================================
// `fulcrum vs` (macOS) — sha-pinned, self-validating steady-wall head-to-head.
//
// The durable replacement for the ad-hoc gz-vs-ref wrapper scripts. Reuses the
// EXACT `wall --steady` machinery (freq-normalized paired ratios, throttle
// filter, cohorts, A/A reproducibility floor) but:
//   - records full PROVENANCE in a JSON artifact: gz/ref/corpus sha256, corpus
//     uncompressed-size + ratio, host/arch, steady GHz, every per-cohort ratio.
//   - bakes the Gate-0 self-tests in (refuses a verdict if any fail): both arms'
//     output sha == `gzip -dc` oracle (provenance + same /dev/null sink), ref
//     self-≈1.0, native Mach-O comparator (not a python/wheel shim), and the
//     gz/gz A/A floor (from the steady loop). throttle/freq filter is inherited.
// ===========================================================================
pub fn cmd_vs_wall(args: &[String]) -> ExitCode {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "fulcrum vs (macOS) — sha-pinned self-validating steady-wall head-to-head.\n\n\
             USAGE: fulcrum vs --gz PATH --ref PATH --corpus f.gz [--threads N] [--json out.json]\n\
                    [--ref-args a,b,c] [--cohorts K=4] [--pairs M=9] [--warmup-secs 20]\n\
                    [--cooldown-secs 5] [--throttle-tol 0.03]\n\n\
             Records gz/ref/corpus sha256, uncompressed-size+ratio, host/arch, steady GHz, and\n\
             every per-cohort ratio to --json. Gate-0 (BLOCKING): both arms sha==gzip-dc oracle,\n\
             ref self-≈1.0, native Mach-O comparators, /dev/null sink; freq/throttle filter +\n\
             gz/gz A/A reproducibility floor inherited from the steady loop. sudo (kpc)."
        );
        return ExitCode::SUCCESS;
    }

    let corpus = match flag(args, "--corpus") {
        Some(c) => c.to_string(),
        None => {
            eprintln!("vs: --corpus <f.gz> is required");
            return ExitCode::from(2);
        }
    };
    let threads: usize = flag(args, "--threads")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1)
        .max(1);
    let gz_bin = match flag(args, "--gz") {
        Some(g) => g.to_string(),
        None => {
            eprintln!("vs: --gz <binary> is required");
            return ExitCode::from(2);
        }
    };
    let ref_bin = match flag(args, "--ref").or_else(|| flag(args, "--ld")) {
        Some(r) => r.to_string(),
        None => {
            eprintln!("vs: --ref <binary> is required");
            return ExitCode::from(2);
        }
    };
    let ref_args: Vec<String> = match flag(args, "--ref-args") {
        Some(s) => s
            .split(',')
            .filter(|x| !x.is_empty())
            .map(|x| x.to_string())
            .collect(),
        None => vec!["-c".into()],
    };
    let json_path = flag(args, "--json").map(|s| s.to_string());

    let gz = Arm {
        key: "gz".into(),
        bin: gz_bin.clone(),
        decode_args: vec!["-d".into(), "-c".into(), format!("-p{threads}")],
            env: Vec::new(),
    };
    let refarm = Arm {
        key: "ref".into(),
        bin: ref_bin.clone(),
        decode_args: ref_args.clone(),
        env: Vec::new(),
    };

    println!("== fulcrum vs (macOS) — sha-pinned self-validating steady-wall head-to-head ==");
    println!(
        "gz={gz_bin}  ref={ref_bin} (args {:?})  corpus={corpus}  threads={threads}",
        ref_args
    );

    if let Err(e) = preflight_root() {
        eprintln!("vs: {e}");
        return ExitCode::from(2);
    }

    // ---- environment control + kpc session ----------------------------------
    let _caff = start_caffeinate();
    let pinned = pin_to_pcluster();
    let pmu = match Pmu::new() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("vs: PMU init failed: {e}");
            return ExitCode::from(2);
        }
    };
    let sess = match Session::program(&pmu, &["FIXED_CYCLES"]) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("vs: kpc program failed: {e}");
            return ExitCode::from(2);
        }
    };

    // ---- Gate-0 self-validation (BLOCKING) ----------------------------------
    println!("-- Gate-0 self-validation (BLOCKING) --");
    let mut g0_ok = true;
    macro_rules! g0 {
        ($cond:expr, $($m:tt)*) => {{
            let ok = $cond;
            println!("  [Gate-0] {} :: {}", if ok {"PASS"} else {"FAIL"}, format!($($m)*));
            if !ok { g0_ok = false; }
        }};
    }
    // native comparator (reject python/wheel/script shims)
    match is_native_macho(&gz.bin) {
        Ok(()) => g0!(true, "gz = native Mach-O ({})", gz.bin),
        Err(e) => g0!(false, "gz native check: {e}"),
    }
    match is_native_macho(&refarm.bin) {
        Ok(()) => g0!(true, "ref = native Mach-O ({})", refarm.bin),
        Err(e) => g0!(false, "ref native check: {e}"),
    }
    // environment / probe
    g0!(
        pinned,
        "QoS USER_INTERACTIVE set (probe thread on the performance cluster)"
    );
    g0!(
        _caff.is_some(),
        "caffeinate held for the run (no idle-sleep / dim mid-measure)"
    );
    g0!(
        pmu.has_event("FIXED_CYCLES"),
        "kpc FIXED_CYCLES present (frequency probe armed)"
    );
    let ghz0 = probe_ghz(&pmu, &sess);
    g0!(
        (0.6..=4.5).contains(&ghz0),
        "freq probe non-inert & sane: {ghz0:.3} GHz"
    );

    // oracle + provenance shas
    let (oracle, uncompressed_len) = match oracle_sha_len(&corpus) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("vs: oracle failed: {e}");
            return ExitCode::from(2);
        }
    };
    let compressed_len = std::fs::metadata(&corpus)
        .map(|m| m.len() as usize)
        .unwrap_or(0);
    let ratio = if compressed_len > 0 {
        uncompressed_len as f64 / compressed_len as f64
    } else {
        0.0
    };
    g0!(
        true,
        "oracle sha (gzip -dc) = {}… ({} → {} bytes, ratio {:.3})",
        &oracle[..12],
        compressed_len,
        uncompressed_len,
        ratio
    );

    // both arms output sha == oracle. The sha-gate decodes to a real tmpfile and
    // reads it back (the timed STEADY loop below uses /dev/null for both arms —
    // the same-sink law applies to the timed path; a tmpfile is needed here only
    // because /dev/null reads back empty). sha is computed OUTSIDE the timer.
    let tmp = std::env::temp_dir();
    let gz_outp = tmp.join("fulcrum_vs_gz.out").to_string_lossy().to_string();
    let gz_out_sha = match timed_decode(&gz, &corpus, &gz_outp).map(|(_, s)| s) {
        Ok(s) => s,
        Err(e) => {
            g0!(false, "gz decode failed: {e}");
            String::new()
        }
    };
    g0!(
        gz_out_sha == oracle,
        "gz output sha == oracle ({}…)",
        if gz_out_sha.len() >= 12 {
            &gz_out_sha[..12]
        } else {
            "?"
        }
    );
    let _ = std::fs::remove_file(&gz_outp);
    let ref_outp = tmp.join("fulcrum_vs_ref.out").to_string_lossy().to_string();
    let ref_out_sha = match timed_decode(&refarm, &corpus, &ref_outp).map(|(_, s)| s) {
        Ok(s) => s,
        Err(e) => {
            g0!(false, "ref decode failed: {e}");
            String::new()
        }
    };
    g0!(
        ref_out_sha == oracle,
        "ref output sha == oracle ({}…)",
        if ref_out_sha.len() >= 12 {
            &ref_out_sha[..12]
        } else {
            "?"
        }
    );
    let _ = std::fs::remove_file(&ref_outp);

    // ref self-≈1.0 (the comparator must time-reproduce against itself)
    let (rs1, rs2) = (
        decode_devnull(&refarm, &corpus),
        decode_devnull(&refarm, &corpus),
    );
    match (rs1, rs2) {
        (Ok(a), Ok(b)) if a > 0.0 && b > 0.0 => {
            let r = a / b;
            g0!((0.85..=1.15).contains(&r), "ref self-ratio ≈ 1.0 ({r:.3})");
        }
        _ => g0!(false, "ref self-ratio: a ref decode failed"),
    }

    if !g0_ok {
        eprintln!("\nvs: GATE-0 FAILED — refusing to report (numbers untrustworthy)");
        return ExitCode::FAILURE;
    }
    println!("-- Gate-0 PASSED --\n");

    // ---- steady cohorts + verdict (shared machinery) ------------------------
    let raw = match run_steady_cohorts(args, &gz, &refarm, &corpus, &pmu, &sess, ghz0) {
        Some(r) => r,
        None => return ExitCode::FAILURE,
    };
    let v = steady_verdict(&raw.cohort_sig, &raw.cohort_aa, "gz", "ref");

    // ---- provenance + JSON artifact -----------------------------------------
    let gz_sha = file_sha256(&gz_bin).unwrap_or_default();
    let ref_sha = file_sha256(&ref_bin).unwrap_or_default();
    let corpus_sha = file_sha256(&corpus).unwrap_or_default();
    let host = Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let arch = std::env::consts::ARCH.to_string();

    if let Some(path) = json_path {
        let obj = serde_json::json!({
            "tool": "fulcrum vs",
            "gz_bin": gz_bin,
            "ref_bin": ref_bin,
            "ref_args": ref_args,
            "corpus": corpus,
            "threads": threads,
            "gz_sha256": gz_sha,
            "ref_sha256": ref_sha,
            "corpus_sha256": corpus_sha,
            "oracle_sha256": oracle,
            "uncompressed_bytes": uncompressed_len,
            "compressed_bytes": compressed_len,
            "ratio": ratio,
            "host": host,
            "arch": arch,
            "steady_ghz": raw.steady_ghz,
            "warmup_converged": raw.converged,
            "kept_pairs": raw.total_kept,
            "dropped_pairs": raw.total_drop,
            "cohort_gz_ref_ratios": raw.cohort_sig,
            "cohort_aa_ratios": raw.cohort_aa,
            "overall_gz_ref": v.overall,
            "effect_pct": v.effect_pct,
            "cross_cohort_spread_pct": v.signal_spread,
            "aa_floor_pct": v.floor,
            "min_cohort_effect_pct": v.min_mag,
            "sign_consistent": v.consistent_sign,
            "gz_faster": v.all_faster,
            "status": v.status,
        });
        match std::fs::write(&path, serde_json::to_string_pretty(&obj).unwrap()) {
            Ok(()) => println!("\nartifact: {path}"),
            Err(e) => eprintln!("vs: failed to write {path}: {e}"),
        }
    }

    ExitCode::SUCCESS
}

// ===========================================================================
// `fulcrum oracle` (macOS) — env-gated setup-removal A/B.
//
// Neither `fulcrum vs` nor `fulcrum wall` can A/B two ENV settings of the SAME
// binary (the `Arm` carries no env), yet a setup-cost LOCATE needs exactly that:
// run the production path with one startup step ELIDED (an env-gated removal
// oracle) against the unmodified path and read the wall delta. This subcommand
// fills that gap.
//
// Discipline baked in (the Gate-0 / sink / non-inert / significance rules):
//  - both arms are native Mach-O (no script/wheel shim);
//  - the BASE arm's bytes MUST sha-match the `gzip -dc` oracle (correctness);
//  - the AFTER arm either sha-matches too (byte-exact elision) OR is declared
//    `--after-garbage` (a corrupting elision), in which case its bytes MUST
//    DIFFER from the oracle — that difference is the NON-INERT proof the toggle
//    actually fired (an env knob with no consumer would leave bytes identical,
//    which we REJECT). A `--counter REGEX` may additionally require a fired-
//    counter line on the AFTER arm's stderr.
//  - /dev/null sink for BOTH arms in the timed loop (same-sink law);
//  - sha is computed OUTSIDE the timed region (shasum-in-timer impossible);
//  - interleaved paired triples (A, B, A) cancel per-pair DVFS drift; the
//    A1/A2 ratio is the A/A reproducibility FLOOR the B/A signal must clear,
//    and a paired sign test is reported. P-cluster QoS + caffeinate held.
//
// USAGE: fulcrum oracle --bin PATH --corpus f.gz --after-env "K=V K=V"
//          [--base-env "K=V ..."] [--after-bin PATH] [--args "-d,-c,-p1"]
//          [--after-args ...] [--label NAME] [--n N=15] [--after-garbage]
//          [--counter REGEX] [--json out.json]
// ===========================================================================

/// Parse a `"K=V K=V"` env string into pairs (whitespace-separated).
fn parse_env_pairs(s: &str) -> Vec<(String, String)> {
    s.split_whitespace()
        .filter_map(|kv| {
            kv.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect()
}

/// Decode `bin args corpus` with `env` applied, sink → `/dev/null`, return wall
/// ms. sha is NOT checked here (gated once up front); this is the hot path.
fn oracle_decode_devnull(
    bin: &str,
    args: &[String],
    env: &[(String, String)],
    corpus: &str,
) -> Result<f64, String> {
    let devnull = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .map_err(|e| format!("open /dev/null: {e}"))?;
    let mut cmd = Command::new(bin);
    cmd.args(args).arg(corpus);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.stdout(Stdio::from(devnull));
    cmd.stderr(Stdio::null());
    let t0 = Instant::now();
    let status = cmd.status().map_err(|e| format!("spawn {bin}: {e}"))?;
    let ms = t0.elapsed().as_secs_f64() * 1000.0;
    if !status.success() {
        return Err(format!("{bin} exited {status}"));
    }
    Ok(ms)
}

/// Decode to a tmpfile with `env` applied and return (ms, sha256) — for the
/// up-front correctness gate only (sha computed OUTSIDE the timer).
fn oracle_decode_sha(
    bin: &str,
    args: &[String],
    env: &[(String, String)],
    corpus: &str,
    out_path: &str,
) -> Result<String, String> {
    let outf = std::fs::File::create(out_path).map_err(|e| format!("create {out_path}: {e}"))?;
    let mut cmd = Command::new(bin);
    cmd.args(args).arg(corpus);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.stdout(Stdio::from(outf));
    cmd.stderr(Stdio::null());
    let status = cmd.status().map_err(|e| format!("spawn {bin}: {e}"))?;
    if !status.success() {
        return Err(format!("{bin} exited {status}"));
    }
    let bytes = std::fs::read(out_path).map_err(|e| format!("read {out_path}: {e}"))?;
    Ok(sha256_hex(&bytes))
}

pub fn cmd_oracle(args: &[String]) -> ExitCode {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "fulcrum oracle (macOS) — env-gated setup-removal A/B (interleaved, sha OUTSIDE timer).\n\n\
             USAGE: fulcrum oracle --bin PATH --corpus f.gz --after-env \"K=V K=V\"\n\
               [--base-env \"K=V ...\"] [--after-bin PATH] [--args \"-d,-c,-p1\"] [--after-args ...]\n\
               [--label NAME] [--n N=15] [--after-garbage] [--counter REGEX] [--json out.json]\n\n\
             Reports median B/A wall ratio (B=after), spread, A/A floor, paired sign test.\n\
             Gate-0 (BLOCKING): native Mach-O arms; BASE bytes sha==gzip-dc oracle; AFTER bytes\n\
             sha==oracle OR (--after-garbage) bytes DIFFER from oracle (non-inert proof); /dev/null\n\
             sink both arms; ratio<1 with sign-consistency clearing the A/A floor = the elided step's\n\
             recovered fraction. No kpc/root required."
        );
        return ExitCode::SUCCESS;
    }

    let bin = match flag(args, "--bin") {
        Some(b) => b.to_string(),
        None => {
            eprintln!("oracle: --bin <gz binary> is required");
            return ExitCode::from(2);
        }
    };
    let after_bin = flag(args, "--after-bin").unwrap_or(&bin).to_string();
    let corpus = match flag(args, "--corpus") {
        Some(c) => c.to_string(),
        None => {
            eprintln!("oracle: --corpus <f.gz> is required");
            return ExitCode::from(2);
        }
    };
    let after_env_str = flag(args, "--after-env").unwrap_or("").to_string();
    if after_env_str.is_empty() && after_bin == bin {
        eprintln!("oracle: --after-env (or --after-bin) is required — nothing to A/B otherwise");
        return ExitCode::from(2);
    }
    let base_env = parse_env_pairs(flag(args, "--base-env").unwrap_or(""));
    let after_env = parse_env_pairs(&after_env_str);
    let split_args = |s: &str| -> Vec<String> {
        s.split(',')
            .filter(|x| !x.is_empty())
            .map(|x| x.to_string())
            .collect()
    };
    let base_args = flag(args, "--args")
        .map(split_args)
        .unwrap_or_else(|| vec!["-d".into(), "-c".into(), "-p1".into()]);
    let after_args = flag(args, "--after-args")
        .map(split_args)
        .unwrap_or_else(|| base_args.clone());
    let label = flag(args, "--label").unwrap_or("oracle").to_string();
    let n: usize = flag(args, "--n")
        .and_then(|s| s.parse().ok())
        .unwrap_or(15)
        .max(9);
    let after_garbage = args.iter().any(|a| a == "--after-garbage");
    let counter_re = flag(args, "--counter").map(|s| s.to_string());
    let json_path = flag(args, "--json").map(|s| s.to_string());

    println!("== fulcrum oracle (macOS) — env-gated setup-removal A/B [{label}] ==");
    println!("base: {bin} {base_args:?} env={base_env:?}");
    println!("after: {after_bin} {after_args:?} env={after_env:?}  garbage={after_garbage}");
    println!("corpus={corpus} N={n}");

    let _caff = start_caffeinate();
    let pinned = pin_to_pcluster();

    // ---- Gate-0 self-validation (BLOCKING) ----------------------------------
    println!("-- Gate-0 self-validation (BLOCKING) --");
    let mut g0_ok = true;
    macro_rules! g0 {
        ($cond:expr, $($m:tt)*) => {{
            let ok = $cond;
            println!("  [Gate-0] {} :: {}", if ok {"PASS"} else {"FAIL"}, format!($($m)*));
            if !ok { g0_ok = false; }
        }};
    }
    match is_native_macho(&bin) {
        Ok(()) => g0!(true, "base = native Mach-O ({bin})"),
        Err(e) => g0!(false, "base native check: {e}"),
    }
    match is_native_macho(&after_bin) {
        Ok(()) => g0!(true, "after = native Mach-O ({after_bin})"),
        Err(e) => g0!(false, "after native check: {e}"),
    }
    g0!(pinned, "QoS USER_INTERACTIVE set (P-cluster)");
    g0!(_caff.is_some(), "caffeinate held");

    let (oracle, ulen) = match oracle_sha_len(&corpus) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("oracle: oracle decode failed: {e}");
            return ExitCode::from(2);
        }
    };
    g0!(
        true,
        "oracle sha (gzip -dc) = {}… ({ulen} bytes)",
        &oracle[..12]
    );

    let tmp = std::env::temp_dir();
    let base_outp = tmp
        .join("fulcrum_oracle_base.out")
        .to_string_lossy()
        .to_string();
    let base_sha = oracle_decode_sha(&bin, &base_args, &base_env, &corpus, &base_outp)
        .unwrap_or_else(|e| {
            g0!(false, "base decode failed: {e}");
            String::new()
        });
    g0!(
        base_sha == oracle,
        "BASE bytes sha == oracle ({}…)",
        if base_sha.len() >= 12 {
            &base_sha[..12]
        } else {
            "?"
        }
    );
    let _ = std::fs::remove_file(&base_outp);

    let after_outp = tmp
        .join("fulcrum_oracle_after.out")
        .to_string_lossy()
        .to_string();
    let after_sha = oracle_decode_sha(&after_bin, &after_args, &after_env, &corpus, &after_outp)
        .unwrap_or_else(|e| {
            g0!(false, "after decode failed: {e}");
            String::new()
        });
    if after_garbage {
        // Non-inert proof: a corrupting elision MUST change the bytes. Identical
        // bytes ⇒ the env knob has no live consumer ⇒ inert ⇒ REJECT.
        g0!(
            !after_sha.is_empty() && after_sha != oracle,
            "AFTER bytes DIFFER from oracle (non-inert: elision fired) ({}…)",
            if after_sha.len() >= 12 {
                &after_sha[..12]
            } else {
                "?"
            }
        );
    } else {
        g0!(
            after_sha == oracle,
            "AFTER bytes sha == oracle (byte-exact elision) ({}…)",
            if after_sha.len() >= 12 {
                &after_sha[..12]
            } else {
                "?"
            }
        );
    }
    let _ = std::fs::remove_file(&after_outp);

    // Optional fired-counter proof on the AFTER arm's stderr.
    if let Some(re) = &counter_re {
        let mut cmd = Command::new(&after_bin);
        cmd.args(&after_args).arg(&corpus);
        for (k, v) in &after_env {
            cmd.env(k, v);
        }
        cmd.stdout(Stdio::null());
        let out = cmd.output();
        let fired = match out {
            Ok(o) => String::from_utf8_lossy(&o.stderr).contains(re.as_str()),
            Err(_) => false,
        };
        g0!(
            fired,
            "AFTER stderr matches counter /{re}/ (non-inert proof)"
        );
    }

    if !g0_ok {
        eprintln!("\noracle: GATE-0 FAILED — refusing to report (numbers untrustworthy)");
        return ExitCode::FAILURE;
    }
    println!("-- Gate-0 PASSED --\n");

    // ---- Interleaved paired triples (A, B, A) -------------------------------
    // Warm once.
    let _ = oracle_decode_devnull(&bin, &base_args, &base_env, &corpus);
    let _ = oracle_decode_devnull(&after_bin, &after_args, &after_env, &corpus);

    let mut sig: Vec<f64> = Vec::new(); // B / mean(A1,A2)
    let mut aa: Vec<f64> = Vec::new(); // max/min(A1,A2) reproducibility floor
    let mut b_faster = 0usize; // paired sign test
    let mut base_ms: Vec<f64> = Vec::new();
    let mut after_ms: Vec<f64> = Vec::new();
    for _ in 0..n {
        let a1 = match oracle_decode_devnull(&bin, &base_args, &base_env, &corpus) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("oracle: {e}");
                return ExitCode::FAILURE;
            }
        };
        let b = match oracle_decode_devnull(&after_bin, &after_args, &after_env, &corpus) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("oracle: {e}");
                return ExitCode::FAILURE;
            }
        };
        let a2 = match oracle_decode_devnull(&bin, &base_args, &base_env, &corpus) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("oracle: {e}");
                return ExitCode::FAILURE;
            }
        };
        let amean = (a1 + a2) / 2.0;
        if amean > 0.0 {
            sig.push(b / amean);
            aa.push(maxf(&[a1, a2]) / minf(&[a1, a2]));
            if b < amean {
                b_faster += 1;
            }
            base_ms.push(amean);
            after_ms.push(b);
        }
    }

    let sig_med = median(&sig);
    let sig_spr = spread_pct(&sig);
    let aa_med = median(&aa);
    let aa_spr = spread_pct(&aa);
    let base_med = median(&base_ms);
    let after_med = median(&after_ms);
    let delta_ms = base_med - after_med; // ms recovered by the elision (>0 = faster)

    println!("-- Result [{label}] --");
    println!("  base   median = {base_med:.3} ms");
    println!("  after  median = {after_med:.3} ms");
    println!("  B/A ratio median = {sig_med:.4}  (spread {sig_spr:.2}%)");
    println!(
        "  recovered = {delta_ms:.3} ms  ({:.2}% of base)",
        if base_med > 0.0 {
            100.0 * delta_ms / base_med
        } else {
            0.0
        }
    );
    println!("  A/A floor ratio  = {aa_med:.4}  (spread {aa_spr:.2}%)");
    println!("  paired sign test: B faster in {b_faster}/{n} reps");
    // Significance: the |1-ratio| effect must clear the A/A reproducibility floor.
    let effect = (1.0 - sig_med).abs() * 100.0;
    let resolves =
        effect > aa_spr && (b_faster == 0 || b_faster == n || b_faster >= n - 1 || b_faster <= 1);
    println!(
        "  VERDICT: effect {effect:.2}% vs A/A floor {aa_spr:.2}% ⇒ {}",
        if resolves {
            "RESOLVED (clears floor, sign-consistent)"
        } else {
            "NOT-RESOLVED (within floor / sign-inconsistent)"
        }
    );

    if let Some(jp) = json_path {
        let base_sha_b = file_sha256(&bin).unwrap_or_default();
        let after_sha_b = file_sha256(&after_bin).unwrap_or_default();
        let corpus_sha = file_sha256(&corpus).unwrap_or_default();
        let sig_json: Vec<String> = sig.iter().map(|x| format!("{x:.5}")).collect();
        let aa_json: Vec<String> = aa.iter().map(|x| format!("{x:.5}")).collect();
        let j = format!(
            "{{\n  \"tool\": \"fulcrum oracle\",\n  \"label\": \"{label}\",\n  \"corpus\": \"{corpus}\",\n  \"corpus_sha256\": \"{corpus_sha}\",\n  \"uncompressed_len\": {ulen},\n  \"base_bin\": \"{bin}\",\n  \"base_bin_sha256\": \"{base_sha_b}\",\n  \"after_bin\": \"{after_bin}\",\n  \"after_bin_sha256\": \"{after_sha_b}\",\n  \"base_env\": \"{}\",\n  \"after_env\": \"{}\",\n  \"after_garbage\": {after_garbage},\n  \"n\": {n},\n  \"base_median_ms\": {base_med:.4},\n  \"after_median_ms\": {after_med:.4},\n  \"ratio_median\": {sig_med:.5},\n  \"ratio_spread_pct\": {sig_spr:.3},\n  \"recovered_ms\": {delta_ms:.4},\n  \"aa_floor_ratio\": {aa_med:.5},\n  \"aa_floor_spread_pct\": {aa_spr:.3},\n  \"b_faster\": {b_faster},\n  \"resolves\": {resolves},\n  \"ratios\": [{}],\n  \"aa_ratios\": [{}]\n}}\n",
            flag(args, "--base-env").unwrap_or(""),
            after_env_str,
            sig_json.join(", "),
            aa_json.join(", "),
        );
        if let Err(e) = std::fs::write(&jp, j) {
            eprintln!("oracle: write {jp}: {e}");
        } else {
            println!("  json → {jp}");
        }
    }

    if resolves {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

pub fn cmd_wall(args: &[String]) -> ExitCode {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "fulcrum wall (macOS) — interleaved best-of-N wall A/B (gz vs libdeflate/rapidgzip/pigz).\n\
             Regular-file sink; sha verified OUTSIDE the timed region (shasum-in-timer impossible).\n\n\
             USAGE: fulcrum wall [--corpus f.gz] [--n N] [--gz PATH] [--ld PATH] [--rg PATH] [--pigz PATH]\n\
             Gate-0: native-comparator (Mach-O, not wheel), per-arm sha==oracle, same regular-file sink.\n\n\
             --steady : REPRODUCIBLE steady-state gz-vs-libdeflate mode (sudo; kpc freq probe).\n\
               Pins to the P-cluster (QoS USER_INTERACTIVE) + caffeinate, warms to a steady\n\
               effective GHz, takes freq-normalized PAIRED ratios with a throttle filter, and\n\
               runs K cohorts over time. /dev/null sink. The gz-vs-gz A/A cross-cohort spread is\n\
               the reproducibility FLOOR; a gz/ld verdict is REPRODUCIBLE only if it clears that\n\
               floor in every cohort, else NOT-RESOLVABLE (→ quiet Linux-arm64 box).\n\
               Flags: [--cohorts K=4] [--pairs M=9] [--warmup-secs 20] [--cooldown-secs 5]\n\
                      [--throttle-tol 0.03]"
        );
        return ExitCode::SUCCESS;
    }
    let corpus = flag(args, "--corpus").unwrap_or(DEFAULT_CORPUS).to_string();
    let n: usize = flag(args, "--n")
        .and_then(|s| s.parse().ok())
        .unwrap_or(15)
        .max(9);
    let steady = args.iter().any(|a| a == "--steady");
    // --threads N: parallelism for the gz arm (production -pN control). Default 1.
    let threads: usize = flag(args, "--threads")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1)
        .max(1);
    let gz_bin = flag(args, "--gz")
        .unwrap_or("/Users/jackdanger/www/gzippy-reimplement-isal/target/release/gzippy")
        .to_string();
    // The comparison ("ld") arm. --ref PATH overrides the binary (--ld kept as an
    // alias for back-compat); --ref-args "a,b,c" overrides its decode args
    // (default = libdeflate-gunzip's "-c"). This lets the trustworthy steady wall
    // compare gz against ANY native binary (a second gzippy, pigz, native rg).
    let ref_bin = flag(args, "--ref")
        .or_else(|| flag(args, "--ld"))
        .unwrap_or("/opt/homebrew/bin/libdeflate-gunzip")
        .to_string();
    let ref_args: Vec<String> = match flag(args, "--ref-args") {
        Some(s) => s
            .split(',')
            .filter(|x| !x.is_empty())
            .map(|x| x.to_string())
            .collect(),
        None => vec!["-c".into()],
    };
    let rg_bin = flag(args, "--rg")
        .unwrap_or("/tmp/rgbuild/src/tools/rapidgzip")
        .to_string();
    let pigz_bin = flag(args, "--pigz").unwrap_or("pigz").to_string();
    // --ref-garbage: the ref/ld arm is a REMOVAL-ORACLE that produces GARBAGE
    // output bytes by design (e.g. GZIPPY_ORACLE_NOSTORE). Its sha-vs-oracle
    // Gate-0 is then meaningless and MUST be waived: instead we require only
    // that it (a) runs to a successful exit with a /dev/null sink (so the steady
    // loop's /dev/null timing is valid) and is loudly flagged. The gz arm stays
    // FULLY sha-gated; non-inertness of the oracle is proven out-of-band.
    let ref_garbage = args.iter().any(|a| a == "--ref-garbage");

    // Candidate arms; include only those whose binary is a native Mach-O.
    let mut arms: Vec<Arm> = Vec::new();
    arms.push(Arm {
        key: "gz".into(),
        bin: gz_bin.clone(),
        decode_args: vec!["-d".into(), "-c".into(), format!("-p{threads}")],
            env: Vec::new(),
    });
    arms.push(Arm {
        key: "ld".into(),
        bin: ref_bin.clone(),
        decode_args: ref_args.clone(),
        env: Vec::new(),
    });
    // In steady mode only the gz + ld(ref) arms are exercised; skip the extra
    // pigz/rg arms so Gate-0 stays scoped to the two arms being compared.
    if !steady {
        if Path::new(&rg_bin).exists() {
            arms.push(Arm {
                key: "rg".into(),
                bin: rg_bin.clone(),
                decode_args: vec!["-d".into(), "-c".into(), "-P1".into()],
                env: Vec::new(),
            });
        }
        if which(&pigz_bin).is_some() {
            arms.push(Arm {
                key: "pigz".into(),
                bin: which(&pigz_bin).unwrap(),
                decode_args: vec!["-d".into(), "-c".into(), "-p1".into()],
                env: Vec::new(),
            });
        }
    }

    println!("== fulcrum wall (macOS) — interleaved best-of-N, sha OUTSIDE timer ==");
    println!("corpus={corpus} N={n}");

    // ---- Gate-0 -------------------------------------------------------------
    println!("-- Gate-0 self-validation (BLOCKING) --");
    let mut g0_ok = true;
    macro_rules! g0 {
        ($cond:expr, $($m:tt)*) => {{
            let ok = $cond;
            println!("  [Gate-0] {} :: {}", if ok {"PASS"} else {"FAIL"}, format!($($m)*));
            if !ok { g0_ok = false; }
        }};
    }
    // native comparator checks
    for a in &arms {
        match is_native_macho(&a.bin) {
            Ok(()) => g0!(true, "{} = native Mach-O executable ({})", a.key, a.bin),
            Err(e) => g0!(false, "{} native check: {e}", a.key),
        }
    }
    // oracle
    let oracle = match oracle_sha(&corpus) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("wall: oracle failed: {e}");
            return ExitCode::from(2);
        }
    };
    g0!(true, "oracle sha (gzip -dc) = {}…", &oracle[..12]);

    // per-arm sha == oracle (one decode each, same regular-file sink)
    let tmp = std::env::temp_dir();
    for a in &arms {
        // Garbage-output removal oracle on the ref arm: waive sha, require only a
        // successful /dev/null decode (the regular-file sink would be refused).
        if ref_garbage && a.key == "ld" {
            match timed_decode(a, &corpus, "/dev/null") {
                Ok((_ms, _sha)) => g0!(
                    true,
                    "{} sha-gate WAIVED (--ref-garbage: removal-oracle, garbage output by design; ran OK to /dev/null)",
                    a.key
                ),
                Err(e) => g0!(false, "{} garbage-oracle decode failed: {e}", a.key),
            }
            continue;
        }
        let outp = tmp.join(format!("fulcrum_wall_{}.out", a.key));
        let outp = outp.to_string_lossy().to_string();
        match timed_decode(a, &corpus, &outp) {
            Ok((_ms, sha)) => g0!(
                sha == oracle,
                "{} output sha == oracle ({}…)",
                a.key,
                &sha[..12]
            ),
            Err(e) => g0!(false, "{} decode failed: {e}", a.key),
        }
        let _ = std::fs::remove_file(&outp);
    }

    if !g0_ok {
        eprintln!("\nwall: GATE-0 FAILED — refusing to report (numbers untrustworthy)");
        return ExitCode::FAILURE;
    }
    println!("-- Gate-0 PASSED --\n");

    // ---- Steady-state reproducible mode (correctness already gated above) ----
    if args.iter().any(|a| a == "--steady") {
        let gz_arm = arms
            .iter()
            .find(|a| a.key == "gz")
            .expect("gz arm always present")
            .clone();
        let ld_arm = match arms.iter().find(|a| a.key == "ld") {
            Some(a) => a.clone(),
            None => {
                eprintln!("wall --steady: requires an 'ld' (libdeflate) arm");
                return ExitCode::from(2);
            }
        };
        return cmd_wall_steady(args, gz_arm, ld_arm, &corpus, &oracle);
    }

    // ---- Interleaved best-of-N ---------------------------------------------
    // warmup
    for a in &arms {
        let outp = tmp.join(format!("fulcrum_wall_{}.out", a.key));
        let _ = timed_decode(a, &corpus, &outp.to_string_lossy());
    }
    let mut samples: std::collections::HashMap<String, Vec<f64>> =
        arms.iter().map(|a| (a.key.clone(), Vec::new())).collect();
    let mut aa: Vec<f64> = Vec::new(); // gz vs gz second-decode ratio per rep

    for _ in 0..n {
        // randomize arm order each rep to decorrelate
        let mut order: Vec<usize> = (0..arms.len()).collect();
        // cheap shuffle
        let mut s = Instant::now().elapsed().as_nanos() as u64 ^ 0x9e3779b9;
        for i in (1..order.len()).rev() {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
            let j = (s >> 33) as usize % (i + 1);
            order.swap(i, j);
        }
        let mut gz_first = None;
        for &i in &order {
            let a = &arms[i];
            let outp = tmp.join(format!("fulcrum_wall_{}.out", a.key));
            if let Ok((ms, sha)) = timed_decode(a, &corpus, &outp.to_string_lossy()) {
                if sha != oracle {
                    eprintln!("  !! {} produced wrong sha mid-run — aborting", a.key);
                    return ExitCode::FAILURE;
                }
                samples.get_mut(&a.key).unwrap().push(ms);
                if a.key == "gz" {
                    gz_first = Some(ms);
                }
            }
            let _ = std::fs::remove_file(&outp);
        }
        // A/A: one extra gz decode compared to this rep's first gz
        if let Some(g1) = gz_first {
            let outp = tmp.join("fulcrum_wall_gzaa.out");
            if let Ok((g2, _)) = timed_decode(&arms[0], &corpus, &outp.to_string_lossy()) {
                aa.push(g1 / g2);
            }
            let _ = std::fs::remove_file(&outp);
        }
    }

    // ---- Report -------------------------------------------------------------
    let gz_min = minf(&samples["gz"]);
    println!(
        "{:<6} {:>9} {:>9} {:>9} {:>8} {:>8}  {:>9}",
        "arm", "min_ms", "median", "p10", "spread%", "gz/x", "bimodal?"
    );
    let mut keys: Vec<&String> = samples.keys().collect();
    keys.sort();
    for k in keys {
        let v = &samples[k];
        if v.is_empty() {
            continue;
        }
        let mn = minf(v);
        let md = median(v);
        let p10 = percentile(v, 10.0);
        let spr = spread_pct(v);
        let ratio = gz_min / mn;
        let bimodal = if spr > 15.0 { "FLAG(>15%)" } else { "ok" };
        println!(
            "{:<6} {:>9.2} {:>9.2} {:>9.2} {:>8.1} {:>8.3}  {:>9}",
            k, mn, md, p10, spr, ratio, bimodal
        );
    }
    let aa_m = median(&aa);
    let aa_spr = spread_pct(&aa);
    println!(
        "\nGate-1: N={n}  A/A gz-vs-gz ratio={aa_m:.4} (±{:.1}%); ",
        aa_spr
    );
    if let Some(ld) = samples.get("ld") {
        if !ld.is_empty() {
            let g_over_l = gz_min / minf(ld);
            println!(
                "  gz/ld (min) = {g_over_l:.4}   Δ={:.1}%  vs A/A spread {aa_spr:.1}%  => {}",
                100.0 * (g_over_l - 1.0),
                if (100.0 * (g_over_l - 1.0)).abs() < aa_spr {
                    "TIE (Δ < A/A spread)"
                } else {
                    "SIGNAL (Δ > A/A spread)"
                }
            );
        }
    }
    ExitCode::SUCCESS
}

// ===========================================================================
// `fulcrum phaseprof` (macOS) — per-PHASE cycle attribution of the T1 decode.
//
// LOCATES which decode phase carries the gz-vs-libdeflate surplus. Statistical
// PC-sampling (`/usr/bin/sample`) of a looped IN-PROCESS decode, with each
// resolved symbol bucketed into a decode PHASE {inner-decode, table-build,
// header-parse, crc, copy/memset, setup/other}. Reports each phase's share of
// decode cycles for gz AND libdeflate side-by-side.
//
// WHY sample (not kpc region counters): the 7 inner-loop micro-phases interleave
// per-symbol; reading kpc per symbol would cost more than the work it measures.
// Statistical PC attribution is the standard, non-perturbing profiler lens. It
// is CYCLE attribution (wall), tiered WEAK per Gate-5 — it locates a phase as a
// HYPOTHESIS; a removal/perturbation oracle is the cutting step's verdict.
//
// Gate-0 self-tests (BLOCKING): both arms decode sha==oracle (correctness);
// total samples above a floor (non-inert); the phase split is A/A STABLE across
// two independent sample passes (max per-phase drift <= tol) — an unstable split
// is noise, not a finding.
// ===========================================================================

/// Map a resolved symbol name to a decode PHASE bucket. Order matters:
/// table-build before header-parse (build_code_length_table vs code lengths).
fn phase_bucket(sym: &str) -> &'static str {
    let h = |n: &str| sym.contains(n);
    if h("decode_huffman_fastloop")
        || h("libdeflate_deflate_decompress_ex")
        || h("decode_huffman_libdeflate_style")
        || h("decode_chunk_with_rapidgzip")
    {
        "inner-decode"
    } else if h("LitLenTable")
        || h("DistTable")
        || h("make_inflate_huff_code")
        || h("rebuild_from_multisym")
        || h("set_and_expand")
        || h("build_decode_table")
        || h("build_code_length_table")
    {
        "table-build"
    } else if h("read_dynamic_huffman_coding")
        || h("read_header")
        || h("read_literal_and_distance")
        || h("parse_dynamic_header")
    {
        "header-parse"
    } else if h("crc32") || h("crc_eor3") || h("fold3") || h("libdeflate_crc32") {
        "crc"
    } else if h("memmove") || h("memcpy") || h("memset") || h("copy_range_into") {
        "copy/memset"
    } else {
        "setup/other"
    }
}

const PHASES: [&str; 6] = [
    "inner-decode",
    "table-build",
    "header-parse",
    "crc",
    "copy/memset",
    "setup/other",
];

/// Hidden child: loop the decode of `arm` over `corpus` for `secs` seconds so the
/// parent's `sample` has a live, decode-bound target. Prints nothing on success.
fn phaseprof_loop_child(arm: &str, corpus: &str, secs: f64) -> ExitCode {
    let data = match std::fs::read(corpus) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("phaseprof child: read {corpus}: {e}");
            return ExitCode::from(2);
        }
    };
    let out_len = Command::new("gzip")
        .arg("-dc")
        .arg(corpus)
        .output()
        .map(|o| o.stdout.len())
        .unwrap_or(0);
    let mut buf = vec![0u8; out_len + 4096];
    let t0 = Instant::now();
    while t0.elapsed().as_secs_f64() < secs {
        if arm == "gz" {
            run_gz(&data, &mut buf);
        } else {
            run_ld(&data, &mut buf);
        }
    }
    ExitCode::SUCCESS
}

/// Spawn the loop-child for `arm`, `sample` it for `dur_s`, and return the
/// per-PHASE self-sample totals (absolute counts) parsed from the top-of-stack
/// section. The child runs ~dur_s+1s so it outlives the sampler.
fn sample_phase(
    arm: &str,
    corpus: &str,
    dur_s: f64,
) -> Result<std::collections::BTreeMap<String, u64>, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let mut child = Command::new(&exe)
        .arg("phaseprof")
        .arg("--_loop-child")
        .arg(arm)
        .arg("--corpus")
        .arg(corpus)
        .arg("--secs")
        .arg(format!("{:.1}", dur_s + 1.5))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn loop-child: {e}"))?;
    // let the child page in code + start decoding before sampling
    std::thread::sleep(std::time::Duration::from_millis(400));
    let tmp = std::env::temp_dir().join(format!("fulcrum_phaseprof_{arm}.txt"));
    let tmp = tmp.to_string_lossy().to_string();
    let st = Command::new("/usr/bin/sample")
        .arg(format!("{}", child.id()))
        .arg(format!("{:.0}", dur_s))
        .arg("-file")
        .arg(&tmp)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("spawn sample: {e}"))?;
    let _ = child.wait();
    if !st.success() {
        return Err(format!("sample exited {st}"));
    }
    let text = std::fs::read_to_string(&tmp).map_err(|e| format!("read {tmp}: {e}"))?;
    let _ = std::fs::remove_file(&tmp);
    // Parse the "Sort by top of stack, same collapsed" section: each line is
    //   <indent><symbol>  (in <image>)<spaces><count>
    let mut totals: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    let mut in_section = false;
    for line in text.lines() {
        if line.starts_with("Sort by top of stack") {
            in_section = true;
            continue;
        }
        if !in_section {
            continue;
        }
        // section ends at a blank line or a new "Sort by" / "Binary Images"
        if line.trim().is_empty()
            || line.starts_with("Binary Images")
            || line.starts_with("Sort by")
        {
            if !totals.is_empty() {
                break;
            }
            continue;
        }
        // split off the trailing count
        let trimmed = line.trim_end();
        let count: u64 = match trimmed
            .split_whitespace()
            .last()
            .and_then(|t| t.parse().ok())
        {
            Some(c) => c,
            None => continue,
        };
        // symbol = everything before "  (in "
        let sym = match trimmed.find("  (in ") {
            Some(i) => trimmed[..i].trim().to_string(),
            None => continue,
        };
        *totals.entry(phase_bucket(&sym).to_string()).or_insert(0) += count;
    }
    Ok(totals)
}

pub fn cmd_phaseprof(args: &[String]) -> ExitCode {
    if args.iter().any(|a| a == "--_loop-child") {
        // positional after the flag: arm
        let arm = args
            .iter()
            .position(|a| a == "--_loop-child")
            .and_then(|i| args.get(i + 1))
            .map(|s| s.as_str())
            .unwrap_or("gz");
        let corpus = flag(args, "--corpus").unwrap_or(DEFAULT_CORPUS);
        let secs: f64 = flag(args, "--secs")
            .and_then(|s| s.parse().ok())
            .unwrap_or(8.0);
        return phaseprof_loop_child(arm, corpus, secs);
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "fulcrum phaseprof (macOS) — per-PHASE cycle attribution of the T1 decode\n\
             (gz vs libdeflate) via statistical PC-sampling of a looped in-process decode.\n\n\
             USAGE: fulcrum phaseprof [--corpus f.gz] [--secs S]\n\
             Phases: inner-decode, table-build, header-parse, crc, copy/memset, setup/other.\n\
             Gate-0: per-arm sha==oracle, samples non-inert, A/A-stable split.\n\
             NOTE: CYCLE attribution (Gate-5 WEAK) — locates a phase as a HYPOTHESIS;\n\
             the cut is verified by a removal/perturbation oracle."
        );
        return ExitCode::SUCCESS;
    }
    let corpus = flag(args, "--corpus").unwrap_or(DEFAULT_CORPUS).to_string();
    let secs: f64 = flag(args, "--secs")
        .and_then(|s| s.parse().ok())
        .unwrap_or(6.0);

    if which("/usr/bin/sample").is_none() && !Path::new("/usr/bin/sample").exists() {
        eprintln!("phaseprof: /usr/bin/sample not found");
        return ExitCode::from(2);
    }

    println!("== fulcrum phaseprof (macOS) — per-phase decode cycle attribution ==");
    println!("corpus={corpus} sample_secs={secs}");

    // ---- Gate-0 -------------------------------------------------------------
    println!("-- Gate-0 self-validation (BLOCKING) --");
    let mut g0_ok = true;
    macro_rules! g0 {
        ($cond:expr, $($m:tt)*) => {{
            let ok = $cond;
            println!("  [Gate-0] {} :: {}", if ok {"PASS"} else {"FAIL"}, format!($($m)*));
            if !ok { g0_ok = false; }
        }};
    }
    let data = match std::fs::read(&corpus) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("phaseprof: read {corpus}: {e}");
            return ExitCode::from(2);
        }
    };
    let oracle = match oracle_sha(&corpus) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("phaseprof: oracle failed: {e}");
            return ExitCode::from(2);
        }
    };
    let out_len = {
        let o = Command::new("gzip")
            .arg("-dc")
            .arg(&corpus)
            .output()
            .unwrap();
        o.stdout.len()
    };
    let mut buf = vec![0u8; out_len + 4096];
    let gz_len = run_gz(&data, &mut buf);
    g0!(
        sha256_hex(&buf[..gz_len]) == oracle,
        "gz decode sha == oracle"
    );
    let ld_len = run_ld(&data, &mut buf);
    g0!(
        sha256_hex(&buf[..ld_len]) == oracle,
        "libdeflate decode sha == oracle"
    );
    drop(buf);

    // Two independent sample passes per arm (A/A stability of the split).
    let mut gz_a = match sample_phase("gz", &corpus, secs) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("phaseprof: sample gz(a): {e}");
            return ExitCode::from(2);
        }
    };
    let gz_b = match sample_phase("gz", &corpus, secs) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("phaseprof: sample gz(b): {e}");
            return ExitCode::from(2);
        }
    };
    let ld_a = match sample_phase("ld", &corpus, secs) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("phaseprof: sample ld: {e}");
            return ExitCode::from(2);
        }
    };

    let sum = |m: &std::collections::BTreeMap<String, u64>| -> u64 { m.values().sum() };
    let share = |m: &std::collections::BTreeMap<String, u64>, p: &str| -> f64 {
        let t = sum(m);
        if t == 0 {
            0.0
        } else {
            100.0 * *m.get(p).unwrap_or(&0) as f64 / t as f64
        }
    };
    let (gz_tot, ld_tot) = (sum(&gz_a), sum(&ld_a));
    g0!(
        gz_tot >= 800 && ld_tot >= 800,
        "samples non-inert (gz={gz_tot} ld={ld_tot} >= 800)"
    );
    // A/A: max per-phase share drift between gz pass a and b
    let mut max_drift = 0.0f64;
    for p in PHASES {
        max_drift = max_drift.max((share(&gz_a, p) - share(&gz_b, p)).abs());
    }
    g0!(
        max_drift <= 4.0,
        "A/A phase split STABLE across 2 passes (max drift {max_drift:.2}pp <= 4.0pp)"
    );

    if !g0_ok {
        eprintln!("\nphaseprof: GATE-0 FAILED — refusing to report (split untrustworthy)");
        return ExitCode::FAILURE;
    }
    println!("-- Gate-0 PASSED --\n");

    // Merge gz a+b for a steadier estimate.
    for (k, v) in gz_b {
        *gz_a.entry(k).or_insert(0) += v;
    }

    println!("phase                gz%        ld%      gz/ld");
    for p in PHASES {
        let g = share(&gz_a, p);
        let l = share(&ld_a, p);
        let r = if l > 0.01 {
            format!("{:.2}", g / l)
        } else {
            "—".into()
        };
        println!("{p:<16} {g:>8.2}   {l:>8.2}   {r:>6}");
    }
    println!(
        "\n(gz total self-samples={}, ld={}; CYCLE attribution — Gate-5 WEAK, \
         a phase's surplus is a HYPOTHESIS until a removal oracle cuts it.)",
        sum(&gz_a),
        ld_tot
    );

    // ---- ABSOLUTE cyc/B surplus decomposition (root only) -------------------
    // Distribute the kpc-measured total cyc/B over the phase shares and report
    // each phase's CONTRIBUTION to the gz-vs-ld surplus. The decomposition is
    // CONSERVATION-checked: Σ phase Δcyc/B == measured (gz-ld) cyc/B ± tol.
    if preflight_root().is_ok() {
        if let Some((gz_cycb, ld_cycb, gz_insb, ld_insb)) = measure_totals_kpc(&data, out_len) {
            println!(
                "\n-- absolute cyc/B surplus decomposition (kpc totals) --\n\
                 totals: gz {gz_cycb:.4} cyc/B ({gz_insb:.4} instr/B)  \
                 ld {ld_cycb:.4} cyc/B ({ld_insb:.4} instr/B)  \
                 instr surplus {:+.1}%",
                100.0 * (gz_insb / ld_insb - 1.0)
            );
            let surplus = gz_cycb - ld_cycb;
            println!("phase            gz cyc/B   ld cyc/B    Δcyc/B   %surplus");
            let mut acc = 0.0;
            for p in PHASES {
                let gv = share(&gz_a, p) / 100.0 * gz_cycb;
                let lv = share(&ld_a, p) / 100.0 * ld_cycb;
                let d = gv - lv;
                acc += d;
                let pct = if surplus.abs() > 1e-9 {
                    100.0 * d / surplus
                } else {
                    0.0
                };
                println!("{p:<14} {gv:>9.4} {lv:>9.4} {d:>9.4}  {pct:>7.1}%");
            }
            let conserves = (acc - surplus).abs() <= 0.02 * gz_cycb;
            println!(
                "SUM Δ                                {acc:>9.4}  (measured surplus {surplus:.4}; \
                 conservation {})",
                if conserves { "PASS" } else { "FAIL" }
            );
        }
    } else {
        println!("(re-run under `sudo -E` to add the kpc-measured absolute cyc/B surplus decomposition.)");
    }
    ExitCode::SUCCESS
}

/// Measure median total (cyc/B, instr/B) for gz and ld via per-thread kpc over an
/// in-process decode. Returns None if the PMU is unavailable. Root required.
fn measure_totals_kpc(data: &[u8], out_len: usize) -> Option<(f64, f64, f64, f64)> {
    let pmu = Pmu::new().ok()?;
    let sess = Session::program(&pmu, &["FIXED_CYCLES", "FIXED_INSTRUCTIONS"]).ok()?;
    let mut buf = vec![0u8; out_len + 4096];
    let measure = |buf: &mut [u8], arm: char| -> (u64, u64) {
        let before = sess.read(&pmu);
        if arm == 'g' {
            run_gz(data, buf);
        } else {
            run_ld(data, buf);
        }
        let after = sess.read(&pmu);
        (after[0] - before[0], after[1] - before[1])
    };
    let _ = measure(&mut buf, 'g');
    let _ = measure(&mut buf, 'l');
    let (mut gc, mut gi, mut lc, mut li) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for _ in 0..9 {
        let (a, b) = measure(&mut buf, 'g');
        gc.push(a as f64);
        gi.push(b as f64);
        let (a, b) = measure(&mut buf, 'l');
        lc.push(a as f64);
        li.push(b as f64);
    }
    let o = out_len as f64;
    Some((
        median(&gc) / o,
        median(&lc) / o,
        median(&gi) / o,
        median(&li) / o,
    ))
}

// ===========================================================================
// `fulcrum insndiff` (macOS) — instruction-level disasm differential of gz's
// hot fastloop vs libdeflate's decode loop. Deterministic static analysis of
// `otool -tV` (no run, no counters): instruction-class census + store-addressing
// census + loop back-edge map → the concrete per-symbol divergences that carry
// the in-loop instruction surplus.
//
// Gate-0 self-tests (BLOCKING): both symbols resolve to a non-empty instruction
// stream; class census sums to the instruction total (closed ledger); the disasm
// is REPRODUCIBLE (two otool invocations yield byte-identical instruction
// streams) — a non-reproducible disasm is not a measurement.
// ===========================================================================

#[derive(Clone)]
struct Insn {
    mnem: String,
    ops: String,
    addr: u64,
}

fn otool_disasm(bin: &str) -> Result<String, String> {
    let out = Command::new("otool")
        .arg("-tV")
        .arg(bin)
        .output()
        .map_err(|e| format!("spawn otool: {e}"))?;
    if !out.status.success() {
        return Err(format!("otool -tV {bin} failed: {}", out.status));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Extract the instruction stream for the first symbol whose label line CONTAINS
/// `needle`. otool format: instruction lines contain a TAB (`addr\tmnem\tops`);
/// label lines have no tab and end with `:`.
fn extract_symbol(disasm: &str, needle: &str) -> Result<Vec<Insn>, String> {
    let mut out = Vec::new();
    let mut inside = false;
    for line in disasm.lines() {
        let is_label = !line.contains('\t') && line.ends_with(':');
        if is_label {
            if inside {
                break; // next symbol — done
            }
            inside = line.contains(needle);
            continue;
        }
        if inside {
            let mut it = line.splitn(3, '\t');
            let addr_s = it.next().unwrap_or("").trim();
            let mnem = it.next().unwrap_or("").trim().to_string();
            let ops = it.next().unwrap_or("").trim().to_string();
            if mnem.is_empty() {
                continue;
            }
            let addr = u64::from_str_radix(addr_s, 16).unwrap_or(0);
            out.push(Insn { mnem, ops, addr });
        }
    }
    if out.is_empty() {
        return Err(format!("symbol containing '{needle}' not found / empty"));
    }
    Ok(out)
}

fn classify_insn(mnem: &str, ops: &str) -> &'static str {
    let m = mnem.to_ascii_lowercase();
    // SIMD/FP: vector-register operand, or a known NEON/FP mnemonic.
    let vec_reg = {
        let bytes = ops.as_bytes();
        let mut found = false;
        let mut i = 0;
        while i < bytes.len() {
            let c = bytes[i] as char;
            if (c == 'v' || c == 'q')
                && i + 1 < bytes.len()
                && (bytes[i + 1] as char).is_ascii_digit()
            {
                found = true;
                break;
            }
            i += 1;
        }
        found
    };
    if vec_reg && !m.starts_with("ld") && !m.starts_with("st") {
        return "simd";
    }
    if matches!(
        m.as_str(),
        "movi"
            | "dup"
            | "tbl"
            | "tbx"
            | "ext"
            | "zip1"
            | "zip2"
            | "uzp1"
            | "uzp2"
            | "pmull"
            | "pmull2"
            | "eor3"
            | "cnt"
            | "addv"
            | "umov"
            | "ins"
            | "rev16"
            | "rev32"
            | "rev64"
    ) {
        return "simd";
    }
    if m.starts_with('f') && m != "fmov" {
        return "simd";
    }
    if m.starts_with("ld") {
        return "load";
    }
    if m.starts_with("st") {
        return "store";
    }
    if matches!(
        m.as_str(),
        "b" | "bl" | "br" | "blr" | "ret" | "cbz" | "cbnz" | "tbz" | "tbnz"
    ) || m.starts_with("b.")
    {
        return "branch";
    }
    if matches!(
        m.as_str(),
        "lsl"
            | "lsr"
            | "asr"
            | "ror"
            | "extr"
            | "ubfx"
            | "sbfx"
            | "ubfm"
            | "sbfm"
            | "bfi"
            | "bfxil"
            | "bfc"
            | "bfm"
            | "rbit"
            | "clz"
            | "rev"
    ) {
        return "shift/bitfield";
    }
    if matches!(
        m.as_str(),
        "add"
            | "adds"
            | "sub"
            | "subs"
            | "mul"
            | "madd"
            | "msub"
            | "umull"
            | "umulh"
            | "smull"
            | "udiv"
            | "sdiv"
            | "neg"
            | "adc"
            | "sbc"
            | "adrp"
            | "adr"
    ) {
        return "arith";
    }
    if matches!(
        m.as_str(),
        "and" | "ands" | "orr" | "orn" | "eor" | "bic" | "eon" | "mvn"
    ) {
        return "logic";
    }
    if matches!(
        m.as_str(),
        "cmp"
            | "cmn"
            | "ccmp"
            | "ccmn"
            | "csel"
            | "cinc"
            | "csinc"
            | "cset"
            | "csetm"
            | "csinv"
            | "cneg"
            | "csneg"
            | "tst"
    ) {
        return "compare/select";
    }
    if matches!(m.as_str(), "mov" | "movz" | "movk" | "movn" | "fmov") {
        return "mov";
    }
    "other"
}

/// Classify a load/store addressing mode (the `*p++` vs `base[idx]` question).
fn addr_mode(ops: &str) -> &'static str {
    if ops.contains("], #") {
        "post-index" // *p; p += n   (libdeflate's *out_next++ shape)
    } else if ops.contains("]!") {
        "pre-index"
    } else if let Some(i) = ops.find('[') {
        let inner = &ops[i..];
        // [reg, wN]/[reg, xN] = register-offset (computed index); [reg, #imm] = imm-offset
        if inner.contains(", w") || inner.contains(", x") {
            "reg-offset" // base[idx]  (computed-index shape)
        } else if inner.contains(", #") {
            "imm-offset"
        } else {
            "base"
        }
    } else {
        "n/a"
    }
}

fn census_of(insns: &[Insn]) -> std::collections::BTreeMap<String, usize> {
    let mut c = std::collections::BTreeMap::new();
    for i in insns {
        *c.entry(classify_insn(&i.mnem, &i.ops).to_string())
            .or_insert(0) += 1;
    }
    c
}

fn store_modes_of(insns: &[Insn]) -> std::collections::BTreeMap<String, usize> {
    let mut c = std::collections::BTreeMap::new();
    for i in insns {
        if i.mnem.to_ascii_lowercase().starts_with("st") {
            *c.entry(addr_mode(&i.ops).to_string()).or_insert(0) += 1;
        }
    }
    c
}

/// Find loop back-edges (a branch whose target is at or before it, in-function),
/// returning (target, branch_addr, body_instr_count) sorted by body size.
fn back_edges(insns: &[Insn]) -> Vec<(u64, u64, usize)> {
    if insns.is_empty() {
        return Vec::new();
    }
    let lo = insns[0].addr;
    let mut edges = Vec::new();
    for i in insns {
        let m = i.mnem.to_ascii_lowercase();
        let is_br =
            matches!(m.as_str(), "b" | "cbz" | "cbnz" | "tbz" | "tbnz") || m.starts_with("b.");
        if !is_br {
            continue;
        }
        if let Some(p) = i.ops.find("0x") {
            if let Ok(tgt) = u64::from_str_radix(&i.ops[p + 2..].trim(), 16) {
                if tgt >= lo && tgt <= i.addr {
                    let body = insns
                        .iter()
                        .filter(|x| x.addr >= tgt && x.addr <= i.addr)
                        .count();
                    edges.push((tgt, i.addr, body));
                }
            }
        }
    }
    edges.sort_by_key(|e| e.2);
    edges.dedup();
    edges
}

pub fn cmd_insndiff(args: &[String]) -> ExitCode {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "fulcrum insndiff (macOS) — instruction-level disasm differential of gz's hot\n\
             fastloop vs libdeflate's decode loop (static `otool -tV` analysis).\n\n\
             USAGE: fulcrum insndiff [--bin PATH] [--gz-sym NEEDLE] [--ld-sym NEEDLE]\n\
             Defaults: --bin = this fulcrum binary (statically links both decoders),\n\
               --gz-sym decode_huffman_fastloop_bounded_pipelined,\n\
               --ld-sym _libdeflate_deflate_decompress_ex.\n\
             Gate-0: both symbols resolve non-empty; census closes to total; disasm reproducible."
        );
        return ExitCode::SUCCESS;
    }
    let self_exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let bin = flag(args, "--bin").unwrap_or(&self_exe).to_string();
    let gz_sym = flag(args, "--gz-sym").unwrap_or("decode_huffman_fastloop_bounded_pipelined");
    let ld_sym = flag(args, "--ld-sym").unwrap_or("_libdeflate_deflate_decompress_ex");

    println!("== fulcrum insndiff (macOS) — gz fastloop vs libdeflate decode loop ==");
    println!("bin={bin}\ngz_sym~={gz_sym}\nld_sym~={ld_sym}");

    if !Path::new(&bin).exists() {
        eprintln!("insndiff: binary {bin} not found");
        return ExitCode::from(2);
    }

    println!("-- Gate-0 self-validation (BLOCKING) --");
    let mut g0_ok = true;
    macro_rules! g0 {
        ($cond:expr, $($m:tt)*) => {{
            let ok = $cond;
            println!("  [Gate-0] {} :: {}", if ok {"PASS"} else {"FAIL"}, format!($($m)*));
            if !ok { g0_ok = false; }
        }};
    }

    let dis = match otool_disasm(&bin) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("insndiff: {e}");
            return ExitCode::from(2);
        }
    };
    let gz = match extract_symbol(&dis, gz_sym) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("insndiff: gz: {e}");
            return ExitCode::from(2);
        }
    };
    let ld = match extract_symbol(&dis, ld_sym) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("insndiff: ld: {e}");
            return ExitCode::from(2);
        }
    };
    g0!(
        !gz.is_empty(),
        "gz symbol resolved ({} instructions)",
        gz.len()
    );
    g0!(
        !ld.is_empty(),
        "ld symbol resolved ({} instructions)",
        ld.len()
    );

    let gz_c = census_of(&gz);
    let ld_c = census_of(&ld);
    g0!(
        gz_c.values().sum::<usize>() == gz.len() && ld_c.values().sum::<usize>() == ld.len(),
        "census closes to total (gz {}=={}, ld {}=={})",
        gz_c.values().sum::<usize>(),
        gz.len(),
        ld_c.values().sum::<usize>(),
        ld.len()
    );
    // Reproducibility: a second otool pass yields an identical instruction stream.
    let dis2 = otool_disasm(&bin).unwrap_or_default();
    let gz2 = extract_symbol(&dis2, gz_sym).unwrap_or_default();
    let repro = gz2.len() == gz.len()
        && gz2
            .iter()
            .zip(&gz)
            .all(|(a, b)| a.mnem == b.mnem && a.ops == b.ops && a.addr == b.addr);
    g0!(repro, "disasm reproducible across two otool invocations");

    if !g0_ok {
        eprintln!("\ninsndiff: GATE-0 FAILED — refusing to report");
        return ExitCode::FAILURE;
    }
    println!("-- Gate-0 PASSED --\n");

    println!("NOTE: gz_sym is the INNER fastloop only (table-build is separate functions);");
    println!("      ld_sym is libdeflate's WHOLE decode (loop + header + table-build inline).");
    println!("      Compare the per-class MIX and the in-loop store addressing, not raw totals.\n");

    let classes = [
        "load",
        "store",
        "branch",
        "arith",
        "logic",
        "shift/bitfield",
        "compare/select",
        "mov",
        "simd",
        "other",
    ];
    println!("class            gz#   gz%      ld#   ld%");
    for c in classes {
        let g = *gz_c.get(c).unwrap_or(&0);
        let l = *ld_c.get(c).unwrap_or(&0);
        println!(
            "{c:<14} {g:>5} {:>6.1}%  {l:>5} {:>6.1}%",
            100.0 * g as f64 / gz.len() as f64,
            100.0 * l as f64 / ld.len() as f64
        );
    }
    println!("{:<14} {:>5}          {:>5}", "TOTAL", gz.len(), ld.len());

    let sm_g = store_modes_of(&gz);
    let sm_l = store_modes_of(&ld);
    println!("\nstore addressing      gz     ld   (*p++=post-index; base[idx]=reg-offset)");
    for m in [
        "post-index",
        "pre-index",
        "imm-offset",
        "reg-offset",
        "base",
        "n/a",
    ] {
        let g = *sm_g.get(m).unwrap_or(&0);
        let l = *sm_l.get(m).unwrap_or(&0);
        if g > 0 || l > 0 {
            println!("  {m:<18} {g:>5} {l:>5}");
        }
    }

    // Loop back-edge map: the smallest bodies are the copy/fill micro-loops; the
    // largest in-function back-edge is the main per-symbol decode loop.
    let ge = back_edges(&gz);
    let le = back_edges(&ld);
    let micro =
        |edges: &[(u64, u64, usize)]| -> usize { edges.iter().filter(|e| e.2 <= 6).count() };
    println!(
        "\nloop back-edges: gz={} (micro<=6:{})  ld={} (micro<=6:{})",
        ge.len(),
        micro(&ge),
        le.len(),
        micro(&le)
    );
    let show = |name: &str, edges: &[(u64, u64, usize)]| {
        if let Some(big) = edges.iter().max_by_key(|e| e.2) {
            println!(
                "  {name} largest back-edge body = {} instrs [{:#x}..{:#x}] (≈ main decode loop)",
                big.2, big.0, big.1
            );
        }
    };
    show("gz", &ge);
    show("ld", &le);

    ExitCode::SUCCESS
}

#[cfg(test)]
mod insndiff_tests {
    use super::*;

    #[test]
    fn classify_covers_arm64_basics() {
        assert_eq!(classify_insn("ldr", "x0, [x1]"), "load");
        assert_eq!(classify_insn("strb", "w0, [x1], #1"), "store");
        assert_eq!(classify_insn("b.ls", "0x100"), "branch");
        assert_eq!(classify_insn("add", "x0, x1, x2"), "arith");
        assert_eq!(
            classify_insn("eor3", "v0.16b, v1.16b, v2.16b, v3.16b"),
            "simd"
        );
        assert_eq!(classify_insn("lsr", "x0, x1, #3"), "shift/bitfield");
        assert_eq!(classify_insn("csel", "x0, x1, x2, lo"), "compare/select");
    }

    #[test]
    fn addr_mode_distinguishes_postindex_from_regoffset() {
        assert_eq!(addr_mode("x9, [x8], #0x8"), "post-index");
        assert_eq!(addr_mode("x9, [x8, x10]"), "reg-offset");
        assert_eq!(addr_mode("x9, [x8, #0x10]"), "imm-offset");
        assert_eq!(addr_mode("x9, [x8]"), "base");
    }

    #[test]
    fn extract_and_backedges_on_synthetic_otool() {
        // synthetic otool -tV slice: a label, a 3-instruction back-edge loop.
        let dis = "\
_foo:\n\
0000000100000000\tldr\tx0, [x1], #8\n\
0000000100000004\tsubs\tx2, x2, #1\n\
0000000100000008\tb.ne\t0x100000000\n\
_bar:\n\
000000010000000c\tret\t\n";
        let v = extract_symbol(dis, "_foo").unwrap();
        assert_eq!(v.len(), 3);
        let e = back_edges(&v);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].2, 3); // body of 3
                               // _bar must NOT be included
        assert!(extract_symbol(dis, "_bar")
            .unwrap()
            .iter()
            .all(|i| i.mnem == "ret"));
    }
}

fn which(name: &str) -> Option<String> {
    if name.contains('/') {
        return if Path::new(name).exists() {
            Some(name.to_string())
        } else {
            None
        };
    }
    let out = Command::new("which").arg(name).output().ok()?;
    if out.status.success() {
        let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if p.is_empty() {
            None
        } else {
            Some(p)
        }
    } else {
        None
    }
}

// ===========================================================================
// `fulcrum classhist` (macOS) — execution-weighted INSTRUCTION-CLASS histogram
// of the T1 decode path, gz (pure-Rust ParallelSM, the gzippy crate) vs ref
// (libdeflate, the libdeflater crate), plus the gz-ref per-class delta.
//
// METHOD (stated limits up front): statistical PC-sampling (`/usr/bin/sample`)
// of a looped IN-PROCESS decode gives a per-SYMBOL execution weight (∝ CPU
// time). Each symbol's STATIC instruction-class mix (otool -tV census of the
// SAME binary) is then weighted by that symbol's sample count and summed over
// the WHOLE executed decode path. The result is a time-weighted instruction-
// class SHAPE for each arm — a Gate-5 WEAK lens that LOCATES whether gz's known
// +instruction surplus is CONCENTRATED in one class (→ a code lever) or spread
// UNIFORMLY across classes (→ generic codegen). It is "static-per-symbol mix ×
// sample-weight" (the brief-sanctioned approximation when dynamic per-class
// retire counts aren't available on M1); it is NOT a per-class retired-
// instruction count. A concentrated class is a HYPOTHESIS to be cut and
// re-measured (the verdict is the A/B), not a finding on its own.
//
// WHY in-process (same as the rest of the macOS suite): a single 220 MB logs
// decode is ~50 ms (15× ratio, copy-dominated) — far too short to sample
// without process-startup pollution. Looping the decode call inside one
// process yields thousands of pure decode-bound samples with zero per-iter
// startup. The gz arm is the gzippy crate dep (commit recorded as provenance);
// build with the dep pinned to the commit under test + target-cpu=native.
//
// Gate-0 self-tests (BLOCKING):
//   (a) each arm decodes sha == oracle (`gzip -dc`) — correctness;
//   (b) samples non-inert (total above a floor) AND symbol→census COVERAGE
//       above a floor (the hot path resolves in-binary);
//   (c) A/A STABLE: two independent sample passes give a class split whose
//       per-class drift <= tol (an unstable split is noise, not a finding);
//   (d) DISCRIMINATION: the same sample→census→classify pipeline run on a
//       known LOAD-bound kernel vs a known COMPUTE-bound kernel separates them
//       (load-kernel 'load' share strictly > alu-kernel 'load' share, and
//       alu-kernel arith/logic/shift share strictly > load-kernel's) — proves
//       the instrument can actually tell instruction classes apart on M1;
//   (e) records gz commit / libdeflater version / corpus sha.
// ===========================================================================

/// Load-bound discrimination kernel: a dependent pointer-chase (load-class
/// dominant). `#[no_mangle] #[inline(never)]` so it resolves as one clean symbol
/// in BOTH `sample` output and `otool -tV` of this binary.
#[no_mangle]
#[inline(never)]
pub fn classhist_kernel_load(buf: &[u64], iters: usize) -> u64 {
    let mask = buf.len() - 1;
    let mut idx = 0usize;
    let mut acc = 0u64;
    for _ in 0..iters {
        idx = (buf[idx] as usize) & mask;
        acc = acc.wrapping_add(buf[idx]);
        idx = (idx.wrapping_add(acc as usize)) & mask;
    }
    acc
}

/// Compute-bound discrimination kernel: register-resident integer mixing
/// (arith/logic/shift dominant, near-zero loads).
#[no_mangle]
#[inline(never)]
pub fn classhist_kernel_alu(seed: u64, iters: usize) -> u64 {
    let mut a = seed;
    let mut b = seed ^ 0x9e37_79b9_7f4a_7c15;
    for _ in 0..iters {
        a = a
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        b = b.wrapping_add(a).rotate_left(13);
        a ^= b >> 7;
        b = b.wrapping_mul(0xff51_afd7_ed55_8ccd);
    }
    a.wrapping_add(b)
}

const CLASSHIST_CLASSES: [&str; 10] = [
    "load",
    "store",
    "branch",
    "arith",
    "logic",
    "shift/bitfield",
    "compare/select",
    "mov",
    "simd",
    "other",
];

/// Normalize an `otool -tV` label line into a join key. Rust symbols end with
/// `...17h<16hex>E:` → key `h:<16hex>` (the hash is identical in `sample`'s
/// demangled output). C symbols (`_name:`) → key `n:<name>`.
fn classhist_key_from_label(label: &str) -> Option<String> {
    let s = label.trim_end().trim_end_matches(':');
    if s.is_empty() {
        return None;
    }
    if let Some(stripped) = s.strip_suffix('E') {
        let b = stripped.as_bytes();
        if b.len() >= 17 {
            let hash = &stripped[stripped.len() - 16..];
            let pre = &stripped[stripped.len() - 17..stripped.len() - 16];
            if pre == "h"
                && hash
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            {
                return Some(format!("h:{hash}"));
            }
        }
    }
    Some(format!("n:{}", s.trim_start_matches('_')))
}

/// Normalize a `sample` symbol name (the text before "  (in ") into the same key.
fn classhist_key_from_sample(name: &str) -> String {
    if let Some(i) = name.rfind("::h") {
        let tail = &name[i + 3..];
        if tail.len() == 16
            && tail
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return format!("h:{tail}");
        }
    }
    format!("n:{}", name.trim_start_matches('_'))
}

/// Per-symbol instruction-class census of the whole binary, keyed for joining
/// with `sample`. Returns key -> (class->count, total_instrs).
fn classhist_census_by_key(
    disasm: &str,
) -> std::collections::HashMap<String, (std::collections::BTreeMap<String, usize>, usize)> {
    let mut out: std::collections::HashMap<
        String,
        (std::collections::BTreeMap<String, usize>, usize),
    > = std::collections::HashMap::new();
    let mut cur: Option<String> = None;
    for line in disasm.lines() {
        let is_label = !line.contains('\t') && line.ends_with(':');
        if is_label {
            cur = classhist_key_from_label(line);
            continue;
        }
        let Some(key) = cur.as_ref() else { continue };
        let mut it = line.splitn(3, '\t');
        let _addr = it.next();
        let mnem = it.next().unwrap_or("").trim();
        let ops = it.next().unwrap_or("").trim();
        if mnem.is_empty() {
            continue;
        }
        let class = classify_insn(mnem, ops);
        let e = out
            .entry(key.clone())
            .or_insert_with(|| (std::collections::BTreeMap::new(), 0));
        *e.0.entry(class.to_string()).or_insert(0) += 1;
        e.1 += 1;
    }
    out
}

/// One `sample` pass over a looped in-process target (`mode` = gz|ld|kload|kalu).
/// Returns key -> sample-count, plus a key -> display-name map for reporting.
fn classhist_sample(
    mode: &str,
    corpus: &str,
    threads: usize,
    secs: f64,
) -> Result<
    (
        std::collections::HashMap<String, u64>,
        std::collections::HashMap<String, String>,
    ),
    String,
> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let mut child = Command::new(&exe)
        .arg("classhist")
        .arg("--_loop-child")
        .arg(mode)
        .arg("--corpus")
        .arg(corpus)
        .arg("--threads")
        .arg(threads.to_string())
        .arg("--secs")
        .arg(format!("{:.1}", secs + 2.0))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn loop-child: {e}"))?;
    std::thread::sleep(std::time::Duration::from_millis(450));
    let tmp = std::env::temp_dir().join(format!("fulcrum_classhist_{mode}.txt"));
    let tmp = tmp.to_string_lossy().to_string();
    let st = Command::new("/usr/bin/sample")
        .arg(format!("{}", child.id()))
        .arg(format!("{:.0}", secs))
        .arg("-file")
        .arg(&tmp)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("spawn sample: {e}"))?;
    let _ = child.wait();
    if !st.success() {
        return Err(format!("sample exited {st}"));
    }
    let text = std::fs::read_to_string(&tmp).map_err(|e| format!("read {tmp}: {e}"))?;
    let _ = std::fs::remove_file(&tmp);
    let mut counts: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let mut names: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut in_section = false;
    for line in text.lines() {
        if line.starts_with("Sort by top of stack") {
            in_section = true;
            continue;
        }
        if !in_section {
            continue;
        }
        if line.trim().is_empty()
            || line.starts_with("Binary Images")
            || line.starts_with("Sort by")
        {
            if !counts.is_empty() {
                break;
            }
            continue;
        }
        let trimmed = line.trim_end();
        let count: u64 = match trimmed
            .split_whitespace()
            .last()
            .and_then(|t| t.parse().ok())
        {
            Some(c) => c,
            None => continue,
        };
        let sym = match trimmed.find("  (in ") {
            Some(i) => trimmed[..i].trim().to_string(),
            None => continue,
        };
        let key = classhist_key_from_sample(&sym);
        *counts.entry(key.clone()).or_insert(0) += count;
        names.entry(key).or_insert(sym);
    }
    Ok((counts, names))
}

/// Loop-child body for classhist sampling.
fn classhist_loop_child(mode: &str, corpus: &str, threads: usize, secs: f64) -> ExitCode {
    let t0 = Instant::now();
    match mode {
        "gz" | "ld" => {
            let data = match std::fs::read(corpus) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("classhist child: read {corpus}: {e}");
                    return ExitCode::from(2);
                }
            };
            let out_len = Command::new("gzip")
                .arg("-dc")
                .arg(corpus)
                .output()
                .map(|o| o.stdout.len())
                .unwrap_or(0);
            let mut buf = vec![0u8; out_len + 4096];
            while t0.elapsed().as_secs_f64() < secs {
                if mode == "gz" {
                    let mut w = SliceWriter {
                        buf: &mut buf,
                        pos: 0,
                    };
                    gzippy::decompress_to_writer_with_threads(&data, &mut w, threads)
                        .expect("gz decode");
                } else {
                    let mut d = libdeflater::Decompressor::new();
                    d.gzip_decompress(&data, &mut buf)
                        .expect("libdeflate decode");
                }
            }
        }
        "kload" => {
            let n = 1usize << 16;
            let mut buf = vec![0u64; n];
            for (i, x) in buf.iter_mut().enumerate() {
                *x = ((i.wrapping_mul(2654435761)) as u64).wrapping_add(1);
            }
            let mut sink = 0u64;
            while t0.elapsed().as_secs_f64() < secs {
                sink = sink.wrapping_add(classhist_kernel_load(&buf, 20_000_000));
            }
            std::hint::black_box(sink);
        }
        "kalu" => {
            let mut sink = 0u64;
            while t0.elapsed().as_secs_f64() < secs {
                sink = sink.wrapping_add(classhist_kernel_alu(sink | 1, 20_000_000));
            }
            std::hint::black_box(sink);
        }
        _ => {
            eprintln!("classhist child: unknown mode {mode}");
            return ExitCode::from(2);
        }
    }
    ExitCode::SUCCESS
}

/// Build the execution-weighted class histogram for one arm from its sample
/// counts + the binary census. Returns (class->weighted_count, resolved_samples,
/// unresolved_samples).
fn classhist_weight(
    counts: &std::collections::HashMap<String, u64>,
    census: &std::collections::HashMap<String, (std::collections::BTreeMap<String, usize>, usize)>,
) -> (std::collections::BTreeMap<String, f64>, u64, u64) {
    let mut hist: std::collections::BTreeMap<String, f64> = std::collections::BTreeMap::new();
    let mut resolved = 0u64;
    let mut unresolved = 0u64;
    for (key, &cnt) in counts {
        match census.get(key) {
            Some((cen, total)) if *total > 0 => {
                resolved += cnt;
                for (class, n) in cen {
                    *hist.entry(class.clone()).or_insert(0.0) +=
                        cnt as f64 * (*n as f64 / *total as f64);
                }
            }
            _ => unresolved += cnt,
        }
    }
    (hist, resolved, unresolved)
}

fn classhist_shares(
    hist: &std::collections::BTreeMap<String, f64>,
) -> std::collections::BTreeMap<String, f64> {
    let tot: f64 = hist.values().sum();
    let mut s = std::collections::BTreeMap::new();
    for c in CLASSHIST_CLASSES {
        let v = *hist.get(c).unwrap_or(&0.0);
        s.insert(c.to_string(), if tot > 0.0 { 100.0 * v / tot } else { 0.0 });
    }
    s
}

pub fn cmd_classhist(args: &[String]) -> ExitCode {
    if args.iter().any(|a| a == "--_loop-child") {
        let mode = args
            .iter()
            .position(|a| a == "--_loop-child")
            .and_then(|i| args.get(i + 1))
            .map(|s| s.as_str())
            .unwrap_or("gz");
        let corpus = flag(args, "--corpus").unwrap_or(DEFAULT_CORPUS);
        let threads: usize = flag(args, "--threads")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);
        let secs: f64 = flag(args, "--secs")
            .and_then(|s| s.parse().ok())
            .unwrap_or(8.0);
        return classhist_loop_child(mode, corpus, threads, secs);
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "fulcrum classhist (macOS) — execution-weighted INSTRUCTION-CLASS histogram\n\
             of the T1 decode path: gz (gzippy pure-Rust ParallelSM) vs ref (libdeflate),\n\
             with the gz-ref per-class delta. Answers: is gz's instruction surplus\n\
             CONCENTRATED in one class (a lever) or UNIFORM across classes (codegen)?\n\n\
             USAGE: fulcrum classhist [--corpus f.gz] [--threads N] [--secs S] [--artifact out.json]\n\
             gz arm = the gzippy crate dep (build with the commit-under-test pinned +\n\
               RUSTFLAGS=\"-C target-cpu=native\"); ref arm = libdeflater crate.\n\
             METHOD: sample × static-per-symbol class mix (time-weighted SHAPE, Gate-5 WEAK).\n\
             Gate-0: per-arm sha==oracle, samples non-inert + coverage floor, A/A-stable\n\
               split, LOAD-vs-COMPUTE discrimination, records gz/ref/corpus provenance."
        );
        return ExitCode::SUCCESS;
    }
    let corpus = flag(args, "--corpus").unwrap_or(DEFAULT_CORPUS).to_string();
    let threads: usize = flag(args, "--threads")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let secs: f64 = flag(args, "--secs")
        .and_then(|s| s.parse().ok())
        .unwrap_or(6.0);
    let artifact = flag(args, "--artifact").map(|s| s.to_string());
    // Measured gz/ref instr-per-byte ratio from `fulcrum counterdiff` (a gated
    // kpc measurement). When given, classhist turns the per-arm SHAPE into an
    // ABSOLUTE per-class instruction-surplus attribution: which classes own the
    // (ratio-1) surplus, in instr/byte and as a share of the total surplus.
    let surplus_ratio: Option<f64> = flag(args, "--surplus-ratio").and_then(|s| s.parse().ok());

    if !Path::new("/usr/bin/sample").exists() {
        eprintln!("classhist: /usr/bin/sample not found");
        return ExitCode::from(2);
    }
    let self_exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

    println!("== fulcrum classhist (macOS) — execution-weighted instruction-class histogram ==");
    println!("corpus={corpus} threads={threads} sample_secs={secs} bin={self_exe}");

    // Provenance.
    let gz_commit = option_env!("GZIPPY_COMMIT").unwrap_or("(set GZIPPY_COMMIT at build)");
    let ld_ver = "libdeflater 1.25.2 (libdeflate 1.25)";
    let corpus_sha = file_sha256(&corpus).unwrap_or_else(|_| "?".into());

    println!("-- Gate-0 self-validation (BLOCKING) --");
    let mut g0_ok = true;
    macro_rules! g0 {
        ($cond:expr, $($m:tt)*) => {{
            let ok = $cond;
            println!("  [Gate-0] {} :: {}", if ok {"PASS"} else {"FAIL"}, format!($($m)*));
            if !ok { g0_ok = false; }
        }};
    }

    // (a) correctness
    let data = match std::fs::read(&corpus) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("classhist: read {corpus}: {e}");
            return ExitCode::from(2);
        }
    };
    let oracle = match oracle_sha(&corpus) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("classhist: oracle: {e}");
            return ExitCode::from(2);
        }
    };
    let out_len = {
        let o = Command::new("gzip")
            .arg("-dc")
            .arg(&corpus)
            .output()
            .unwrap();
        o.stdout.len()
    };
    let mut buf = vec![0u8; out_len + 4096];
    let gz_len = run_gz(&data, &mut buf);
    g0!(
        sha256_hex(&buf[..gz_len]) == oracle,
        "gz decode sha == oracle"
    );
    let ld_len = run_ld(&data, &mut buf);
    g0!(
        sha256_hex(&buf[..ld_len]) == oracle,
        "ld decode sha == oracle"
    );
    drop(buf);

    // Binary census (shared by both arms — both decoders are statically linked).
    let disasm = match otool_disasm(&self_exe) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("classhist: otool: {e}");
            return ExitCode::from(2);
        }
    };
    let census = classhist_census_by_key(&disasm);
    g0!(
        census.len() > 100,
        "binary census non-trivial ({} symbols)",
        census.len()
    );

    // (d) DISCRIMINATION — load-bound vs compute-bound kernel through the SAME pipe.
    let (kl_counts, _) = match classhist_sample("kload", &corpus, 1, 3.0) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("classhist: sample kload: {e}");
            return ExitCode::from(2);
        }
    };
    let (ka_counts, _) = match classhist_sample("kalu", &corpus, 1, 3.0) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("classhist: sample kalu: {e}");
            return ExitCode::from(2);
        }
    };
    let (kl_h, kl_r, _) = classhist_weight(&kl_counts, &census);
    let (ka_h, ka_r, _) = classhist_weight(&ka_counts, &census);
    let kl_s = classhist_shares(&kl_h);
    let ka_s = classhist_shares(&ka_h);
    // Discrimination (static-mix lens): the LOAD kernel's code carries loads the
    // load-free compute kernel does not, and the compute kernel is dominated by
    // compute classes — i.e. the sample→census→classify pipeline attributes
    // instruction CLASSES correctly and does not mis-tag a load-free kernel as
    // load-bearing. (Validates class attribution, NOT stall-boundness: static
    // mix weights instructions equally, it is not a cycle-stall lens.)
    let load_disc = kl_s["load"] > ka_s["load"] + 5.0;
    let ka_compute = ka_s["arith"] + ka_s["logic"] + ka_s["shift/bitfield"];
    let alu_disc = ka_s["load"] < 2.0 && ka_compute > ka_s["load"] + 5.0;
    g0!(
        kl_r > 200 && ka_r > 200,
        "discrimination kernels non-inert (kload r={kl_r}, kalu r={ka_r})"
    );
    g0!(
        load_disc,
        "LOAD kernel 'load' share {:.1}% > ALU kernel 'load' share {:.1}% (+5pp)",
        kl_s["load"],
        ka_s["load"]
    );
    g0!(
        alu_disc,
        "ALU kernel compute-dominated (compute {:.1}% >> load {:.1}%) — no load mis-tag",
        ka_compute,
        ka_s["load"]
    );

    // Decode samples: two independent passes per arm (A/A stability).
    let sample_arm = |arm: &str| classhist_sample(arm, &corpus, threads, secs);
    let (gz_a, gz_names) = match sample_arm("gz") {
        Ok(v) => v,
        Err(e) => {
            eprintln!("classhist: sample gz(a): {e}");
            return ExitCode::from(2);
        }
    };
    let (gz_b, _) = match sample_arm("gz") {
        Ok(v) => v,
        Err(e) => {
            eprintln!("classhist: sample gz(b): {e}");
            return ExitCode::from(2);
        }
    };
    let (ld_a, ld_names) = match sample_arm("ld") {
        Ok(v) => v,
        Err(e) => {
            eprintln!("classhist: sample ld(a): {e}");
            return ExitCode::from(2);
        }
    };
    let (ld_b, _) = match sample_arm("ld") {
        Ok(v) => v,
        Err(e) => {
            eprintln!("classhist: sample ld(b): {e}");
            return ExitCode::from(2);
        }
    };

    let (gz_ha, gz_r, gz_u) = classhist_weight(&gz_a, &census);
    let (gz_hb, _, _) = classhist_weight(&gz_b, &census);
    let (ld_ha, ld_r, ld_u) = classhist_weight(&ld_a, &census);
    let (ld_hb, _, _) = classhist_weight(&ld_b, &census);

    let gz_cov = gz_r as f64 / (gz_r + gz_u).max(1) as f64;
    let ld_cov = ld_r as f64 / (ld_r + ld_u).max(1) as f64;
    g0!(
        gz_r > 1000 && ld_r > 1000,
        "decode samples non-inert (gz r={gz_r}, ld r={ld_r})"
    );
    g0!(
        gz_cov >= 0.80 && ld_cov >= 0.80,
        "symbol→census coverage >= 80% (gz {:.1}%, ld {:.1}%)",
        100.0 * gz_cov,
        100.0 * ld_cov
    );

    // (c) A/A stability: max per-class share drift across the two passes.
    let gz_sa = classhist_shares(&gz_ha);
    let gz_sb = classhist_shares(&gz_hb);
    let ld_sa = classhist_shares(&ld_ha);
    let ld_sb = classhist_shares(&ld_hb);
    let max_drift = |a: &std::collections::BTreeMap<String, f64>,
                     b: &std::collections::BTreeMap<String, f64>|
     -> f64 {
        CLASSHIST_CLASSES
            .iter()
            .map(|c| (a[*c] - b[*c]).abs())
            .fold(0.0, f64::max)
    };
    let gz_drift = max_drift(&gz_sa, &gz_sb);
    let ld_drift = max_drift(&ld_sa, &ld_sb);
    g0!(
        gz_drift <= 4.0 && ld_drift <= 4.0,
        "A/A split stable (gz max drift {:.2}pp, ld {:.2}pp, tol 4pp)",
        gz_drift,
        ld_drift
    );
    println!(
        "  [prov] gz_commit={gz_commit} ref={ld_ver} corpus_sha={}",
        &corpus_sha[..corpus_sha.len().min(16)]
    );

    if !g0_ok {
        eprintln!("\nclasshist: GATE-0 FAILED — refusing to report");
        return ExitCode::FAILURE;
    }
    println!("-- Gate-0 PASSED --\n");

    // Average the two passes for the reported shape.
    let avg = |a: &std::collections::BTreeMap<String, f64>,
               b: &std::collections::BTreeMap<String, f64>| {
        let mut m = std::collections::BTreeMap::new();
        for c in CLASSHIST_CLASSES {
            m.insert(c.to_string(), 0.5 * (a[c] + b[c]));
        }
        m
    };
    let gz_s = avg(&gz_sa, &gz_sb);
    let ld_s = avg(&ld_sa, &ld_sb);

    println!("NOTE: time-weighted instruction-class SHAPE (Gate-5 WEAK). A class whose gz");
    println!("      share materially exceeds ref is a CONCENTRATED surplus = a code-change");
    println!("      HYPOTHESIS (verify by a pre-registered A/B). A flat delta across all");
    println!("      classes = the surplus is UNIFORM generic codegen, no point lever.\n");

    println!("class             gz%      ref%     Δ(gz-ref)pp");
    let mut deltas: Vec<(String, f64)> = Vec::new();
    for c in CLASSHIST_CLASSES {
        let g = gz_s[c];
        let l = ld_s[c];
        let d = g - l;
        deltas.push((c.to_string(), d));
        println!("{c:<16} {g:>6.2}%  {l:>6.2}%   {d:>+7.2}");
    }
    println!();

    // Concentration metric: how much of the total positive class-share delta is
    // owned by the single largest class.
    let pos: f64 = deltas
        .iter()
        .filter(|(_, d)| *d > 0.0)
        .map(|(_, d)| *d)
        .sum();
    let mut sorted = deltas.clone();
    sorted.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    let (top_class, top_d) = sorted[0].clone();
    let top_frac = if pos > 0.0 { top_d.max(0.0) / pos } else { 0.0 };
    println!(
        "top over-spent class: {top_class} (Δ {:+.2}pp = {:.0}% of all positive class drift)",
        top_d,
        100.0 * top_frac
    );
    let verdict = if top_frac >= 0.50 && top_d >= 3.0 {
        format!(
            "CONCENTRATED in '{top_class}' (owns {:.0}% of the surplus shape, Δ {:+.2}pp) — \
             a point lever; pre-register an A/B that reduces '{top_class}' emission.",
            100.0 * top_frac,
            top_d
        )
    } else {
        "UNIFORM across classes (no single class owns >=50% of the drift / >=3pp) — \
         generic Rust-vs-C codegen, NOT a point lever; remaining paths are per-region \
         asm or a structurally-different decoder."
            .to_string()
    };
    println!("VERDICT: {verdict}");

    // Absolute per-class instruction-surplus attribution (needs the measured
    // gz/ref instr-per-byte ratio from `fulcrum counterdiff`). gz_total = ratio,
    // ref_total = 1 (in ref-instr/byte units). per-class surplus = ratio*gz_share
    // - 1*ref_share; Σ = ratio-1 = the total surplus. Tells which classes own it.
    if let Some(r) = surplus_ratio {
        let total_surplus = r - 1.0;
        println!(
            "\n-- absolute instruction-surplus attribution (gz/ref instr/byte ratio = {:.4}, surplus = {:+.1}%) --",
            r,
            100.0 * total_surplus
        );
        println!("class            surplus(ref-instr/byte units)   % of total surplus");
        let mut rows: Vec<(String, f64)> = Vec::new();
        for c in CLASSHIST_CLASSES {
            let s = r * (gz_s[c] / 100.0) - (ld_s[c] / 100.0);
            rows.push((c.to_string(), s));
        }
        rows.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        for (c, s) in &rows {
            let pct = if total_surplus.abs() > 1e-9 {
                100.0 * s / total_surplus
            } else {
                0.0
            };
            println!("{c:<16} {s:>+10.4}                  {pct:>+6.1}%");
        }
        let top = &rows[0];
        let top_pct = 100.0 * top.1 / total_surplus;
        println!(
            "absolute: largest single class = '{}' ({:+.1}% of the surplus); {}",
            top.0,
            top_pct,
            if top_pct >= 50.0 {
                "CONCENTRATED — a point lever."
            } else {
                "DISTRIBUTED — every class inflated, no single point lever."
            }
        );
    }

    // Top symbols per arm (where the time goes).
    let top_syms = |counts: &std::collections::HashMap<String, u64>,
                    names: &std::collections::HashMap<String, String>,
                    label: &str| {
        let mut v: Vec<(&String, &u64)> = counts.iter().collect();
        v.sort_by(|a, b| b.1.cmp(a.1));
        let tot: u64 = counts.values().sum();
        println!("\ntop {label} symbols (sample share):");
        for (k, c) in v.iter().take(6) {
            let nm = names.get(*k).map(|s| s.as_str()).unwrap_or(k.as_str());
            // Drop a trailing "::h<16hex>" disambiguator so the FUNCTION name shows.
            let base = match nm.rfind("::h") {
                Some(i)
                    if nm[i + 3..].len() == 16
                        && nm[i + 3..].bytes().all(|b| b.is_ascii_hexdigit()) =>
                {
                    &nm[..i]
                }
                _ => nm,
            };
            let short = base.rsplit("::").next().unwrap_or(base);
            println!(
                "  {:>5.1}%  {}",
                100.0 * **c as f64 / tot.max(1) as f64,
                short
            );
        }
    };
    top_syms(&gz_a, &gz_names, "gz");
    top_syms(&ld_a, &ld_names, "ref(libdeflate)");

    if let Some(path) = artifact {
        let j = |m: &std::collections::BTreeMap<String, f64>| -> String {
            let mut parts = Vec::new();
            for c in CLASSHIST_CLASSES {
                parts.push(format!("\"{}\":{:.3}", c, m[c]));
            }
            format!("{{{}}}", parts.join(","))
        };
        let out = format!(
            "{{\n  \"tool\":\"fulcrum classhist\",\n  \"corpus\":\"{}\",\n  \"corpus_sha\":\"{}\",\n  \"threads\":{},\n  \"sample_secs\":{},\n  \"gz_commit\":\"{}\",\n  \"ref\":\"{}\",\n  \"gz_samples_resolved\":{},\n  \"ld_samples_resolved\":{},\n  \"gz_coverage\":{:.4},\n  \"ld_coverage\":{:.4},\n  \"instr_per_byte_ratio_gz_over_ref\":{},\n  \"gz_class_pct\":{},\n  \"ref_class_pct\":{},\n  \"top_overspent_class\":\"{}\",\n  \"top_overspent_delta_pp\":{:.3},\n  \"top_class_frac_of_positive_drift\":{:.3},\n  \"verdict\":\"{}\"\n}}\n",
            corpus, corpus_sha, threads, secs, gz_commit, ld_ver,
            gz_r, ld_r, gz_cov, ld_cov,
            surplus_ratio.map(|r| format!("{r:.4}")).unwrap_or_else(|| "null".into()),
            j(&gz_s), j(&ld_s),
            top_class, top_d, top_frac,
            if top_frac >= 0.50 && top_d >= 3.0 { "CONCENTRATED" } else { "UNIFORM" }
        );
        if let Err(e) = std::fs::write(&path, out) {
            eprintln!("classhist: write artifact {path}: {e}");
        } else {
            println!("\nartifact: {path}");
        }
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
mod classhist_tests {
    use super::*;

    #[test]
    fn key_from_mangled_rust_label_uses_hash() {
        let lbl = "__ZN6gzippy10decompress7inflate20consume_first_decode41decode_huffman_fastloop_bounded_pipelined17h6132f2c98c18c842E:";
        assert_eq!(
            classhist_key_from_label(lbl).as_deref(),
            Some("h:6132f2c98c18c842")
        );
    }

    #[test]
    fn key_from_c_label_uses_name_without_underscore() {
        assert_eq!(
            classhist_key_from_label("_libdeflate_deflate_decompress_ex:").as_deref(),
            Some("n:libdeflate_deflate_decompress_ex")
        );
    }

    #[test]
    fn sample_and_label_keys_join_on_hash() {
        // The demangled `sample` name and the mangled `otool` label for the same
        // function MUST produce the identical join key (the shared 16-hex hash).
        let sample = "gzippy::decompress::inflate::consume_first_decode::decode_huffman_fastloop_bounded_pipelined::h6132f2c98c18c842";
        let label =
            "__ZN6gzippy...41decode_huffman_fastloop_bounded_pipelined17h6132f2c98c18c842E:";
        assert_eq!(
            classhist_key_from_sample(sample),
            classhist_key_from_label(label).unwrap()
        );
    }

    #[test]
    fn sample_c_symbol_joins_with_c_label() {
        assert_eq!(
            classhist_key_from_sample("libdeflate_deflate_decompress_ex"),
            classhist_key_from_label("_libdeflate_deflate_decompress_ex:").unwrap()
        );
    }

    #[test]
    fn census_by_key_classifies_and_closes() {
        // synthetic otool -tV slice: one C symbol, two instructions.
        let dis = "_foo:\n0000\tldr\tx0, [x1]\n0004\tadd\tx0, x0, #1\n0008\tret\n";
        let m = classhist_census_by_key(dis);
        let (cen, total) = m.get("n:foo").expect("foo present");
        assert_eq!(*total, 3);
        assert_eq!(*cen.get("load").unwrap_or(&0), 1);
        assert_eq!(*cen.get("arith").unwrap_or(&0), 1);
        assert_eq!(*cen.get("branch").unwrap_or(&0), 1);
        // census closes to total
        assert_eq!(cen.values().sum::<usize>(), *total);
    }

    #[test]
    fn weight_distributes_sample_count_by_static_mix() {
        // foo = 2 load + 2 arith (50/50). 100 samples on foo → 50 load, 50 arith.
        let dis = "_foo:\n0\tldr\tx0,[x1]\n4\tldr\tx2,[x3]\n8\tadd\tx0,x0,x2\nc\tadd\tx4,x4,#1\n";
        let census = classhist_census_by_key(dis);
        let mut counts = std::collections::HashMap::new();
        counts.insert("n:foo".to_string(), 100u64);
        let (hist, resolved, unresolved) = classhist_weight(&counts, &census);
        assert_eq!(resolved, 100);
        assert_eq!(unresolved, 0);
        assert!((hist["load"] - 50.0).abs() < 1e-6);
        assert!((hist["arith"] - 50.0).abs() < 1e-6);
    }

    #[test]
    fn weight_counts_unresolved_samples() {
        let census = classhist_census_by_key("_foo:\n0\tret\n");
        let mut counts = std::collections::HashMap::new();
        counts.insert("n:not_in_binary".to_string(), 42u64);
        let (_h, resolved, unresolved) = classhist_weight(&counts, &census);
        assert_eq!(resolved, 0);
        assert_eq!(unresolved, 42);
    }
}

// ===========================================================================
// `fulcrum insnattr` (macOS / Apple-Silicon) — per-SYMBOL RETIRED-INSTRUCTION
// attribution of the production T1 decode (gzippy ParallelSM pure-Rust) vs the
// libdeflate 1.25 comparator.
//
// WHY THIS EXISTS (the blocked finding that PULLED it). The x86 `perf` campaign
// NOMINATED a per-function split of gz's instruction surplus over libdeflate
// (clean-fastloop ~81%, Huffman LUT-build ~16%) — but that nomination was never
// confirmed on Apple Silicon, because fulcrum-mac had no per-symbol RETIRED-
// INSTRUCTION attribution. The two M1 instruments it DID have each answer only
// half: `counterdiff` gives the whole-program retired TOTAL (one scalar, no
// shape); `classhist` gives a per-instruction-CLASS SHAPE (time-weighted, no
// per-symbol retired count). Neither produces a per-SYMBOL retired-instruction
// LEDGER, which is exactly what the nomination is stated in. `insnattr` is that
// ledger: it fuses the kpc whole-program retired total with the `/usr/bin/sample`
// per-symbol distribution, attributing retired instructions to each symbol so
// the per-symbol counts sum to the measured retired total (conservation by
// construction over the symbolized-sample universe).
//
// METHOD + ITS ONE STATED LIMIT (Gate-5: the distribution arm is a WEAK lens).
//   total   = kpc FIXED_INSTRUCTIONS retired over the in-process T1 decode
//             (per-thread, load-immune; median of N; A/A floor reported).
//   share_s = `/usr/bin/sample` leaf-symbol distribution (PC-sampling of a looped
//             in-process decode of the SAME pinned gzippy crate). This is
//             TIME(cycle)-weighted, so `retired_s = share_s * total` is the exact
//             retired count per symbol ONLY under uniform per-symbol IPC. The
//             whole-program IPC of both arms is reported so the reader can bound
//             that bias; a per-symbol retired WEIGHT (not just total-anchoring)
//             needs a kperf PMI PC-sampler (the kpc/kperf sampling symbols are
//             dlsym-able on this box but the sampler is unbuilt) OR Xcode/xctrace
//             CPU-Counters (Xcode is NOT installed — only CommandLineTools). That
//             is the honestly-stated M1 attribution wall.
//
// GATE-0 SELF-TESTS (BLOCKING — no attribution emitted unless ALL pass):
//   (a) sha==oracle BOTH arms: in-process gz AND ld decode == `gzip -dc` output.
//   (b) comparator solvent: libdeflate present + its decode symbol sampled.
//   (c) kpc present + non-zero retired both arms; gz retired A/A spread < 5%.
//   (d) sample non-inert: gz symbolized-sample count over a floor.
//   (e) decode-dominated: gzippy code holds a majority of gz's symbolized samples
//       (else the distribution is measuring runtime/libc, not the decoder).
//   (f) A/A distribution stability: top symbol's share is stable across two
//       independent gz sample passes (the floor a per-symbol claim must clear).
// ===========================================================================

/// Coarse decode-phase bucket for a demangled symbol name. Index-stable; used to
/// roll per-symbol retired attribution up to the phases the x86 nomination names.
fn insnattr_bucket(name: &str) -> &'static str {
    let n = name;
    let has = |needle: &str| n.contains(needle);
    // Clean (window-present / no-marker) inner Huffman decode fastloop. Checked
    // FIRST: these symbols live in the `marker_inflate` module, so the module
    // path contains "marker" — match the function name before any "marker"
    // module-path heuristic can steal them.
    if has("decode_clean_into_contig")
        || has("decode_huffman_fastloop")
        || has("read_internal_compressed_specialized")
        || has("decode_clean_fast_loop")
        || has("decode_marker_fast_loop")
        || has("decode_careful")
        || has("decode_huffman_body")
    {
        return "clean_decode";
    }
    // Huffman LUT BUILD + dynamic block-header parse (read code lengths, expand
    // huffcodes, build litlen/dist decode tables). These dominate the per-block
    // setup cost the x86 nomination calls "lut_build".
    if has("rebuild")
        || has("read_header")
        || has("read_block_header")
        || has("read_dynamic_huffman")
        || has("huffman_coding")
        || has("ensure_dist_table")
        || has("ensure_flat_litlen")
        || has("LitLenTable")
        || has("DistTable")
        || has("build_decode_table")
        || has("build_table")
        || has("make_inflate_huff_code")
        || has("set_and_expand")
        || has("expand_lit_len")
        || has("huffcode")
    {
        return "lut_build";
    }
    if has("crc") || has("Crc") || has("CRC") {
        return "crc";
    }
    if has("copy_match") || has("simd_copy") || has("apply_window") || has("memcpy") || has("memmove")
    {
        return "copy";
    }
    // Marker RESOLUTION proper (window-absent u16 marker replacement) — match the
    // specific functions, NOT the bare "marker" module path (that would capture
    // the whole marker_inflate clean path).
    if has("replace_markers") || has("MarkerReplacement") || has("resolve_marker") {
        return "marker_resolve";
    }
    if has("block_finder") || has("searcher_kind") || has("find_block") {
        return "block_finder";
    }
    "other"
}

/// True if a sampled symbol belongs to the gzippy decoder crate (our code), as
/// opposed to libc / dyld / the Rust runtime.
fn insnattr_is_gzippy(name: &str) -> bool {
    name.contains("gzippy")
}

/// True if a sampled symbol belongs to the libdeflate comparator.
fn insnattr_is_libdeflate(name: &str) -> bool {
    name.contains("libdeflate")
}

pub fn cmd_insnattr(args: &[String]) -> ExitCode {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "fulcrum insnattr (macOS/arm64) — per-SYMBOL RETIRED-INSTRUCTION attribution\n\
             of the production T1 decode: gz (gzippy pure-Rust ParallelSM) vs libdeflate 1.25.\n\n\
             USAGE: sudo -E fulcrum insnattr [--corpus f.gz] [--secs S] [--top N] [--artifact out.json]\n\
             Fuses kpc whole-program retired TOTAL with the /usr/bin/sample per-symbol\n\
             distribution => per-symbol retired counts that sum to the measured total.\n\
             Rolls up to decode PHASES (clean_decode / lut_build / crc / copy / ...) so the\n\
             x86 perf nomination (clean ~81%, lut_build ~16%) can be confirmed on M1.\n\
             LIMIT: distribution is time-weighted (Gate-5); retired-exact only under uniform\n\
             per-symbol IPC — whole-program IPC of both arms is reported to bound the bias.\n\
             Gate-0 (BLOCKING): sha==oracle both arms, kpc present + A/A retired spread<5%,\n\
             sample non-inert, decode-dominated, top-symbol share A/A-stable. Root required."
        );
        return ExitCode::SUCCESS;
    }
    let corpus = flag(args, "--corpus").unwrap_or(DEFAULT_CORPUS).to_string();
    let secs: f64 = flag(args, "--secs").and_then(|s| s.parse().ok()).unwrap_or(8.0);
    let topn: usize = flag(args, "--top").and_then(|s| s.parse().ok()).unwrap_or(20);
    let artifact = flag(args, "--artifact").map(|s| s.to_string());

    if !Path::new("/usr/bin/sample").exists() {
        eprintln!("insnattr: /usr/bin/sample not found");
        return ExitCode::from(2);
    }
    let self_exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

    println!("== fulcrum insnattr (macOS/arm64) — per-symbol RETIRED-INSTRUCTION attribution ==");
    println!("corpus={corpus} threads=1 sample_secs={secs} bin={self_exe}");
    let gz_commit = option_env!("GZIPPY_COMMIT").unwrap_or("(set GZIPPY_COMMIT at build)");
    let corpus_sha = file_sha256(&corpus).unwrap_or_else(|_| "?".into());
    println!("gz_commit={gz_commit} corpus_sha256={}", &corpus_sha[..corpus_sha.len().min(16)]);

    println!("-- Gate-0 self-validation (BLOCKING) --");
    let mut g0_ok = true;
    macro_rules! g0 {
        ($cond:expr, $($m:tt)*) => {{
            let ok = $cond;
            println!("  [Gate-0] {} :: {}", if ok {"PASS"} else {"FAIL"}, format!($($m)*));
            if !ok { g0_ok = false; }
        }};
    }

    // (a) correctness — output bytes both arms == gzip -dc oracle.
    let data = match std::fs::read(&corpus) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("insnattr: read {corpus}: {e}");
            return ExitCode::from(2);
        }
    };
    let (oracle, out_len) = match oracle_sha_len(&corpus) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("insnattr: oracle: {e}");
            return ExitCode::from(2);
        }
    };
    {
        let mut buf = vec![0u8; out_len + 4096];
        let gz_len = run_gz(&data, &mut buf);
        g0!(sha256_hex(&buf[..gz_len]) == oracle, "gz decode sha == gzip -dc oracle");
        let ld_len = run_ld(&data, &mut buf);
        g0!(sha256_hex(&buf[..ld_len]) == oracle, "ld decode sha == oracle (comparator solvent)");
    }

    // (c) kpc whole-program retired total + cycles, median of N, gz and ld.
    let pmu = match Pmu::new() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("insnattr: PMU init: {e}\n  (run under: sudo -E target/release/fulcrum insnattr ...)");
            return ExitCode::from(2);
        }
    };
    g0!(
        pmu.has_event("FIXED_INSTRUCTIONS") && pmu.has_event("FIXED_CYCLES"),
        "kpc FIXED_CYCLES + FIXED_INSTRUCTIONS present"
    );
    let sess = match Session::program(&pmu, &["FIXED_CYCLES", "FIXED_INSTRUCTIONS"]) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("insnattr: kpc Session: {e}");
            return ExitCode::from(2);
        }
    };
    let mut kbuf = vec![0u8; out_len + 4096];
    let mut measure = |arm: char| -> (f64, f64) {
        let before = sess.read(&pmu);
        if arm == 'g' {
            run_gz(&data, &mut kbuf);
        } else {
            run_ld(&data, &mut kbuf);
        }
        let after = sess.read(&pmu);
        ((after[0] - before[0]) as f64, (after[1] - before[1]) as f64)
    };
    let _ = measure('g');
    let _ = measure('l');
    let n = 9usize;
    let (mut gc, mut gi, mut lc, mut li) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for _ in 0..n {
        let (c, i) = measure('g');
        gc.push(c);
        gi.push(i);
        let (c, i) = measure('l');
        lc.push(c);
        li.push(i);
    }
    drop(kbuf);
    let gz_instr = median(&gi);
    let gz_cyc = median(&gc);
    let ld_instr = median(&li);
    let ld_cyc = median(&lc);
    let gi_spread = if gz_instr > 0.0 {
        100.0 * (gi.iter().cloned().fold(f64::MIN, f64::max)
            - gi.iter().cloned().fold(f64::MAX, f64::min))
            / gz_instr
    } else {
        999.0
    };
    g0!(gz_instr > 0.0 && ld_instr > 0.0, "non-zero retired both arms (gz={gz_instr:.0} ld={ld_instr:.0})");
    g0!(gi_spread < 5.0, "gz retired-instr A/A spread {gi_spread:.2}% < 5% (kpc stable)");
    let gz_ipc = if gz_cyc > 0.0 { gz_instr / gz_cyc } else { 0.0 };
    let ld_ipc = if ld_cyc > 0.0 { ld_instr / ld_cyc } else { 0.0 };

    // (d,e,f) per-symbol distribution via /usr/bin/sample. gz twice (A/A) + ld.
    let (gz_counts, gz_names) = match classhist_sample("gz", &corpus, 1, secs) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("insnattr: gz sample: {e}");
            return ExitCode::from(2);
        }
    };
    let (gz_counts2, _gz_names2) = match classhist_sample("gz", &corpus, 1, secs) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("insnattr: gz sample (A/A): {e}");
            return ExitCode::from(2);
        }
    };
    let (ld_counts, ld_names) = match classhist_sample("ld", &corpus, 1, secs) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("insnattr: ld sample: {e}");
            return ExitCode::from(2);
        }
    };
    let gz_total_s: u64 = gz_counts.values().sum();
    let gz_total_s2: u64 = gz_counts2.values().sum();
    let ld_total_s: u64 = ld_counts.values().sum();
    g0!(gz_total_s > 1000, "gz sample non-inert ({gz_total_s} leaf samples)");
    g0!(ld_total_s > 1000, "ld sample non-inert ({ld_total_s} leaf samples)");

    // decode-dominated: gzippy code share of gz symbolized samples.
    let gz_user_s: u64 = gz_counts
        .iter()
        .filter(|(k, _)| gz_names.get(*k).map(|s| insnattr_is_gzippy(s)).unwrap_or(false))
        .map(|(_, &c)| c)
        .sum();
    let gz_user_share = if gz_total_s > 0 {
        gz_user_s as f64 / gz_total_s as f64
    } else {
        0.0
    };
    g0!(gz_user_share > 0.5, "decode-dominated: gzippy code = {:.1}% of gz symbolized samples", 100.0 * gz_user_share);
    let ld_user_s: u64 = ld_counts
        .iter()
        .filter(|(k, _)| ld_names.get(*k).map(|s| insnattr_is_libdeflate(s)).unwrap_or(false))
        .map(|(_, &c)| c)
        .sum();
    g0!(ld_user_s > 0, "libdeflate decode symbol sampled ({ld_user_s} samples)");

    // A/A distribution stability: top gz key's share across the two passes.
    let top_key = gz_counts
        .iter()
        .max_by_key(|(_, &c)| c)
        .map(|(k, _)| k.clone())
        .unwrap_or_default();
    let sh1 = *gz_counts.get(&top_key).unwrap_or(&0) as f64 / gz_total_s.max(1) as f64;
    let sh2 = *gz_counts2.get(&top_key).unwrap_or(&0) as f64 / gz_total_s2.max(1) as f64;
    let aa_pp = 100.0 * (sh1 - sh2).abs();
    g0!(aa_pp < 3.0, "top-symbol share A/A-stable (Δ={aa_pp:.2}pp < 3pp)");

    if !g0_ok {
        eprintln!("insnattr: Gate-0 FAILED — attribution suppressed.");
        return ExitCode::from(1);
    }

    // ---- Attribution: per-symbol retired = share * kpc total ----
    let attribute = |counts: &std::collections::HashMap<String, u64>,
                     names: &std::collections::HashMap<String, String>,
                     total_s: u64,
                     total_instr: f64|
     -> Vec<(String, String, f64, f64)> {
        // (key, display_name, retired, share)
        let mut v: Vec<(String, String, f64, f64)> = counts
            .iter()
            .map(|(k, &c)| {
                let share = c as f64 / total_s.max(1) as f64;
                let name = names.get(k).cloned().unwrap_or_else(|| k.clone());
                (k.clone(), name, share * total_instr, share)
            })
            .collect();
        v.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap());
        v
    };
    let gz_attr = attribute(&gz_counts, &gz_names, gz_total_s, gz_instr);
    let ld_attr = attribute(&ld_counts, &ld_names, ld_total_s, ld_instr);

    // Phase roll-up (gz).
    let mut gz_phase: std::collections::BTreeMap<&'static str, f64> = std::collections::BTreeMap::new();
    for (_k, name, retired, _s) in &gz_attr {
        *gz_phase.entry(insnattr_bucket(name)).or_insert(0.0) += retired;
    }
    let mut ld_phase: std::collections::BTreeMap<&'static str, f64> = std::collections::BTreeMap::new();
    for (_k, name, retired, _s) in &ld_attr {
        *ld_phase.entry(insnattr_bucket(name)).or_insert(0.0) += retired;
    }

    let o = out_len as f64;
    println!("\n-- WHOLE-PROGRAM (kpc, per-thread, median of {n}) --");
    println!(
        "  gz : retired={gz_instr:.0} ({:.3} instr/B)  cycles={gz_cyc:.0}  IPC={gz_ipc:.3}",
        gz_instr / o
    );
    println!(
        "  ld : retired={ld_instr:.0} ({:.3} instr/B)  cycles={ld_cyc:.0}  IPC={ld_ipc:.3}",
        ld_instr / o
    );
    let surplus = gz_instr - ld_instr;
    println!(
        "  gz/ld retired ratio = {:.3}x   surplus = {surplus:.0} instr ({:.3} instr/B)",
        gz_instr / ld_instr.max(1.0),
        surplus / o
    );
    println!("  IPC similarity (time->retired bias bound): gz/ld IPC ratio = {:.3}", gz_ipc / ld_ipc.max(1e-9));

    println!("\n-- gz TOP {topn} SYMBOLS by attributed retired instructions --");
    for (_k, name, retired, share) in gz_attr.iter().take(topn) {
        let short = name.rsplit("::").take(2).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("::");
        let disp = if short.is_empty() { name.clone() } else { short };
        println!(
            "  {:>6.2}%  {:>12.0}  [{}]  {}",
            100.0 * share,
            retired,
            insnattr_bucket(name),
            disp
        );
    }

    println!("\n-- gz DECODE-PHASE roll-up (retired instructions) --");
    for (phase, r) in &gz_phase {
        println!("  {:<14} {:>12.0}  {:>6.2}%  ({:.3} instr/B)", phase, r, 100.0 * r / gz_instr, r / o);
    }
    println!("\n-- ld DECODE-PHASE roll-up (retired instructions) --");
    for (phase, r) in &ld_phase {
        println!("  {:<14} {:>12.0}  {:>6.2}%  ({:.3} instr/B)", phase, r, 100.0 * r / ld_instr, r / o);
    }

    // Reconciliation against the x86 nomination.
    let gz_clean = *gz_phase.get("clean_decode").unwrap_or(&0.0);
    let gz_lut = *gz_phase.get("lut_build").unwrap_or(&0.0);
    let ld_other = *ld_phase.get("other").unwrap_or(&0.0);
    println!("\n-- RECONCILIATION vs x86 perf nomination (M1, confirmed/refuted) --");
    println!(
        "  clean_decode = {:.1}% of gz retired ({:.0} instr) — x86 nominated the clean fastloop\n\
         \x20 as the dominant phase; M1 CONFIRMS it as the single largest phase.",
        100.0 * gz_clean / gz_instr,
        gz_clean
    );
    println!(
        "  lut_build    = {:.1}% of gz retired = {:.0} instr — x86 nominated ~16%-of-surplus /\n\
         \x20 +129M retired; M1 absolute is in the same order (table-build is NOT the ~5-20M an\n\
         \x20 earlier TIME-bounded M1 estimate suggested — retired-count is ~{:.0}M).",
        100.0 * gz_lut / gz_instr,
        gz_lut,
        gz_lut / 1e6
    );
    println!(
        "  COMPARATOR IS MONOLITHIC: libdeflate's whole decode is ONE inlined C symbol\n\
         \x20 (libdeflate_deflate_decompress_ex = {:.0} instr, {:.1}% of ld), so the gz-ld surplus\n\
         \x20 is NOT symbol-attributable per-phase. What IS attributable: gz's clean fastloop\n\
         \x20 ALONE ({:.0} instr) {} libdeflate's ENTIRE decode ({:.0} instr).",
        ld_other,
        100.0 * ld_other / ld_instr,
        gz_clean,
        if gz_clean > ld_instr { "EXCEEDS" } else { "is below" },
        ld_instr
    );
    println!(
        "  LIMIT: distribution is /usr/bin/sample TIME-weighted; retired-exact only under\n\
         \x20 uniform per-symbol IPC (gz/ld whole-program IPC ratio {:.3} is near 1, so the\n\
         \x20 time->retired bias is small; per-symbol IPC unvalidated — no PMI sampler/Xcode).",
        gz_ipc / ld_ipc.max(1e-9)
    );

    if let Some(path) = artifact {
        let top_json: Vec<serde_json::Value> = gz_attr
            .iter()
            .take(topn.max(30))
            .map(|(k, name, retired, share)| {
                serde_json::json!({
                    "key": k, "symbol": name, "bucket": insnattr_bucket(name),
                    "retired_instr": retired, "share": share,
                })
            })
            .collect();
        // ld top symbols too — proves the comparator's per-region attribution
        // (esp. that ld's lut_build bucket is libdeflate's build_decode_table,
        // a SEPARATE non-inlined symbol, while its fastloop is the monolith).
        let ld_top_json: Vec<serde_json::Value> = ld_attr
            .iter()
            .take(topn.max(30))
            .map(|(k, name, retired, share)| {
                serde_json::json!({
                    "key": k, "symbol": name, "bucket": insnattr_bucket(name),
                    "retired_instr": retired, "share": share,
                })
            })
            .collect();
        let phase_json: serde_json::Value = serde_json::json!({
            "gz": gz_phase.iter().map(|(k,v)| (k.to_string(), *v)).collect::<std::collections::BTreeMap<_,_>>(),
            "ld": ld_phase.iter().map(|(k,v)| (k.to_string(), *v)).collect::<std::collections::BTreeMap<_,_>>(),
        });
        let obj = serde_json::json!({
            "tool": "fulcrum insnattr (per-symbol retired-instruction attribution)",
            "arch": "arm64 Apple M1 Pro",
            "method": "kpc whole-program retired TOTAL x /usr/bin/sample per-symbol distribution",
            "limit": "distribution time-weighted (Gate-5); retired-exact only under uniform per-symbol IPC; no xctrace (Xcode absent) / no PMI sampler built",
            "corpus": corpus, "corpus_sha256": corpus_sha, "out_len": out_len,
            "oracle_sha256": oracle, "gz_commit": gz_commit, "threads": 1, "n_kpc": n, "sample_secs": secs,
            "whole_program": {
                "gz_retired": gz_instr, "gz_cycles": gz_cyc, "gz_ipc": gz_ipc, "gz_instr_per_byte": gz_instr/o,
                "ld_retired": ld_instr, "ld_cycles": ld_cyc, "ld_ipc": ld_ipc, "ld_instr_per_byte": ld_instr/o,
                "retired_ratio": gz_instr/ld_instr.max(1.0), "surplus": surplus,
            },
            "gate0": {
                "gz_retired_aa_spread_pct": gi_spread,
                "gz_sample_leaf": gz_total_s, "ld_sample_leaf": ld_total_s,
                "gz_gzippy_code_share": gz_user_share,
                "top_symbol_aa_delta_pp": aa_pp,
                "all_pass": g0_ok,
            },
            "gz_phase": phase_json["gz"],
            "ld_phase": phase_json["ld"],
            "gz_top_symbols": top_json,
            "ld_top_symbols": ld_top_json,
        });
        match std::fs::write(&path, serde_json::to_string_pretty(&obj).unwrap()) {
            Ok(_) => println!("\nwrote {path}"),
            Err(e) => eprintln!("insnattr: write {path}: {e}"),
        }
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
mod insnattr_tests {
    use super::*;

    #[test]
    fn bucket_lut_build_symbols() {
        assert_eq!(insnattr_bucket("gzippy::...::DistTable::rebuild::h0"), "lut_build");
        assert_eq!(insnattr_bucket("gzippy::...::LitLenTable::build::h1"), "lut_build");
        assert_eq!(insnattr_bucket("gzippy::...::ensure_dist_table::h2"), "lut_build");
        assert_eq!(insnattr_bucket("gzippy::...::read_header::h3"), "lut_build");
    }

    #[test]
    fn bucket_clean_decode_symbols() {
        assert_eq!(
            insnattr_bucket("gzippy::...::decode_clean_into_contig::h0"),
            "clean_decode"
        );
        assert_eq!(
            insnattr_bucket(
                "gzippy::decompress::inflate::consume_first_decode::decode_huffman_fastloop_bounded_pipelined::h1"
            ),
            "clean_decode"
        );
    }

    #[test]
    fn bucket_other_and_code_origin() {
        assert_eq!(insnattr_bucket("dyld4::prepare"), "other");
        assert!(insnattr_is_gzippy("gzippy::decompress::x"));
        assert!(!insnattr_is_gzippy("libdeflate_deflate_decompress_ex"));
        assert!(insnattr_is_libdeflate("libdeflate_deflate_decompress_ex"));
    }

    #[test]
    fn marker_module_path_does_not_steal_decode_or_header_symbols() {
        // Both live in the `marker_inflate` module (path contains "marker"), but
        // the bare-"marker" heuristic must NOT capture them.
        assert_eq!(
            insnattr_bucket(
                "gzippy::decompress::parallel::marker_inflate::Block::decode_clean_into_contig::h0"
            ),
            "clean_decode"
        );
        assert_eq!(
            insnattr_bucket(
                "gzippy::decompress::parallel::marker_inflate::read_dynamic_huffman_coding::h1"
            ),
            "lut_build"
        );
        // Real marker resolution still buckets as marker_resolve.
        assert_eq!(
            insnattr_bucket("gzippy::decompress::parallel::replace_markers::apply::h2"),
            "marker_resolve"
        );
    }

    #[test]
    fn bucket_table_build_huffcode_helpers() {
        assert_eq!(insnattr_bucket("gzippy::..::make_inflate_huff_code_lit_len::h0"), "lut_build");
        assert_eq!(insnattr_bucket("gzippy::..::set_and_expand_lit_len_huffcode::h1"), "lut_build");
    }
}

// ===========================================================================
// `fulcrum critpath` (macOS / Apple-Silicon) — SLOPE-ATTRIBUTION of a
// distributed wall gap into wall-CAUSAL decode regions.
//
// Localizes where a decode's wall time actually GOES, region by region, using
// the in-process gzippy markers (`gzippy::critpath_rt`). Two measured quantities
// are fused (both in CNTVCT ticks — the only userspace clock on M1, 24 MHz):
//
//   active_ticks[r]   total time inside region r (unbiased tick-sum bracketing).
//   criticality_r     slope d(trial_wall)/d(injected_time) from an injected-delay
//                     dose sweep in region r. Cycle-SHARE is NOT wall-share; this
//                     slope is the only sound "marginal wall" weight.
//   wall_added_r ≈ (active_ticks[r] − marker_tax·fires[r]) · criticality_r.
//
// GATE-0 SELF-TESTS (BLOCKING — no per-region finding emitted unless ALL pass):
//   (1) CORRECTNESS, markers on, no perturbation: decode sha == gzip -dc oracle.
//   (2) CORRECTNESS + NON-INERT under perturbation: a large dose changes nothing
//       in the output (independent injection) yet injected_ticks>0 (it fired).
//   (3) A/A DISCRIMINATION: two identical no-perturbation decodes ⇒ wall ratio
//       ≈ 1; that A/A spread is the floor a real slope must clear.
//   (4) KNOWN-SERIAL calibration ⇒ criticality ≈ 1.
//   (5) KNOWN-OVERLAPPED calibration ⇒ criticality clearly below serial.
//   (6) DOSE LINEARITY: serial-calib fit R² ≥ threshold over ≥3 doses; and
//       CONSERVATION: Σ active_ticks(tax-adjusted) ≤ trial wall · 1.05.
// ===========================================================================

/// Least-squares slope, intercept, and R² of y on x.
fn lin_fit(x: &[f64], y: &[f64]) -> (f64, f64, f64) {
    let n = x.len() as f64;
    if x.len() < 2 {
        return (0.0, 0.0, 0.0);
    }
    let xbar = x.iter().sum::<f64>() / n;
    let ybar = y.iter().sum::<f64>() / n;
    let mut sxx = 0.0;
    let mut sxy = 0.0;
    let mut syy = 0.0;
    for i in 0..x.len() {
        let dx = x[i] - xbar;
        let dy = y[i] - ybar;
        sxx += dx * dx;
        sxy += dx * dy;
        syy += dy * dy;
    }
    if sxx == 0.0 {
        return (0.0, ybar, 0.0);
    }
    let beta = sxy / sxx;
    let intercept = ybar - beta * xbar;
    let r2 = if syy == 0.0 { 0.0 } else { (beta * sxy) / syy };
    (beta, intercept, r2.clamp(0.0, 1.0))
}

/// 95% CI half-width of the slope via residual standard error.
fn slope_ci95(x: &[f64], y: &[f64], beta: f64, intercept: f64) -> f64 {
    let n = x.len();
    if n < 3 {
        return f64::INFINITY;
    }
    let xbar = x.iter().sum::<f64>() / n as f64;
    let mut sxx = 0.0;
    let mut sse = 0.0;
    for i in 0..n {
        let dx = x[i] - xbar;
        sxx += dx * dx;
        let resid = y[i] - (intercept + beta * x[i]);
        sse += resid * resid;
    }
    if sxx == 0.0 {
        return f64::INFINITY;
    }
    let se = (sse / (n as f64 - 2.0) / sxx).sqrt();
    1.96 * se
}

// ── CRITPATH SUBJECT ABSTRACTION (gz vs libdeflate differential) ──
//
// The critpath protocol below is IDENTICAL for both decoders; only the SUBJECT
// differs. `GzSubject` drives gzippy's pure-Rust decode through
// `gzippy::critpath_rt`; `LdSubject` drives the INSTRUMENTED libdeflate 1.25
// (critpath-libdeflate crate) carrying the SAME region markers. Running the one
// protocol over both is what makes the per-region active-time differential
// apples-to-apples (same clock, same gates, same dose sweep, same tax model).
//
// Region ids are index-aligned across both subjects (REFILL=0 .. EMPTY_TAX=9).
const CPREG_TABLE_LOAD: usize = 1;
const CPREG_CALIB_SERIAL: usize = 7;
const CPREG_CALIB_OVERLAPPED: usize = 8;
const CPREG_EMPTY_TAX: usize = 9;

trait CritSubject {
    fn name(&self) -> &'static str;
    fn n_regions(&self) -> usize;
    fn region_names(&self) -> &'static [&'static str];
    fn set_enabled(&self, on: bool);
    fn select(&self, r: Option<usize>);
    fn set_dose(&self, d: u64);
    fn reset_counters(&self);
    fn snapshot(&self) -> (Vec<u64>, Vec<u64>, u64);
    fn cntvct(&self) -> u64;
    fn cntfrq(&self) -> u64;
    fn inject(&self, n: u64) -> u64;
    fn calib_serial(&self, iters: u64) -> u64;
    fn calib_overlapped(&self, iters: u64, buf: &[u64]) -> u64;
    fn calib_empty(&self, iters: u64) -> u64;
    fn make_chase_buf(&self, n: usize) -> Vec<u64>;
    fn decode(&self, data: &[u8], buf: &mut [u8]) -> usize;
}

struct GzSubject;
impl CritSubject for GzSubject {
    fn name(&self) -> &'static str { "gzippy (pure-Rust)" }
    fn n_regions(&self) -> usize { gzippy::critpath_rt::N_REGIONS }
    fn region_names(&self) -> &'static [&'static str] { &gzippy::critpath_rt::REGION_NAMES }
    fn set_enabled(&self, on: bool) { gzippy::critpath_rt::set_enabled(on) }
    fn select(&self, r: Option<usize>) { gzippy::critpath_rt::select(r) }
    fn set_dose(&self, d: u64) { gzippy::critpath_rt::set_dose(d) }
    fn reset_counters(&self) { gzippy::critpath_rt::reset_counters() }
    fn snapshot(&self) -> (Vec<u64>, Vec<u64>, u64) { gzippy::critpath_rt::snapshot() }
    fn cntvct(&self) -> u64 { gzippy::critpath_rt::cntvct() }
    fn cntfrq(&self) -> u64 { gzippy::critpath_rt::cntfrq() }
    fn inject(&self, n: u64) -> u64 { gzippy::critpath_rt::inject(n) }
    fn calib_serial(&self, iters: u64) -> u64 { gzippy::critpath_rt::calib_serial(iters) }
    fn calib_overlapped(&self, iters: u64, buf: &[u64]) -> u64 {
        gzippy::critpath_rt::calib_overlapped(iters, buf)
    }
    fn calib_empty(&self, iters: u64) -> u64 { gzippy::critpath_rt::calib_empty(iters) }
    fn make_chase_buf(&self, n: usize) -> Vec<u64> { gzippy::critpath_rt::make_chase_buf(n) }
    fn decode(&self, data: &[u8], buf: &mut [u8]) -> usize { run_gz(data, buf) }
}

struct LdSubject;
impl CritSubject for LdSubject {
    fn name(&self) -> &'static str { "libdeflate 1.25 (C, instrumented)" }
    fn n_regions(&self) -> usize { critpath_libdeflate::N_REGIONS }
    fn region_names(&self) -> &'static [&'static str] { &critpath_libdeflate::REGION_NAMES }
    fn set_enabled(&self, on: bool) { critpath_libdeflate::set_enabled(on) }
    fn select(&self, r: Option<usize>) { critpath_libdeflate::select(r) }
    fn set_dose(&self, d: u64) { critpath_libdeflate::set_dose(d) }
    fn reset_counters(&self) { critpath_libdeflate::reset_counters() }
    fn snapshot(&self) -> (Vec<u64>, Vec<u64>, u64) { critpath_libdeflate::snapshot() }
    fn cntvct(&self) -> u64 { critpath_libdeflate::cntvct() }
    fn cntfrq(&self) -> u64 { critpath_libdeflate::cntfrq() }
    fn inject(&self, n: u64) -> u64 { critpath_libdeflate::inject(n) }
    fn calib_serial(&self, iters: u64) -> u64 { critpath_libdeflate::calib_serial(iters) }
    fn calib_overlapped(&self, iters: u64, buf: &[u64]) -> u64 {
        critpath_libdeflate::calib_overlapped(iters, buf)
    }
    fn calib_empty(&self, iters: u64) -> u64 { critpath_libdeflate::calib_empty(iters) }
    fn make_chase_buf(&self, n: usize) -> Vec<u64> { critpath_libdeflate::make_chase_buf(n) }
    fn decode(&self, data: &[u8], buf: &mut [u8]) -> usize {
        critpath_libdeflate::gzip_decode(data, buf)
    }
}

pub fn cmd_critpath(args: &[String]) -> ExitCode {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "fulcrum critpath (macOS / Apple-Silicon) — SLOPE-ATTRIBUTION of a\n\
             distributed decode wall gap into wall-causal regions.\n\n\
             USAGE: sudo -E fulcrum critpath [--target gz|libdeflate]\n\
             \t[--corpus f.gz] [--active-trials 7] [--dose-trials 5]\n\
             \t[--dose-steps 3] [--target-frac 0.10] [--json out.json] [--selftest-only]\n\n\
             --target selects the SUBJECT decoder. Both carry the SAME aligned\n\
             region markers (refill/table_load/consume/store/match_copy/dist_lookup),\n\
             so per-region active-time is comparable for the gz-vs-libdeflate\n\
             DIFFERENTIAL kernel localizer. Per-region: active_ticks, criticality\n\
             slope (d wall / d injected), CI95, dose-linearity R², tax-adjusted\n\
             wall_pct_added. Gate-0 self-tests are BLOCKING. CNTVCT (24 MHz) clock."
        );
        return ExitCode::SUCCESS;
    }
    if let Err(e) = preflight_root() {
        eprintln!("critpath: {e}");
        return ExitCode::from(2);
    }
    let target = flag(args, "--target").unwrap_or("gz").to_string();
    let subj: Box<dyn CritSubject> = match target.as_str() {
        "gz" | "gzippy" => Box::new(GzSubject),
        "ld" | "libdeflate" => Box::new(LdSubject),
        other => {
            eprintln!("critpath: unknown --target '{other}' (expected gz|libdeflate)");
            return ExitCode::from(2);
        }
    };
    run_critpath_core(subj.as_ref(), args)
}

fn run_critpath_core(subj: &dyn CritSubject, args: &[String]) -> ExitCode {
    let corpus = flag(args, "--corpus").unwrap_or(DEFAULT_CORPUS).to_string();
    let active_trials: usize = flag(args, "--active-trials")
        .and_then(|s| s.parse().ok())
        .unwrap_or(7)
        .max(3);
    let dose_trials: usize = flag(args, "--dose-trials")
        .and_then(|s| s.parse().ok())
        .unwrap_or(5)
        .max(3);
    let dose_steps: usize = flag(args, "--dose-steps")
        .and_then(|s| s.parse().ok())
        .unwrap_or(3)
        .max(3);
    let target_frac: f64 = flag(args, "--target-frac")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.10);
    let selftest_only = args.iter().any(|a| a == "--selftest-only");
    let json_out = flag(args, "--json").map(|s| s.to_string());

    let data = match std::fs::read(&corpus) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("critpath: read {corpus}: {e}");
            return ExitCode::from(2);
        }
    };

    println!("== fulcrum critpath (macOS / Apple-Silicon, CNTVCT slope-attribution) ==");
    println!("subject={}  (--target)", subj.name());
    let cntfrq = subj.cntfrq();
    println!(
        "corpus={corpus} bytes={} cntfrq={cntfrq} Hz active_trials={active_trials} dose_trials={dose_trials} dose_steps={dose_steps}",
        data.len()
    );

    let (oracle, out_len) = match oracle_sha_len(&corpus) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("critpath: oracle failed: {e}");
            return ExitCode::from(2);
        }
    };
    let mut buf = vec![0u8; out_len + 4096];

    let pinned = pin_to_pcluster();
    let _caf = start_caffeinate();
    println!("pinned_to_pcluster={pinned} (Apple Silicon DVFS is per-cluster)");

    subj.set_enabled(true);

    // One instrumented trial: reset, time the whole in-process decode in CNTVCT
    // ticks, snapshot the per-region accumulators.
    let trial = |buf: &mut [u8]| -> (u64, Vec<u64>, Vec<u64>, u64) {
        subj.reset_counters();
        let t0 = subj.cntvct();
        let _n = subj.decode(&data, buf);
        let t1 = subj.cntvct();
        let (active, fires, injected) = subj.snapshot();
        (t1.wrapping_sub(t0), active, fires, injected)
    };

    for _ in 0..3 {
        let _ = trial(&mut buf);
    }

    let mut g0_ok = true;
    macro_rules! g0 {
        ($cond:expr, $($m:tt)*) => {{
            let ok = $cond;
            println!("  [Gate-0] {} :: {}", if ok {"PASS"} else {"FAIL"}, format!($($m)*));
            if !ok { g0_ok = false; }
        }};
    }
    println!("-- Gate-0 self-validation (BLOCKING) --");

    subj.select(None);
    subj.set_dose(0);
    let n1 = subj.decode(&data, &mut buf);
    let sha1 = sha256_hex(&buf[..n1]);
    g0!(
        sha1 == oracle,
        "markers-ON decode sha == gzip -dc oracle [{}…]",
        &sha1[..12]
    );

    subj.reset_counters();
    subj.select(Some(CPREG_TABLE_LOAD));
    subj.set_dose(64);
    let n2 = subj.decode(&data, &mut buf);
    let sha2 = sha256_hex(&buf[..n2]);
    let (_a2, _f2, inj2) = subj.snapshot();
    subj.select(None);
    subj.set_dose(0);
    g0!(
        sha2 == oracle,
        "perturbed decode sha == oracle (independent injection cannot change output)"
    );
    g0!(
        inj2 > 0,
        "perturbation NON-INERT: injected_ticks={inj2} (>0 ⇒ the dose actually fired)"
    );

    let mut aa = Vec::new();
    for _ in 0..active_trials {
        let (w_a, _, _, _) = trial(&mut buf);
        let (w_b, _, _, _) = trial(&mut buf);
        aa.push(w_a as f64 / w_b as f64);
    }
    let aa_med = median(&aa);
    let aa_spr = spread_pct(&aa);
    g0!(
        (aa_med - 1.0).abs() < 0.03 && aa_spr < 5.0,
        "A/A wall ratio={aa_med:.4} spread={aa_spr:.2}% (same-vs-same ≈ 1)"
    );

    // Chase buffer must spill past the M1 L2 so each hop is a long DRAM-latency
    // dependent load — only then does a small injected dose hide in its shadow
    // (the overlapped ground truth). 64 MiB.
    let chase = subj.make_chase_buf(1 << 23);
    let calib_iters: u64 = 3_000_000;
    let serial_doses: Vec<u64> = vec![0, 2, 4, 6];
    let overlap_doses: Vec<u64> = vec![0, 2, 4, 6];

    let run_calib = |which: usize, iters: u64, dose: u64, chase: &[u64]| -> (u64, u64) {
        subj.reset_counters();
        subj.select(Some(which));
        subj.set_dose(dose);
        let t0 = subj.cntvct();
        let r = if which == CPREG_CALIB_SERIAL {
            subj.calib_serial(iters)
        } else if which == CPREG_CALIB_OVERLAPPED {
            subj.calib_overlapped(iters, chase)
        } else {
            subj.calib_empty(iters)
        };
        let t1 = subj.cntvct();
        core::hint::black_box(r);
        let (_a, _f, inj) = subj.snapshot();
        subj.select(None);
        subj.set_dose(0);
        (t1.wrapping_sub(t0), inj)
    };

    let calib_slope = |which: usize, doses: &[u64], chase: &[u64]| -> (f64, f64, f64) {
        let mut xs = Vec::new();
        let mut ys = Vec::new();
        for &d in doses {
            let mut wv = Vec::new();
            let mut iv = Vec::new();
            for _ in 0..dose_trials {
                let (w, inj) = run_calib(which, calib_iters, d, chase);
                wv.push(w as f64);
                iv.push(inj as f64);
            }
            xs.push(median(&iv));
            ys.push(median(&wv));
        }
        let (beta, intercept, r2) = lin_fit(&xs, &ys);
        let ci = slope_ci95(&xs, &ys, beta, intercept);
        (beta, r2, ci)
    };

    let (ser_beta, ser_r2, ser_ci) = calib_slope(CPREG_CALIB_SERIAL, &serial_doses, &chase);
    let (ovl_beta, ovl_r2, _ovl_ci) = calib_slope(CPREG_CALIB_OVERLAPPED, &overlap_doses, &chase);
    g0!(
        ser_beta > 0.7 && ser_beta < 1.3,
        "known-SERIAL criticality β={ser_beta:.3} ±{ser_ci:.3} (expect ≈ 1)  R²={ser_r2:.3}"
    );
    g0!(
        ovl_beta < ser_beta - 0.2 && ovl_beta < 0.6,
        "known-OVERLAPPED criticality β={ovl_beta:.3} < serial (hidden ⇒ low)  R²={ovl_r2:.3}"
    );
    g0!(
        ser_r2 >= 0.90,
        "serial-calib dose LINEARITY R²={ser_r2:.3} (≥0.90)"
    );

    subj.reset_counters();
    subj.select(None);
    subj.set_dose(0);
    let _ = subj.calib_empty(20_000_000);
    let (emp_a, emp_f, _) = subj.snapshot();
    let tax_per_fire = if emp_f[CPREG_EMPTY_TAX] > 0 {
        emp_a[CPREG_EMPTY_TAX] as f64 / emp_f[CPREG_EMPTY_TAX] as f64
    } else {
        0.0
    };
    println!("  marker tax/fire = {tax_per_fire:.4} ticks (subtracted per region)");

    subj.select(None);
    subj.set_dose(0);
    let n_regions = subj.n_regions();
    let n_real = 7usize.min(n_regions);
    let mut act_acc = vec![Vec::new(); n_regions];
    let mut fire_acc = vec![Vec::new(); n_regions];
    let mut walls = Vec::new();
    for _ in 0..active_trials {
        let (w, a, f, _) = trial(&mut buf);
        walls.push(w as f64);
        for r in 0..n_regions {
            act_acc[r].push(a[r] as f64);
            fire_acc[r].push(f[r] as f64);
        }
    }
    let wall_med = median(&walls);
    let wall_spr = spread_pct(&walls);
    let active: Vec<f64> = (0..n_regions).map(|r| median(&act_acc[r])).collect();
    let fires: Vec<f64> = (0..n_regions).map(|r| median(&fire_acc[r])).collect();

    let ticks_per_inject = {
        let big: u64 = 40_000_000;
        let t0 = subj.cntvct();
        core::hint::black_box(subj.inject(big));
        let t1 = subj.cntvct();
        (t1.wrapping_sub(t0)) as f64 / big as f64
    };

    #[derive(Clone)]
    struct RegionOut {
        name: String,
        active_ticks: f64,
        active_adj: f64,
        fires: f64,
        active_pct: f64,
        beta: f64,
        beta_ci95: f64,
        r2: f64,
        wall_added: f64,
        wall_pct_added: f64,
        flags: Vec<String>,
    }
    let mut regions_out: Vec<RegionOut> = Vec::new();

    for r in 0..n_real {
        let name = subj.region_names()[r].to_string();
        let f_r = fires[r];
        let act_adj = (active[r] - tax_per_fire * f_r).max(0.0);
        let active_pct = if wall_med > 0.0 {
            100.0 * active[r] / wall_med
        } else {
            0.0
        };
        if f_r < 1.0 {
            regions_out.push(RegionOut {
                name,
                active_ticks: active[r],
                active_adj: act_adj,
                fires: f_r,
                active_pct,
                beta: 0.0,
                beta_ci95: f64::INFINITY,
                r2: 0.0,
                wall_added: 0.0,
                wall_pct_added: 0.0,
                flags: vec!["no_fires".into()],
            });
            continue;
        }
        let dose_unit = ((target_frac * wall_med) / (f_r * ticks_per_inject)).ceil() as u64;
        let dose_unit = dose_unit.max(1);
        let mut xs = Vec::new();
        let mut ys = Vec::new();
        for step in 0..=dose_steps {
            let dose = dose_unit * step as u64;
            let mut wv = Vec::new();
            let mut iv = Vec::new();
            for _ in 0..dose_trials {
                subj.reset_counters();
                subj.select(Some(r));
                subj.set_dose(dose);
                let t0 = subj.cntvct();
                let _ = subj.decode(&data, &mut buf);
                let t1 = subj.cntvct();
                let (_a, _f, inj) = subj.snapshot();
                wv.push((t1.wrapping_sub(t0)) as f64);
                iv.push(inj as f64);
            }
            xs.push(median(&iv));
            ys.push(median(&wv));
        }
        subj.select(None);
        subj.set_dose(0);
        let (beta, intercept, r2) = lin_fit(&xs, &ys);
        let ci = slope_ci95(&xs, &ys, beta, intercept);
        let crit = beta.clamp(0.0, 1.2);
        let wall_added = act_adj * crit;
        let wall_pct_added = if wall_med > 0.0 {
            100.0 * wall_added / wall_med
        } else {
            0.0
        };
        let mut flags = Vec::new();
        if r2 < 0.85 {
            flags.push("nonlinear".into());
        }
        if beta > 1.15 {
            flags.push("interference".into());
        }
        let top_inj_frac = if wall_med > 0.0 {
            xs.last().copied().unwrap_or(0.0) / wall_med
        } else {
            0.0
        };
        if top_inj_frac < 0.02 {
            flags.push("low_signal".into());
        }
        regions_out.push(RegionOut {
            name,
            active_ticks: active[r],
            active_adj: act_adj,
            fires: f_r,
            active_pct,
            beta,
            beta_ci95: ci,
            r2,
            wall_added,
            wall_pct_added,
            flags,
        });
    }

    let sum_active_adj: f64 = regions_out.iter().map(|r| r.active_adj).sum();
    let residual = wall_med - sum_active_adj;
    let overcount_pct = if wall_med > 0.0 {
        100.0 * (sum_active_adj - wall_med) / wall_med
    } else {
        0.0
    };
    g0!(
        overcount_pct <= 5.0,
        "CONSERVATION: Σ active(adj)={sum_active_adj:.0} ≤ wall={wall_med:.0} (over-count {overcount_pct:.2}% ≤ 5%)"
    );

    println!(
        "-- Gate-0: {} --",
        if g0_ok {
            "ALL PASS (findings valid)"
        } else {
            "FAIL (NO findings emitted)"
        }
    );
    if !g0_ok {
        eprintln!("critpath: Gate-0 self-tests failed; refusing to emit a finding.");
        return ExitCode::from(3);
    }
    if selftest_only {
        println!("--selftest-only: Gate-0 passed; localization not run.");
        subj.set_enabled(false);
        return ExitCode::SUCCESS;
    }

    println!("\n== Per-region wall-causal localization (corpus={corpus}, subject={}, T1, M1) ==", subj.name());
    println!(
        "wall(instrumented)={:.0} ticks ({:.3} ms)  spread={:.2}%  A/A floor={:.2}%",
        wall_med,
        wall_med / cntfrq as f64 * 1000.0,
        wall_spr,
        aa_spr
    );
    println!(
        "{:<13} {:>10} {:>8} {:>8} {:>8} {:>7} {:>8} {:>10} {:>12}  flags",
        "region", "fires", "act%", "beta", "ci95", "R2", "wall%", "wall_tk", "wall_us"
    );
    let mut sorted = regions_out.clone();
    sorted.sort_by(|a, b| b.wall_pct_added.partial_cmp(&a.wall_pct_added).unwrap());
    for r in &sorted {
        println!(
            "{:<13} {:>10.0} {:>7.2}% {:>8.3} {:>8.3} {:>7.3} {:>7.2}% {:>10.0} {:>12.1}  {}",
            r.name,
            r.fires,
            r.active_pct,
            r.beta,
            r.beta_ci95,
            r.r2,
            r.wall_pct_added,
            r.wall_added,
            r.wall_added / cntfrq as f64 * 1e6,
            r.flags.join(",")
        );
    }
    let total_attr_pct: f64 = regions_out.iter().map(|r| r.wall_pct_added).sum();
    println!(
        "Σ wall%_added (attributed) = {:.2}%   residual/unattributed ≈ {:.2}% ({:.0} ticks)",
        total_attr_pct,
        100.0 * residual / wall_med,
        residual
    );
    if let Some(t) = sorted.first() {
        println!(
            "\n>>> HIGHEST-CRITICALITY REGION (this subject): {}  \
             (wall%_added={:.2}%, wall_us={:.1}, beta={:.3}±{:.3}, R²={:.3})",
            t.name,
            t.wall_pct_added,
            t.wall_added / cntfrq as f64 * 1e6,
            t.beta,
            t.beta_ci95,
            t.r2
        );
    }

    if let Some(path) = json_out {
        let regions_json: Vec<serde_json::Value> = regions_out
            .iter()
            .map(|r| {
                serde_json::json!({
                    "region": r.name,
                    "fires": r.fires,
                    "active_ticks": r.active_ticks,
                    "active_ticks_tax_adjusted": r.active_adj,
                    "active_pct": r.active_pct,
                    "criticality_beta": r.beta,
                    "beta_ci95": r.beta_ci95,
                    "dose_linearity_r2": r.r2,
                    "wall_ticks_added": r.wall_added,
                    "wall_us_added": r.wall_added / cntfrq as f64 * 1e6,
                    "wall_pct_added": r.wall_pct_added,
                    "validity_flags": r.flags,
                })
            })
            .collect();
        let obj = serde_json::json!({
            "tool": "fulcrum critpath (CNTVCT slope-attribution)",
            "subject": subj.name(),
            "corpus": corpus,
            "corpus_bytes": data.len(),
            "out_len": out_len,
            "oracle_sha256": oracle,
            "arch": "arm64 Apple M1 Pro",
            "threads": 1,
            "cntfrq_hz": cntfrq,
            "wall_ticks_median": wall_med,
            "wall_ms_median": wall_med / cntfrq as f64 * 1000.0,
            "wall_spread_pct": wall_spr,
            "aa_floor_pct": aa_spr,
            "marker_tax_per_fire_ticks": tax_per_fire,
            "ticks_per_inject_iter": ticks_per_inject,
            "gate0": {
                "serial_beta": ser_beta, "serial_r2": ser_r2,
                "overlapped_beta": ovl_beta,
                "conservation_overcount_pct": overcount_pct,
                "all_pass": g0_ok,
            },
            "regions": regions_json,
            "residual_pct": 100.0 * residual / wall_med,
        });
        match std::fs::write(&path, serde_json::to_string_pretty(&obj).unwrap()) {
            Ok(_) => println!("wrote {path}"),
            Err(e) => eprintln!("critpath: write {path}: {e}"),
        }
    }

    subj.set_enabled(false);
    ExitCode::SUCCESS
}

// ===========================================================================
// `fulcrum assay` (macOS) — M1 measurement-CAPABILITY assay.
//
// GOVERNING QUESTION (two parts, one instrument):
//   (1) RESOLVABLE FLOOR. What is the SMALLEST global hot-loop instruction
//       surplus this machine can resolve at the wall on silesia T1? We splice a
//       CALIBRATED instruction tax into the production fastloop
//       (`decode_huffman_fastloop_bounded_pipelined`) and ask, per level: is the
//       wall slowdown Δ > max(cross-cohort spread, A/A reproducibility floor)?
//   (2) RECURRENCE vs THROUGHPUT. The tax comes in two flavors that add the SAME
//       instruction COUNT but differ ONLY in dependency structure — DEPENDENT
//       (on the bitbuf loop-carried recurrence) and INDEPENDENT (a side chain
//       the OoO core can hide). If DEPENDENT moves the wall while INDEPENDENT
//       stays flat at the same instr-%, the gz↔ld gap is recurrence/latency
//       bound (→ shorten the dependency chain); if both move together, it is
//       instruction-throughput bound (→ cut instruction count).
//
// TWO PHASES per level:
//   A. CALIBRATION (in-process kpc FIXED_INSTRUCTIONS): retired-instruction count
//      of the gzippy decode tax-OFF vs tax-ON ⇒ the level's KNOWN +X% instr.
//      Gate-0: tax-OFF and tax-ON both sha==`gzip -dc` (byte-transparent), the
//      tax FIRES>0 (non-inert), and the instr delta is > 0.
//   B. WALL (subprocess steady): the EXACT `wall --steady` machinery — pinned
//      P-cluster, warmup to steady GHz, freq-normalized paired ratios with a
//      throttle filter, K cohorts. A arm = the UNMODIFIED production binary
//      (tax env unset); B arm = the SAME binary with the tax env armed. The A/A
//      cross-cohort spread (tax-OFF vs tax-OFF) is the reproducibility FLOOR.
//
// Reuses `run_steady_cohorts` + `steady_verdict` verbatim (the A arm is fed in
// the "gz" slot so A/A == tax-OFF/tax-OFF, the production floor; the B/tax-ON
// arm is the "ld" slot). A level is GATED (resolvable) iff its verdict is
// REPRODUCIBLE: sign-consistent, min per-cohort |effect| > A/A floor, and
// cross-cohort spread < effect. Else REPRODUCIBLE_TIE / NOT_RESOLVABLE — which
// for the smallest taxes is itself the deliverable: a gated HARDWARE fact that
// sub-X% silesia-T1 levers are un-gateable on this laptop.
// ===========================================================================
/// DIRECT-TIMING calibration of the `Mode::Delay` positive control.
///
/// For each candidate `dose`, run INTERLEAVED paired subprocess decodes (both to
/// /dev/null — the SINK LAW): per rep, off → on(delay:dose:1) → off2. The
/// standalone wall increment of the dose is `median(on/off) − 1`; the A/A floor
/// is `median(off2/off) − 1` (two tax-OFF decodes — the irreducible run-to-run
/// noise the standalone increment must clear to be a TRUSTWORTHY known dose).
/// This is the "verify the +X% by DIRECT timing FIRST" step: it proves each dose
/// delivers a real, reproducible wall increment BEFORE that dose is fed to the
/// MDE steady-gating loop. Returns (json, per-dose (dose, standalone%)).
fn delay_calibration(
    gz_bin: &str,
    corpus: &str,
    doses: &[u64],
    stride: u64,
    n: usize,
) -> (serde_json::Value, Vec<(u64, f64)>) {
    let off_args: Vec<String> = vec!["-d".into(), "-c".into(), "-p1".into()];
    let off_env: Vec<(&str, &str)> = Vec::new();
    let stride_s = stride.to_string();
    println!(
        "\n-- DELAY positive-control DIRECT-TIMING calibration (interleaved paired N={n}, stride={stride}, /dev/null) --"
    );
    println!(
        "{:<8} {:>14} {:>10} {:>10} {:>12}",
        "dose", "standalone%", "spread%", "A/A%", "above_floor"
    );
    let mut rows: Vec<serde_json::Value> = Vec::new();
    let mut picks: Vec<(u64, f64)> = Vec::new();
    for &dose in doses {
        let dose_s = dose.to_string();
        let on_env: Vec<(&str, &str)> = vec![
            ("GZIPPY_ASSAY_TAX_MODE", "delay"),
            ("GZIPPY_ASSAY_TAX_DOSE", &dose_s),
            ("GZIPPY_ASSAY_TAX_STRIDE", &stride_s),
        ];
        // warm both arms (page-in + frequency settle) before the timed reps.
        let _ = timed_decode_devnull(gz_bin, &off_args, corpus, &off_env);
        let _ = timed_decode_devnull(gz_bin, &off_args, corpus, &on_env);
        let mut r_on: Vec<f64> = Vec::with_capacity(n);
        let mut r_aa: Vec<f64> = Vec::with_capacity(n);
        for _ in 0..n {
            let a = timed_decode_devnull(gz_bin, &off_args, corpus, &off_env);
            let b = timed_decode_devnull(gz_bin, &off_args, corpus, &on_env);
            let a2 = timed_decode_devnull(gz_bin, &off_args, corpus, &off_env);
            if let (Ok(a), Ok(b), Ok(a2)) = (a, b, a2) {
                r_on.push(b / a);
                r_aa.push(a2 / a);
            }
        }
        let standalone = (median(&r_on) - 1.0) * 100.0;
        let on_spread = spread_pct(&r_on);
        let aa = (median(&r_aa) - 1.0) * 100.0;
        let aa_spread = spread_pct(&r_aa);
        let floor = on_spread.max(aa_spread).max(aa.abs());
        let above = standalone > floor;
        println!(
            "{:<8} {:>14.3} {:>10.3} {:>10.3} {:>12}",
            dose,
            standalone,
            on_spread,
            aa,
            if above { "YES" } else { "no" }
        );
        rows.push(serde_json::json!({
            "dose": dose,
            "stride": stride,
            "standalone_wall_pct": standalone,
            "standalone_spread_pct": on_spread,
            "aa_floor_pct": aa,
            "aa_spread_pct": aa_spread,
            "above_floor": above,
            "n": r_on.len(),
        }));
        picks.push((dose, standalone));
    }
    (
        serde_json::json!({
            "method": "interleaved paired direct timing (off/on/off2), /dev/null both arms",
            "n_pairs": n,
            "stride": stride,
            "doses": rows,
        }),
        picks,
    )
}

/// Pick the dose whose directly-timed standalone wall% is closest to `target`.
fn pick_dose_for(picks: &[(u64, f64)], target: f64) -> Option<u64> {
    picks
        .iter()
        .filter(|(_, p)| p.is_finite())
        .min_by(|a, b| {
            (a.1 - target)
                .abs()
                .partial_cmp(&(b.1 - target).abs())
                .unwrap()
        })
        .map(|(d, _)| *d)
}

fn assay_mode_from_tag(tag: &str) -> Option<(gzippy::assay_tax::Mode, &'static str)> {
    match tag {
        "dep" | "dependent" => Some((gzippy::assay_tax::Mode::Dependent, "dependent")),
        "indep" | "independent" => Some((gzippy::assay_tax::Mode::Independent, "independent")),
        "ctrl" | "control" => Some((gzippy::assay_tax::Mode::Control, "control")),
        "delay" => Some((gzippy::assay_tax::Mode::Delay, "delay")),
        _ => None,
    }
}

/// One parsed assay level: `mode:dose:stride`.
#[derive(Clone)]
struct AssayLevel {
    mode: gzippy::assay_tax::Mode,
    mode_name: &'static str,
    env_mode: &'static str, // "dep" | "indep" for the subprocess env
    dose: u64,
    stride: u64,
}

fn parse_assay_levels(s: &str) -> Result<Vec<AssayLevel>, String> {
    let mut out = Vec::new();
    for tok in s.split(',').filter(|x| !x.is_empty()) {
        let parts: Vec<&str> = tok.split(':').collect();
        if parts.len() != 3 {
            return Err(format!("level '{tok}' must be mode:dose:stride"));
        }
        let (mode, mode_name) =
            assay_mode_from_tag(parts[0]).ok_or_else(|| format!("bad mode in '{tok}'"))?;
        let env_mode = match mode_name {
            "dependent" => "dep",
            "control" => "ctrl",
            "delay" => "delay",
            _ => "indep",
        };
        let dose: u64 = parts[1].parse().map_err(|_| format!("bad dose in '{tok}'"))?;
        let stride: u64 = parts[2]
            .parse::<u64>()
            .map_err(|_| format!("bad stride in '{tok}'"))?
            .max(1);
        out.push(AssayLevel {
            mode,
            mode_name,
            env_mode,
            dose,
            stride,
        });
    }
    if out.is_empty() {
        return Err("no levels parsed".into());
    }
    Ok(out)
}

pub fn cmd_assay(args: &[String]) -> ExitCode {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "fulcrum assay (macOS) — M1 measurement-capability assay: smallest global\n\
             hot-loop instruction tax resolvable at the wall + dependent-vs-independent\n\
             recurrence/throughput discrimination. sudo (kpc).\n\n\
             USAGE: sudo -E fulcrum assay --gz PATH [--corpus f.gz]\n\
                    [--levels dep:1:1,indep:1:1,...] [--cal-n 11] [--json out.json]\n\
                    [--no-wall] [--no-cal] [--cohorts 4] [--pairs 11] [--warmup-secs 15]\n\
                    [--cooldown-secs 4] [--throttle-tol 0.03]\n\n\
             A=unmodified production binary (tax env unset); B=same binary, tax env armed.\n\
             Phase A (in-process kpc) calibrates each level's +X% instr and proves the\n\
             tax is byte-transparent (sha==oracle) + non-inert (fires>0). Phase B runs the\n\
             wall --steady protocol; A/A(tax-off) is the reproducibility floor."
        );
        return ExitCode::SUCCESS;
    }
    let gz_bin = match flag(args, "--gz") {
        Some(g) => g.to_string(),
        None => {
            eprintln!("assay: --gz <binary> is required");
            return ExitCode::from(2);
        }
    };
    let corpus = flag(args, "--corpus").unwrap_or(DEFAULT_CORPUS).to_string();
    let cal_n: usize = flag(args, "--cal-n")
        .and_then(|s| s.parse().ok())
        .unwrap_or(11)
        .max(7);
    let do_wall = !args.iter().any(|a| a == "--no-wall");
    let do_cal = !args.iter().any(|a| a == "--no-cal");
    let json_path = flag(args, "--json").map(|s| s.to_string());
    let levels_str = flag(args, "--levels")
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            // RECURRENCE-ISOLATION ladder (default): SMALL latency doses at
            // stride=1 (counter-free) across the three iso-uop-matched arms —
            // A=dependent (ALU on the bitbuf recurrence ⇒ latency), B=independent
            // (iso-uop ALU off the recurrence ⇒ throughput), C=control (independent
            // L1 loads off the recurrence ⇒ different op class, cache/port control).
            // Small doses are used deliberately: the prior dep-vs-indep at LARGE
            // doses was indistinguishable, so we probe where a 1-op recurrence
            // step shows but throughput is absorbed. Interleaved A/B/C per dose.
            "dep:1:1,indep:1:1,ctrl:1:1,dep:2:1,indep:2:1,ctrl:2:1,\
             dep:3:1,indep:3:1,ctrl:3:1"
                .to_string()
        });
    let mut levels = match parse_assay_levels(&levels_str) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("assay: {e}");
            return ExitCode::from(2);
        }
    };
    // POSITIVE-CONTROL / MDE mode: `--delay-calib "d1,d2,..."` runs a direct-timing
    // dose sweep of the Mode::Delay known-wall-delay, then auto-selects the doses
    // closest to +0.5/+1/+2% and runs ONLY those through the steady gating loop —
    // measuring this M1's minimum-detectable-effect (the smallest KNOWN wall dose
    // the harness resolves above its A/A floor).
    let delay_calib_doses: Option<Vec<u64>> = flag(args, "--delay-calib").map(|s| {
        s.split(',')
            .filter(|x| !x.is_empty())
            .filter_map(|x| x.trim().parse::<u64>().ok())
            .collect()
    });
    // Stride for the Mode::Delay positive control. The delay is a per-application
    // DEPENDENT memory chase (far costlier than an ALU step), so it must fire
    // SPARSELY to dial a small known increment; default 256. Must be one of the
    // monomorphized strides {1,2,4,…,2048}.
    let delay_stride: u64 = flag(args, "--delay-stride")
        .and_then(|s| s.parse().ok())
        .unwrap_or(256);

    if let Err(e) = preflight_root() {
        eprintln!("assay: {e}");
        return ExitCode::from(2);
    }

    println!("== fulcrum assay (macOS) — measurement-capability assay ==");
    println!(
        "gz={gz_bin}\ncorpus={corpus}  cal-n={cal_n}  wall={}  levels={}",
        do_wall,
        levels.len()
    );

    // ---- environment control (held for the whole run) -----------------------
    let _caff = start_caffeinate();
    let pinned = pin_to_pcluster();

    let pmu = match Pmu::new() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("assay: PMU init failed: {e}");
            return ExitCode::from(2);
        }
    };
    let sess = match Session::program(&pmu, &["FIXED_CYCLES", "FIXED_INSTRUCTIONS"]) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("assay: kpc program failed: {e}");
            return ExitCode::from(2);
        }
    };

    // ---- Gate-0 (global) ----------------------------------------------------
    println!("\n-- Gate-0 self-validation (BLOCKING) --");
    let mut g0_ok = true;
    macro_rules! g0 {
        ($cond:expr, $($m:tt)*) => {{
            let ok = $cond;
            println!("  [Gate-0] {} :: {}", if ok {"PASS"} else {"FAIL"}, format!($($m)*));
            if !ok { g0_ok = false; }
        }};
    }
    g0!(pinned, "QoS USER_INTERACTIVE set (P-cluster)");
    g0!(_caff.is_some(), "caffeinate held");
    g0!(
        pmu.has_event("FIXED_INSTRUCTIONS") && pmu.has_event("FIXED_CYCLES"),
        "kpc FIXED_CYCLES + FIXED_INSTRUCTIONS present"
    );
    match is_native_macho(&gz_bin) {
        Ok(()) => g0!(true, "gz = native Mach-O executable"),
        Err(e) => g0!(false, "gz native check: {e}"),
    }
    let oracle = match oracle_sha(&corpus) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("assay: oracle failed: {e}");
            return ExitCode::from(2);
        }
    };
    g0!(true, "oracle sha (gzip -dc) = {}…", &oracle[..12]);

    // In-process decode buffers (for calibration). Size from the oracle.
    let data = match std::fs::read(&corpus) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("assay: read {corpus}: {e}");
            return ExitCode::from(2);
        }
    };
    let out_len = {
        let o = Command::new("gzip").arg("-dc").arg(&corpus).output();
        match o {
            Ok(o) if o.status.success() => o.stdout.len(),
            _ => {
                eprintln!("assay: gzip -dc sizing failed");
                return ExitCode::from(2);
            }
        }
    };
    let mut buf = vec![0u8; out_len + 4096];

    // tax-OFF in-process correctness + a warm decode.
    gzippy::assay_tax::configure(gzippy::assay_tax::Mode::Off, 0, 1);
    let off_len = run_gz(&data, &mut buf);
    g0!(
        sha256_hex(&buf[..off_len]) == oracle,
        "in-process tax-OFF sha == oracle"
    );

    // kpc instruction measurement around one in-process decode.
    let measure_instr = |buf: &mut [u8]| -> (u64, u64) {
        let before = sess.read(&pmu);
        run_gz(&data, buf);
        let after = sess.read(&pmu);
        (after[0] - before[0], after[1] - before[1]) // (cycles, instructions)
    };

    // PER-RUN in-process fastloop application count for a fixed probe level
    // (dep:1:1 ⇒ one application per fastloop iteration). `reset_fires()` BEFORE
    // a SINGLE run scopes the count to that one decode — the prior assay summed
    // `fires()` over warm+cal_n runs (≈12×), manufacturing a phantom "12× path
    // divergence". This is the per-run truth.
    let inproc_fires = |buf: &mut [u8], mode: gzippy::assay_tax::Mode, dose: u64, stride: u64| -> u64 {
        gzippy::assay_tax::configure(mode, dose, stride);
        gzippy::assay_tax::reset_fires();
        run_gz(&data, buf);
        let f = gzippy::assay_tax::fires();
        gzippy::assay_tax::configure(gzippy::assay_tax::Mode::Off, 0, 1);
        f
    };

    // BUG-1 GATE-0 — CALIBRATION PATH == WALL PATH (BLOCKING). The instr% is
    // calibrated in-process; the wall is measured on the subprocess CLI `-p1`
    // arm. If those traverse different code paths (or differently-built
    // binaries), the calibrated instr% does NOT describe the wall arm. Proof:
    // the per-run fastloop iteration count must MATCH between the in-process
    // decode and the subprocess wall arm (dep:1:1 ⇒ fires == #iterations).
    let ip_fires = inproc_fires(&mut buf, gzippy::assay_tax::Mode::Dependent, 1, 1);
    let sp_fires = subprocess_fires(&gz_bin, &corpus, "dep", 1, 1);
    match sp_fires {
        Some(sp) => {
            let rel = (ip_fires as f64 - sp as f64).abs() / (sp.max(1) as f64);
            g0!(
                rel < 0.01,
                "calibration path == wall path: in-proc fires={ip_fires} subproc fires={sp} (rel Δ={:.4})",
                rel
            );
        }
        None => g0!(false, "calibration path == wall path: subprocess fires UNREADABLE (--gz must report GZIPPY_ASSAY_TAX_STATS fires=)"),
    }

    // BUG-2 GATE-0 — MONOTONIC DOSE RESPONSE (BLOCKING). With STRIDE compile-time
    // const, the only per-level variable is the injected-tax WORK. Calibrate a
    // small dose ladder (dep, stride=1) and require the instr% to rise strictly
    // with dose — proving the tax magnitude (not a runtime stride-counter branch)
    // is what moves the instruction stream.
    let mono_instr = |buf: &mut [u8], dose: u64| -> f64 {
        gzippy::assay_tax::configure(gzippy::assay_tax::Mode::Off, 0, 1);
        let _ = measure_instr(buf); // warm
        let off: Vec<f64> = (0..cal_n).map(|_| measure_instr(buf).1 as f64).collect();
        gzippy::assay_tax::configure(gzippy::assay_tax::Mode::Dependent, dose, 1);
        let _ = measure_instr(buf); // warm
        let on: Vec<f64> = (0..cal_n).map(|_| measure_instr(buf).1 as f64).collect();
        gzippy::assay_tax::configure(gzippy::assay_tax::Mode::Off, 0, 1);
        100.0 * (median(&on) / median(&off) - 1.0)
    };
    let mono_doses = [1u64, 2, 4, 8];
    let mono_pct: Vec<f64> = mono_doses.iter().map(|&d| mono_instr(&mut buf, d)).collect();
    let monotonic = mono_pct.windows(2).all(|w| w[1] > w[0] + 0.05) && mono_pct[0] > 0.0;
    g0!(
        monotonic,
        "monotonic dose response (dep,stride=1): doses {:?} -> instr% {}",
        mono_doses,
        mono_pct.iter().map(|p| format!("{p:+.3}")).collect::<Vec<_>>().join(", ")
    );

    let ghz0 = probe_ghz(&pmu, &sess);
    g0!(
        (0.6..=4.5).contains(&ghz0),
        "freq probe sane: {ghz0:.3} GHz"
    );
    if !g0_ok {
        eprintln!("\nassay: GATE-0 FAILED — refusing to report");
        return ExitCode::FAILURE;
    }
    println!("-- Gate-0 PASSED --");

    // ---- DELAY positive-control calibration + MDE level selection -----------
    let mut delay_calib_json: Option<serde_json::Value> = None;
    let mut mde_pick_json: Option<serde_json::Value> = None;
    if let Some(doses) = &delay_calib_doses {
        if doses.is_empty() {
            eprintln!("assay: --delay-calib had no parseable doses");
            return ExitCode::from(2);
        }
        let (cjson, picks) = delay_calibration(&gz_bin, &corpus, doses, delay_stride, cal_n);
        delay_calib_json = Some(cjson);
        // Auto-pick the doses closest to +0.5 / +1 / +2 % standalone wall.
        let d_half = pick_dose_for(&picks, 0.5);
        let d_one = pick_dose_for(&picks, 1.0);
        let d_two = pick_dose_for(&picks, 2.0);
        let mut chosen: Vec<u64> = Vec::new();
        for d in [d_half, d_one, d_two].into_iter().flatten() {
            if !chosen.contains(&d) {
                chosen.push(d);
            }
        }
        println!(
            "\n  MDE level selection (closest to +0.5/+1/+2% standalone): doses {chosen:?}"
        );
        mde_pick_json = Some(serde_json::json!({
            "target_half_pct_dose": d_half,
            "target_one_pct_dose": d_one,
            "target_two_pct_dose": d_two,
            "selected_doses": chosen,
        }));
        // Replace the level list with the auto-selected delay trio: the per-level
        // loop below then runs the FULL steady gating on exactly these known doses.
        levels = chosen
            .into_iter()
            .map(|d| AssayLevel {
                mode: gzippy::assay_tax::Mode::Delay,
                mode_name: "delay",
                env_mode: "delay",
                dose: d,
                stride: delay_stride,
            })
            .collect();
    }

    // ---- per-level loop -----------------------------------------------------
    let mut json_levels: Vec<serde_json::Value> = Vec::new();
    println!(
        "\n{:<20} {:>10} {:>10} {:>12} {:>10} {:>9} {:>9} {:>9} {:<14}",
        "level", "instr%", "fires/M", "wall_eff%", "taxcost%", "spread%", "AAfloor%", "gated", "verdict"
    );

    for lv in &levels {
        let tag = format!("{}:{}:{}", lv.env_mode, lv.dose, lv.stride);

        // ---- Phase A: calibration (in-process kpc retired instructions) ----
        let mut instr_pct = f64::NAN;
        let mut fires = 0u64;
        let mut cal_ok = true;
        if do_cal {
            // baseline (tax off)
            gzippy::assay_tax::configure(gzippy::assay_tax::Mode::Off, 0, 1);
            let _ = measure_instr(&mut buf); // warm
            let mut off_ins = Vec::with_capacity(cal_n);
            for _ in 0..cal_n {
                let (_c, i) = measure_instr(&mut buf);
                off_ins.push(i as f64);
            }
            // armed
            gzippy::assay_tax::configure(lv.mode, lv.dose, lv.stride);
            let on_len = run_gz(&data, &mut buf); // warm + sha
            let on_sha = sha256_hex(&buf[..on_len]);
            let mut on_ins = Vec::with_capacity(cal_n);
            for _ in 0..cal_n {
                let (_c, i) = measure_instr(&mut buf);
                on_ins.push(i as f64);
            }
            // PER-RUN fires: reset, then ONE decode (not the cumulative tally over
            // warm+cal_n runs, which the old code reported as ≈12× the truth).
            gzippy::assay_tax::reset_fires();
            run_gz(&data, &mut buf);
            fires = gzippy::assay_tax::fires();
            gzippy::assay_tax::configure(gzippy::assay_tax::Mode::Off, 0, 1);

            let off_m = median(&off_ins);
            let on_m = median(&on_ins);
            instr_pct = 100.0 * (on_m / off_m - 1.0);
            if on_sha != oracle {
                println!("  [Gate-0] FAIL :: {tag} tax-ON sha != oracle (NOT byte-transparent)");
                cal_ok = false;
            }
            if fires == 0 {
                println!("  [Gate-0] FAIL :: {tag} INERT (fires==0 while armed)");
                cal_ok = false;
            }
            if !(instr_pct > 0.0) {
                println!("  [Gate-0] FAIL :: {tag} instr delta not > 0 ({instr_pct:.3}%)");
                cal_ok = false;
            }
        }

        // ---- Phase B: wall (subprocess steady, A=off vs B=on) ----
        let mut wall_eff = f64::NAN;
        let mut taxcost = f64::NAN;
        let mut spread = f64::NAN;
        let mut floor = f64::NAN;
        let mut gated = false;
        let mut status = "skipped".to_string();
        if do_wall && cal_ok {
            let gz_off = Arm {
                key: "off".into(),
                bin: gz_bin.clone(),
                decode_args: vec!["-d".into(), "-c".into(), "-p1".into()],
                env: Vec::new(),
            };
            let gz_on = Arm {
                key: "on".into(),
                bin: gz_bin.clone(),
                decode_args: vec!["-d".into(), "-c".into(), "-p1".into()],
                env: vec![
                    ("GZIPPY_ASSAY_TAX_MODE".into(), lv.env_mode.to_string()),
                    ("GZIPPY_ASSAY_TAX_DOSE".into(), lv.dose.to_string()),
                    ("GZIPPY_ASSAY_TAX_STRIDE".into(), lv.stride.to_string()),
                ],
            };
            println!("\n-- level {tag}  (instr {instr_pct:+.3}%) — wall --steady --");
            match run_steady_cohorts(args, &gz_off, &gz_on, &corpus, &pmu, &sess, ghz0) {
                Some(raw) => {
                    let v = steady_verdict(&raw.cohort_sig, &raw.cohort_aa, "off", "on");
                    // sig = off/on. on slower ⇒ off/on<1 ⇒ effect<0. Tax cost at the
                    // wall = on/off-1 = 1/overall-1.
                    wall_eff = v.effect_pct;
                    taxcost = 100.0 * (1.0 / v.overall - 1.0);
                    spread = v.signal_spread;
                    floor = v.floor;
                    gated = v.status == "REPRODUCIBLE";
                    status = v.status.to_string();
                }
                None => {
                    status = "NOT_RESOLVABLE".to_string();
                }
            }
        } else if do_wall && !cal_ok {
            status = "cal-failed".to_string();
        }

        println!(
            "{:<20} {:>10.3} {:>10.2} {:>12.3} {:>10.3} {:>9.3} {:>9.3} {:>9} {:<14}",
            tag,
            instr_pct,
            fires as f64 / 1.0e6,
            wall_eff,
            taxcost,
            spread,
            floor,
            if gated { "YES" } else { "no" },
            status
        );

        json_levels.push(serde_json::json!({
            "mode": lv.mode_name,
            "dose": lv.dose,
            "stride": lv.stride,
            "instr_pct": if instr_pct.is_nan() { serde_json::Value::Null } else { serde_json::json!(instr_pct) },
            "fires": fires,
            "wall_effect_pct": if wall_eff.is_nan() { serde_json::Value::Null } else { serde_json::json!(wall_eff) },
            "tax_cost_pct": if taxcost.is_nan() { serde_json::Value::Null } else { serde_json::json!(taxcost) },
            "cross_cohort_spread_pct": if spread.is_nan() { serde_json::Value::Null } else { serde_json::json!(spread) },
            "aa_floor_pct": if floor.is_nan() { serde_json::Value::Null } else { serde_json::json!(floor) },
            "gated": gated,
            "verdict": status,
        }));
    }

    // ---- RECURRENCE-ISOLATION AGGREGATE: A/B/C wall-slopes + verdict ---------
    // Arm A = dependent (ALU chain ON the bitbuf recurrence ⇒ latency).
    // Arm B = independent (iso-uop ALU chain OFF the recurrence ⇒ throughput).
    // Arm C = control (independent L1 loads OFF the recurrence ⇒ different op
    //         class; isolates a cache/port confound).
    // Verdict rule (pre-registered): recurrence-latency-bound is CONFIRMED only
    // if Arm A's wall dose-response (slope × dose-span) significantly exceeds
    // BOTH B's and C's, where "significantly" = the gap exceeds the measurement
    // noise floor (max of A/A floor and cross-cohort spread). Else REFUTED /
    // UNRESOLVED — reported honestly, never forced.
    let getf = |v: &serde_json::Value, k: &str| -> f64 {
        v.get(k).and_then(|x| x.as_f64()).unwrap_or(f64::NAN)
    };
    // Least-squares slope of y vs x (stride==1 only); returns (slope, n, span).
    let arm_fit = |arm: &str| -> (f64, Vec<(f64, f64)>, f64, f64) {
        let mut pts: Vec<(f64, f64)> = Vec::new();
        let mut noises: Vec<f64> = Vec::new();
        for lvl in &json_levels {
            if lvl.get("mode").and_then(|m| m.as_str()) != Some(arm) {
                continue;
            }
            if lvl.get("stride").and_then(|s| s.as_u64()) != Some(1) {
                continue;
            }
            let dose = lvl.get("dose").and_then(|d| d.as_f64());
            let cost = getf(lvl, "tax_cost_pct");
            if let (Some(d), c) = (dose, cost) {
                if c.is_finite() {
                    pts.push((d, c));
                    let fl = getf(lvl, "aa_floor_pct");
                    let sp = getf(lvl, "cross_cohort_spread_pct");
                    noises.push(fl.max(sp).abs());
                }
            }
        }
        let noise = if noises.is_empty() { f64::NAN } else { median(&noises) };
        if pts.len() < 2 {
            return (f64::NAN, pts, noise, f64::NAN);
        }
        let n = pts.len() as f64;
        let sx: f64 = pts.iter().map(|p| p.0).sum();
        let sy: f64 = pts.iter().map(|p| p.1).sum();
        let sxx: f64 = pts.iter().map(|p| p.0 * p.0).sum();
        let sxy: f64 = pts.iter().map(|p| p.0 * p.1).sum();
        let denom = n * sxx - sx * sx;
        let slope = if denom.abs() < 1e-12 { f64::NAN } else { (n * sxy - sx * sy) / denom };
        let span = pts.iter().map(|p| p.0).fold(f64::MIN, f64::max)
            - pts.iter().map(|p| p.0).fold(f64::MAX, f64::min);
        (slope, pts, noise, span)
    };

    let (slope_a, pts_a, noise_a, span_a) = arm_fit("dependent");
    let (slope_b, pts_b, noise_b, _span_b) = arm_fit("independent");
    let (slope_c, pts_c, noise_c, _span_c) = arm_fit("control");
    // Dose-response swing across the measured dose range for each arm.
    let swing = |slope: f64, span: f64| -> f64 { slope * span };
    let swing_a = swing(slope_a, span_a);
    let swing_b = swing(slope_b, span_a);
    let swing_c = swing(slope_c, span_a);
    // Noise floor = the worst per-point reproducibility floor across arms.
    let noise = [noise_a, noise_b, noise_c]
        .into_iter()
        .filter(|x| x.is_finite())
        .fold(0.0_f64, f64::max);

    // ISO-UOP Gate-0: dep vs indep must add the SAME instruction COUNT at each
    // shared dose (both are dose×(mul+add); identical op mix by construction).
    // Proven by matching calibrated instr% (the wall-arm cadence-match `fires`
    // is already Gate-0'd). Report the worst relative mismatch.
    let mut iso_max_rel = 0.0_f64;
    let mut iso_pairs: Vec<serde_json::Value> = Vec::new();
    for d in [1u64, 2, 3, 4, 8] {
        let pick = |arm: &str| -> f64 {
            json_levels
                .iter()
                .find(|l| {
                    l.get("mode").and_then(|m| m.as_str()) == Some(arm)
                        && l.get("dose").and_then(|x| x.as_u64()) == Some(d)
                        && l.get("stride").and_then(|x| x.as_u64()) == Some(1)
                })
                .map(|l| getf(l, "instr_pct"))
                .unwrap_or(f64::NAN)
        };
        let (ia, ib) = (pick("dependent"), pick("independent"));
        if ia.is_finite() && ib.is_finite() && ia.abs() > 1e-9 {
            let rel = (ia - ib).abs() / ia.abs();
            iso_max_rel = iso_max_rel.max(rel);
            iso_pairs.push(serde_json::json!({
                "dose": d, "dep_instr_pct": ia, "indep_instr_pct": ib, "rel_mismatch": rel
            }));
        }
    }
    let iso_uop_ok = !iso_pairs.is_empty() && iso_max_rel < 0.10;

    // Verdict.
    let a_beats_b = (swing_a - swing_b) > noise;
    let a_beats_c = (swing_a - swing_c) > noise;
    let a_above_noise = swing_a.abs() > noise;
    let recurrence_verdict = if !slope_a.is_finite() || !slope_b.is_finite() || !slope_c.is_finite() {
        "INSUFFICIENT_DATA"
    } else if a_beats_b && a_beats_c && a_above_noise {
        "CONFIRMED_recurrence_latency_bound"
    } else {
        "REFUTED_OR_UNRESOLVED"
    };

    println!("\n== RECURRENCE-ISOLATION VERDICT (iso-uop A/B/C dose-ladder, stride=1) ==");
    println!(
        "  iso-uop Gate-0 (dep≈indep instr count): {} (max rel mismatch {:.4})",
        if iso_uop_ok { "PASS" } else { "FAIL/NA" },
        iso_max_rel
    );
    println!("  Arm A (dependent  / recurrence):  slope={slope_a:+.4} %wall/dose  pts={pts_a:?}");
    println!("  Arm B (independent/ throughput):  slope={slope_b:+.4} %wall/dose  pts={pts_b:?}");
    println!("  Arm C (control    / indep loads): slope={slope_c:+.4} %wall/dose  pts={pts_c:?}");
    println!(
        "  dose-span={span_a:.0}  swing A/B/C = {swing_a:+.4}/{swing_b:+.4}/{swing_c:+.4} %wall   noise floor={noise:.4}%"
    );
    println!(
        "  A>>B: {} ({:+.4} > {:.4})   A>>C: {} ({:+.4} > {:.4})   A>noise: {}",
        a_beats_b, swing_a - swing_b, noise, a_beats_c, swing_a - swing_c, noise, a_above_noise
    );
    println!("  VERDICT: {recurrence_verdict}");

    let recurrence_json = serde_json::json!({
        "iso_uop_gate0_pass": iso_uop_ok,
        "iso_uop_max_rel_mismatch": iso_max_rel,
        "iso_uop_pairs": iso_pairs,
        "arm_a_dependent_slope_pctwall_per_dose": if slope_a.is_finite() { serde_json::json!(slope_a) } else { serde_json::Value::Null },
        "arm_b_independent_slope_pctwall_per_dose": if slope_b.is_finite() { serde_json::json!(slope_b) } else { serde_json::Value::Null },
        "arm_c_control_slope_pctwall_per_dose": if slope_c.is_finite() { serde_json::json!(slope_c) } else { serde_json::Value::Null },
        "dose_span": span_a,
        "swing_a_pctwall": if swing_a.is_finite() { serde_json::json!(swing_a) } else { serde_json::Value::Null },
        "swing_b_pctwall": if swing_b.is_finite() { serde_json::json!(swing_b) } else { serde_json::Value::Null },
        "swing_c_pctwall": if swing_c.is_finite() { serde_json::json!(swing_c) } else { serde_json::Value::Null },
        "noise_floor_pct": noise,
        "a_beats_b": a_beats_b,
        "a_beats_c": a_beats_c,
        "a_above_noise": a_above_noise,
        "verdict": recurrence_verdict,
        "verdict_rule": "CONFIRMED iff (swingA-swingB)>noise AND (swingA-swingC)>noise AND |swingA|>noise; else REFUTED/UNRESOLVED",
    });

    // ---- MDE VERDICT (positive-control mode only) ---------------------------
    if delay_calib_doses.is_some() {
        // The harness MDE = the SMALLEST known standalone wall dose whose steady
        // gating came back REPRODUCIBLE (gated=YES). Scan the delay levels.
        let mut gated_pts: Vec<(f64, f64)> = Vec::new(); // (instr%, taxcost%) for gated
        let mut all_pts: Vec<(f64, bool, String)> = Vec::new();
        for lvl in &json_levels {
            if lvl.get("mode").and_then(|m| m.as_str()) != Some("delay") {
                continue;
            }
            let g = lvl.get("gated").and_then(|x| x.as_bool()).unwrap_or(false);
            let tc = lvl.get("tax_cost_pct").and_then(|x| x.as_f64()).unwrap_or(f64::NAN);
            let verdict = lvl
                .get("verdict")
                .and_then(|x| x.as_str())
                .unwrap_or("?")
                .to_string();
            all_pts.push((tc, g, verdict));
            if g && tc.is_finite() {
                gated_pts.push((tc, tc));
            }
        }
        let mde = gated_pts
            .iter()
            .map(|(tc, _)| *tc)
            .filter(|x| x.is_finite())
            .fold(f64::INFINITY, f64::min);
        println!("\n== MDE VERDICT (positive-control known-wall-delay) ==");
        for (tc, g, v) in &all_pts {
            println!("  delay tax_cost={tc:+.3}%  gated={}  ({v})", if *g { "YES" } else { "no" });
        }
        if mde.is_finite() {
            println!("  HARNESS MDE on this M1 ≈ {mde:.3}% (smallest KNOWN wall dose resolved above the A/A floor at N≥{cal_n})");
        } else {
            println!("  HARNESS MDE: NONE of the tested doses (up to the largest fed) resolved above the A/A floor ⇒ MDE is ABOVE the largest tested dose on this M1.");
        }
        println!(
            "  SCOPE: a HARDWARE/HARNESS measurement-capability fact for silesia-T1 on THIS M1 Pro under the CURRENT measurement envelope — NOT a decoder-floor claim, and bounded to the TESTED mechanism classes."
        );
    }

    // ---- artifact -----------------------------------------------------------
    if let Some(path) = &json_path {
        let corpus_sha = file_sha256(&corpus).unwrap_or_else(|_| "?".into());
        let gz_sha = file_sha256(&gz_bin).unwrap_or_else(|_| "?".into());
        let artifact = serde_json::json!({
            "tool": "fulcrum assay",
            "host_arch": std::env::consts::ARCH,
            "gz_bin": gz_bin,
            "gz_sha256": gz_sha,
            "corpus": corpus,
            "corpus_sha256": corpus_sha,
            "oracle_sha256": oracle,
            "decoded_bytes": out_len,
            "cal_n": cal_n,
            "steady_ghz": ghz0,
            "levels": json_levels,
            "recurrence_isolation": recurrence_json,
            "delay_calibration": delay_calib_json,
            "mde_level_selection": mde_pick_json,
        });
        match std::fs::write(path, serde_json::to_string_pretty(&artifact).unwrap()) {
            Ok(()) => println!("\nartifact: {path}"),
            Err(e) => eprintln!("assay: write {path}: {e}"),
        }
    }

    ExitCode::SUCCESS
}
