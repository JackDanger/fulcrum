//! Fair cross-tool comparison harness — an HONEST win/lose table BY CONSTRUCTION.
//!
//! [`crate::xtool`] folds *pre-captured* perf reports into a comparable shape. This
//! module is the layer that actually RUNS the tools and decides who wins — and it
//! is built specifically so the five classic ways a cross-tool benchmark LIES are
//! impossible to commit by accident:
//!
//! 1. **Interpreter-wrapped / slow-packaged competitor + startup tax.** A tool can
//!    be a Python/sh shim that pays a fixed interpreter-startup cost every
//!    invocation (catastrophic on a sub-second job) and runs a slower
//!    non-native core. This harness RESOLVES each tool's real binary, SNIFFS it
//!    ([`probe_binary`]) and WARNS if it looks interpreter-wrapped, and MEASURES
//!    per-invocation startup (an empty / `--version` run) so it can be SUBTRACTED
//!    from each timing or amortized by requiring a large-enough input
//!    ([`Comparison::startup_warning`]).
//! 2. **Naive uniform flag instead of the tool's best.** A per-tool [`ToolSpec`]
//!    carries the documented BEST configuration (auto-thread spelling, the right
//!    thread flag), so "auto = best" is used instead of an arbitrary `-P N`.
//! 3. **No output-correctness check.** Every run's stdout is sha256'd
//!    ([`sha256`]) and compared to a REFERENCE digest; a mismatch DISQUALIFIES
//!    the run — speed over wrong bytes is never a win.
//! 4. **Single cherry-picked corpus / thread count.** The harness sweeps the full
//!    (corpus × thread-count) matrix and reports the HONEST SCOPE of any win
//!    ([`Comparison::scope_line`]) rather than one cell.
//! 5. **best-of-N under background contention.** Runs are INTERLEAVED (round-robin
//!    across tools, not all-N-of-A then all-N-of-B), and load average + timing
//!    variance are checked so a dirty run is FLAGGED or REFUSED
//!    ([`ContentionGuard`]).
//!
//! Everything here is generic: a tool is described by a small [`ToolSpec`]
//! (argv templates with `{input}` / `{threads}` / `{output}` placeholders); there
//! are NO hard-coded competitor names. A user supplies the specs (or a
//! `--tools-config` JSON); the bundled [`ToolSpec::detect_common`] only offers
//! generic capability for binaries that happen to be on PATH.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// Send SIGKILL to a whole process group (negative pid). Declared directly so we
/// don't add a libc dependency on non-Linux targets just for the timeout kill.
/// SAFETY: `kill(2)` with a valid pgid and SIGKILL is always safe to call.
#[cfg(unix)]
unsafe fn libc_kill_group(pgid: i32) {
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    const SIGKILL: i32 = 9;
    // Negative pid → deliver to the entire process group.
    kill(-pgid, SIGKILL);
}

/// Hard cap for the per-invocation STARTUP probe. A genuine process/interpreter
/// start is well under this; a tool that takes longer on its version/bare run is
/// pathological and must not be allowed to hang the whole comparison.
const STARTUP_PROBE_CAP: Duration = Duration::from_secs(3);

/// Run a binary with one arg, discarding output, killed at `cap` (process-group
/// kill on Unix so wrappers/grandchildren die too). Used by the startup probe so
/// a tool with no fast `--version` can't hang the comparison. Returns nothing —
/// the caller only times the wall.
fn run_bounded(bin: &Path, arg: &str, cap: Duration) {
    let mut cmd = Command::new(bin);
    if !arg.is_empty() {
        cmd.arg(arg);
    }
    cmd.stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .stdin(std::process::Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let Ok(mut child) = cmd.spawn() else { return };
    #[cfg(unix)]
    let pgid = child.id() as i32;
    let t0 = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {
                if t0.elapsed() > cap {
                    #[cfg(unix)]
                    unsafe {
                        libc_kill_group(pgid);
                    }
                    let _ = child.kill();
                    let _ = child.wait();
                    return;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(_) => return,
        }
    }
}

// ───────────────────────────── tool specification ──────────────────────────────

/// How to drive ONE tool generically. Argv templates use placeholders that the
/// harness substitutes per run:
///   `{input}`   → the input file path
///   `{output}`  → a temp output path (when `writes_to == OutputMode::File`)
///   `{threads}` → the concrete thread count for this cell
///
/// A tool that auto-selects threads omits `{threads}` from its argv and instead
/// sets `auto_threads_arg` (used at the "auto" cell). This is how hole #2 is
/// closed: the BEST documented config is the data, not a guessed uniform flag.
#[derive(Clone, Debug)]
pub struct ToolSpec {
    /// Display + reference name (generic, e.g. "tool-a"). Never a real
    /// competitor product name in the repo's own fixtures.
    pub name: String,
    /// The command (resolved against PATH if not absolute).
    pub bin: String,
    /// argv template for a decode/run that emits the canonical output on stdout.
    /// `{input}` substituted; threads via `{threads}` OR `thread_arg`/`auto`.
    pub argv: Vec<String>,
    /// How this tool's per-thread count is spelled, if it takes one. The token
    /// is formatted with the count, e.g. `"-p{n}"` or `"--threads={n}"`. When
    /// `argv` already contains `{threads}`, leave this `None`.
    pub thread_arg: Option<String>,
    /// The tool's documented BEST auto/all-cores argument (e.g. `"-p0"` meaning
    /// "auto"). Used for the synthetic "auto" thread cell. `None` = no auto mode.
    pub auto_threads_arg: Option<String>,
    /// Where the canonical output lands.
    pub writes_to: OutputMode,
    /// Argument that prints version/help quickly, for the STARTUP probe (hole #1).
    /// Defaults to `--version`.
    pub version_arg: String,
}

/// Where a tool's canonical (verifiable) output goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputMode {
    /// Output is written to stdout (the harness captures + hashes it).
    Stdout,
    /// Output is written to the file named by the `{output}` placeholder; the
    /// harness reads + hashes that file then deletes it.
    File,
}

impl ToolSpec {
    /// Construct a stdout-decoding spec from a name, binary, and argv template.
    pub fn stdout(name: &str, bin: &str, argv: &[&str]) -> Self {
        ToolSpec {
            name: name.to_string(),
            bin: bin.to_string(),
            argv: argv.iter().map(|s| s.to_string()).collect(),
            thread_arg: None,
            auto_threads_arg: None,
            writes_to: OutputMode::Stdout,
            version_arg: "--version".to_string(),
        }
    }

    /// Builder: set the thread-flag spelling, e.g. `"-p{n}"`.
    pub fn with_thread_arg(mut self, tmpl: &str) -> Self {
        self.thread_arg = Some(tmpl.to_string());
        self
    }

    /// Builder: set the documented best auto/all-cores arg, e.g. `"-p0"`.
    pub fn with_auto_arg(mut self, arg: &str) -> Self {
        self.auto_threads_arg = Some(arg.to_string());
        self
    }

    /// Builder: set the version/startup-probe argument.
    pub fn with_version_arg(mut self, arg: &str) -> Self {
        self.version_arg = arg.to_string();
        self
    }

    /// Resolve `bin` to an absolute path via PATH lookup. `None` if not found.
    pub fn resolve(&self) -> Option<PathBuf> {
        resolve_in_path(&self.bin)
    }

    /// Build the concrete argv for a run at a given thread cell. `Auto` uses the
    /// documented auto arg; `Fixed(n)` uses the thread-flag spelling. `{input}`,
    /// `{output}` are substituted. Returns argv WITHOUT the program (caller has
    /// the resolved bin).
    pub fn build_argv(&self, input: &Path, output: Option<&Path>, threads: ThreadCell) -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        for tok in &self.argv {
            let t = tok
                .replace("{input}", &input.display().to_string())
                .replace(
                    "{output}",
                    &output.map(|o| o.display().to_string()).unwrap_or_default(),
                )
                .replace("{threads}", &threads.count_string());
            // Skip an empty {threads}/{output} token that resolved to nothing.
            if t.is_empty() && (tok.contains("{threads}") || tok.contains("{output}")) {
                continue;
            }
            v.push(t);
        }
        // Append the thread/auto flag if the template didn't already inline it.
        let inlined_threads = self.argv.iter().any(|t| t.contains("{threads}"));
        if !inlined_threads {
            match threads {
                ThreadCell::Auto => {
                    if let Some(a) = &self.auto_threads_arg {
                        v.push(a.clone());
                    }
                }
                ThreadCell::Fixed(n) => {
                    if let Some(tmpl) = &self.thread_arg {
                        v.push(tmpl.replace("{n}", &n.to_string()));
                    }
                }
            }
        }
        v
    }
}

/// A thread-count cell in the sweep: a fixed count, or the tool's documented
/// auto/all-cores mode (hole #2 — compare auto-vs-auto, the tool's best).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadCell {
    Auto,
    Fixed(usize),
}

impl ThreadCell {
    pub fn label(&self) -> String {
        match self {
            ThreadCell::Auto => "auto".to_string(),
            ThreadCell::Fixed(n) => format!("T{n}"),
        }
    }
    fn count_string(&self) -> String {
        match self {
            ThreadCell::Auto => "0".to_string(),
            ThreadCell::Fixed(n) => n.to_string(),
        }
    }
}

// ───────────────────────────── binary probe (hole #1) ──────────────────────────

/// What a binary looks like — native ELF/Mach-O, or an interpreter shim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BinaryKind {
    /// A native compiled executable (ELF / Mach-O / PE).
    Native,
    /// A text script with an interpreter shebang (python/perl/ruby/node/sh…).
    /// Carries the interpreter name for the warning.
    Interpreted(String),
    /// Could not be classified (binary not found, unreadable).
    Unknown,
}

/// The result of probing a tool's resolved binary for hole #1.
#[derive(Clone, Debug)]
pub struct BinaryProbe {
    pub path: PathBuf,
    pub kind: BinaryKind,
    /// Per-invocation startup wall (median of a few `--version` runs). This is
    /// the fixed cost paid EVERY run; on a sub-second job it dominates and a
    /// fair harness must subtract or amortize it.
    pub startup: Duration,
    /// Spread of the startup samples (max/min−1); high = noisy box.
    pub startup_spread: f64,
}

impl BinaryProbe {
    /// Is this tool likely an interpreter shim (hole #1's first half)?
    pub fn looks_interpreted(&self) -> bool {
        matches!(self.kind, BinaryKind::Interpreted(_))
    }
}

/// Resolve a command against `$PATH` (or treat as a literal path if it contains
/// a slash). Pure; no allocation games. Returns the first executable hit.
pub fn resolve_in_path(cmd: &str) -> Option<PathBuf> {
    let p = Path::new(cmd);
    if cmd.contains('/') {
        return if p.exists() { Some(p.to_path_buf()) } else { None };
    }
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let cand = dir.join(cmd);
        if cand.is_file() {
            // Best-effort executable check; on unix verify the x bit.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(md) = cand.metadata() {
                    if md.permissions().mode() & 0o111 != 0 {
                        return Some(cand);
                    }
                }
            }
            #[cfg(not(unix))]
            {
                return Some(cand);
            }
        }
    }
    None
}

/// Classify a binary as native vs interpreter-wrapped by reading its first
/// bytes (magic numbers + shebang). This is the hole-#1 detector: a shebang to a
/// scripting interpreter is the tell-tale of a pip/gem/npm shim that pays
/// interpreter startup and usually wraps a slower-than-native core.
pub fn classify_binary(path: &Path) -> BinaryKind {
    let Ok(bytes) = read_prefix(path, 256) else {
        return BinaryKind::Unknown;
    };
    if bytes.len() >= 4 {
        // ELF, Mach-O (32/64, both endians), PE/COFF → native.
        let m = &bytes[..4];
        let machos: [[u8; 4]; 4] = [
            [0xFE, 0xED, 0xFA, 0xCE],
            [0xFE, 0xED, 0xFA, 0xCF],
            [0xCE, 0xFA, 0xED, 0xFE],
            [0xCF, 0xFA, 0xED, 0xFE],
        ];
        let fat: [[u8; 4]; 2] = [[0xCA, 0xFE, 0xBA, 0xBE], [0xBE, 0xBA, 0xFE, 0xCA]];
        if m == b"\x7FELF" || machos.iter().any(|x| x == m) || fat.iter().any(|x| x == m) {
            return BinaryKind::Native;
        }
        if &bytes[..2] == b"MZ" {
            return BinaryKind::Native; // PE
        }
    }
    if bytes.starts_with(b"#!") {
        // Read the interpreter from the shebang line.
        let line_end = bytes.iter().position(|&b| b == b'\n').unwrap_or(bytes.len());
        let line = String::from_utf8_lossy(&bytes[2..line_end]);
        let interp = interpreter_name(&line);
        return BinaryKind::Interpreted(interp);
    }
    BinaryKind::Unknown
}

/// Extract a human interpreter name from a shebang body, recognizing the
/// `/usr/bin/env python3` form and bare paths. Returns lowercased basename.
fn interpreter_name(shebang_body: &str) -> String {
    let toks: Vec<&str> = shebang_body.split_whitespace().collect();
    // `#!/usr/bin/env python3` → token after `env`; else basename of token 0.
    let raw = if let Some(first) = toks.first() {
        if first.ends_with("env") {
            toks.get(1).copied().unwrap_or(first)
        } else {
            first
        }
    } else {
        ""
    };
    Path::new(raw)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(raw)
        .trim_end_matches(|c: char| c.is_ascii_digit() || c == '.')
        .to_ascii_lowercase()
}

/// Names we treat as scripting interpreters worth a fairness warning.
const SCRIPT_INTERPRETERS: &[&str] = &[
    "python", "perl", "ruby", "node", "bash", "sh", "php", "lua", "tclsh", "wish", "Rscript",
];

/// Is this interpreter name a scripting interpreter (vs e.g. a native loader)?
pub fn is_script_interpreter(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    SCRIPT_INTERPRETERS.iter().any(|s| n == s.to_ascii_lowercase())
}

fn read_prefix(path: &Path, n: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut buf = vec![0u8; n];
    let got = f.read(&mut buf)?;
    buf.truncate(got);
    Ok(buf)
}

/// Probe a tool: resolve, classify, and MEASURE per-invocation startup by
/// running its version/help arg a few times and taking the median wall. The
/// startup figure is the fixed tax hole #1 warns about.
pub fn probe_binary(spec: &ToolSpec, startup_samples: usize) -> BinaryProbe {
    let path = spec.resolve().unwrap_or_else(|| PathBuf::from(&spec.bin));
    let kind = classify_binary(&path);
    let mut walls = Vec::new();
    for _ in 0..startup_samples.max(1) {
        let t0 = Instant::now();
        // Run the version probe; ignore status. We only want the process
        // spin-up + interpreter-init wall, which is the per-invocation tax.
        // BOUND it: a real startup is sub-second, so cap the probe (e.g. a tool
        // with no fast --version, or one that hangs on a bare run, must not hang
        // the whole comparison). A capped probe yields a clamped-large startup,
        // which the cross-tool subtraction bound then handles safely.
        run_bounded(&path, &spec.version_arg, STARTUP_PROBE_CAP);
        walls.push(t0.elapsed());
    }
    walls.sort();
    let startup = walls[walls.len() / 2];
    let spread = if let (Some(min), Some(max)) = (walls.first(), walls.last()) {
        if min.as_nanos() > 0 {
            max.as_secs_f64() / min.as_secs_f64() - 1.0
        } else {
            0.0
        }
    } else {
        0.0
    };
    BinaryProbe {
        path,
        kind,
        startup,
        startup_spread: spread,
    }
}

// ───────────────────────────── contention guard (hole #5) ──────────────────────

/// Reads loadavg + watches timing variance so a dirty (contended) run is flagged
/// or refused. Closes hole #5's "best-of-N under background contention" half.
#[derive(Clone, Debug)]
pub struct ContentionGuard {
    /// 1-minute load average at the start (None if unavailable on this OS).
    pub load1_start: Option<f64>,
    /// Logical CPU count, for a load/CPU ratio.
    pub ncpu: usize,
    /// Refuse (error) rather than merely warn when contended.
    pub strict: bool,
    /// load1/ncpu above this fraction is "busy". Default 0.5.
    pub busy_ratio: f64,
}

impl ContentionGuard {
    pub fn new(strict: bool) -> Self {
        ContentionGuard {
            load1_start: read_loadavg1(),
            ncpu: num_cpus(),
            strict,
            busy_ratio: 0.5,
        }
    }

    /// Is the box busy enough that best-of-N is untrustworthy?
    pub fn box_is_busy(&self) -> Option<bool> {
        let l = self.load1_start?;
        Some(l / self.ncpu.max(1) as f64 > self.busy_ratio)
    }

    /// A human warning line about the box state (or `None` if clean / unknown).
    pub fn warning(&self) -> Option<String> {
        match (self.load1_start, self.box_is_busy()) {
            (Some(l), Some(true)) => Some(format!(
                "load1 {:.2} over {} CPUs ({:.0}% busy) — best-of-N is contended; results FLAGGED dirty",
                l,
                self.ncpu,
                100.0 * l / self.ncpu.max(1) as f64
            )),
            (None, _) => Some(
                "loadavg unavailable on this platform — cannot verify the box is quiet".to_string(),
            ),
            _ => None,
        }
    }
}

/// Read 1-minute load average. Unix via libc-free `getloadavg`-style parse of
/// `/proc/loadavg` on Linux; on macOS via `sysctl vm.loadavg` shell-out. `None`
/// where unavailable.
fn read_loadavg1() -> Option<f64> {
    // Linux: /proc/loadavg "0.50 0.40 0.35 ...".
    if let Ok(s) = std::fs::read_to_string("/proc/loadavg") {
        return s.split_whitespace().next()?.parse().ok();
    }
    // macOS / BSD: `sysctl -n vm.loadavg` → "{ 1.50 1.20 1.05 }".
    let out = Command::new("sysctl").args(["-n", "vm.loadavg"]).output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    s.split_whitespace()
        .find_map(|t| t.trim_matches(|c| c == '{' || c == '}').parse::<f64>().ok())
}

/// Logical CPU count, best-effort (defaults to 1 if unknown).
pub fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

// ───────────────────────────── correctness (hole #3) ───────────────────────────

/// A tiny, dependency-free SHA-256 so every run's output can be verified against
/// a reference without pulling a crate. (Correctness is non-negotiable — hole
/// #3 — so the hash lives in-tree, not behind an optional dep.)
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data)
}

/// Hex-encode a digest.
pub fn hex32(d: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in d {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Self-contained SHA-256 (FIPS 180-4). Verified against known vectors in the
/// module tests; used only to compare run outputs, never for security.
struct Sha256 {
    state: [u32; 8],
    len: u64,
    buf: [u8; 64],
    buf_len: usize,
}

impl Sha256 {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    fn new() -> Self {
        Sha256 {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            len: 0,
            buf: [0u8; 64],
            buf_len: 0,
        }
    }

    fn digest(data: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(data);
        h.finish()
    }

    fn update(&mut self, mut data: &[u8]) {
        self.len = self.len.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let need = 64 - self.buf_len;
            let take = need.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }
        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            self.compress(&block);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    fn finish(mut self) -> [u8; 32] {
        let bit_len = self.len.wrapping_mul(8);
        // append 0x80 then zero-pad to 56 mod 64, then 8-byte big-endian length.
        let mut pad = [0u8; 72];
        pad[0] = 0x80;
        let rem = (self.buf_len + 1) % 64;
        let zeros = if rem <= 56 { 56 - rem } else { 120 - rem };
        let total = 1 + zeros + 8;
        pad[1 + zeros..total].copy_from_slice(&bit_len.to_be_bytes());
        self.update(&pad[..total]);
        let mut out = [0u8; 32];
        for (i, w) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    // The SHA-256 round schedule is clearest with explicit indices (it mirrors
    // FIPS 180-4); the range-loop lint is a false positive on crypto.
    #[allow(clippy::needless_range_loop)]
    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut h = self.state;
        for i in 0..64 {
            let s1 = h[4].rotate_right(6) ^ h[4].rotate_right(11) ^ h[4].rotate_right(25);
            let ch = (h[4] & h[5]) ^ ((!h[4]) & h[6]);
            let t1 = h[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(Self::K[i])
                .wrapping_add(w[i]);
            let s0 = h[0].rotate_right(2) ^ h[0].rotate_right(13) ^ h[0].rotate_right(22);
            let maj = (h[0] & h[1]) ^ (h[0] & h[2]) ^ (h[1] & h[2]);
            let t2 = s0.wrapping_add(maj);
            h[7] = h[6];
            h[6] = h[5];
            h[5] = h[4];
            h[4] = h[3].wrapping_add(t1);
            h[3] = h[2];
            h[2] = h[1];
            h[1] = h[0];
            h[0] = t1.wrapping_add(t2);
        }
        for i in 0..8 {
            self.state[i] = self.state[i].wrapping_add(h[i]);
        }
    }
}

// ───────────────────────────── corpus + matrix ─────────────────────────────────

/// One corpus the matrix sweeps. The `kind` is a free-form GENERIC label
/// (e.g. "compressible", "incompressible", "multi-member") so the scope line can
/// say WHERE a win holds (hole #4). The reference digest is the correct output
/// every tool must reproduce.
#[derive(Clone, Debug)]
pub struct Corpus {
    pub name: String,
    pub kind: String,
    pub path: PathBuf,
    /// Decompressed size in bytes, used for MB/s + the startup-amortization check.
    pub plain_bytes: u64,
    /// The reference output digest (sha256 of the correct decoded bytes).
    pub reference: [u8; 32],
}

/// One measured cell: (tool, corpus, thread-cell).
#[derive(Clone, Debug)]
pub struct Cell {
    pub tool: String,
    pub corpus: String,
    pub corpus_kind: String,
    pub threads: ThreadCell,
    /// Median wall over the interleaved samples (raw, INCLUDING startup).
    pub wall: Duration,
    /// Wall with the tool's measured startup SUBTRACTED (never below ~0).
    pub wall_minus_startup: Duration,
    /// Best (min) wall, for reference.
    pub best_wall: Duration,
    /// Output digest produced (for the correctness check).
    pub digest: [u8; 32],
    /// Did the output match the corpus reference? A `false` DISQUALIFIES the cell.
    pub correct: bool,
    /// Sample-to-sample spread (max/min−1), a noise indicator.
    pub spread: f64,
    /// Throughput on decompressed bytes using the startup-subtracted wall.
    pub mbps: f64,
    /// Decompressed bytes for this corpus (for the MB/s recompute after startup
    /// subtraction).
    pub plain_bytes: u64,
    /// Did this tool/cell error out (nonzero exit / spawn failure)?
    pub errored: bool,
}

impl Cell {
    /// A cell counts as a valid datapoint only if it ran and produced correct
    /// bytes. Hole #3: a fast-but-wrong cell is NOT a win.
    pub fn valid(&self) -> bool {
        !self.errored && self.correct
    }
}

/// The full comparison: probes + cells + the honest scope.
#[derive(Clone, Debug)]
pub struct Comparison {
    pub subject: String,
    pub probes: BTreeMap<String, BinaryProbe>,
    pub cells: Vec<Cell>,
    pub guard_warning: Option<String>,
    pub samples: usize,
    /// True when `strict_contention` was set AND the box was busy, so the sweep
    /// was REFUSED (no cells measured). hole #5's "refuse dirty runs" limb.
    pub refused: bool,
}

/// The outcome at one (corpus, thread) cell, AFTER the noise check. A win is
/// only declared when the margin over the runner-up clears the measurement
/// noise floor — otherwise it's a TIE, because calling a within-spread gap a
/// "win" is the same over-claim the harness exists to prevent (a sixth guard,
/// reinforcing holes #4/#5: a robust scope cannot rest on noise).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CellVerdict {
    /// The lead tool beats the runner-up by more than the noise floor.
    Win { tool: String },
    /// The top tools are within the noise floor — no honest winner.
    Tie { tools: Vec<String> },
    /// No valid (correct-bytes, non-errored) cell.
    NoData,
}

impl Comparison {
    /// Find the winner (lowest startup-subtracted wall among VALID cells) for a
    /// (corpus, thread-cell). Returns the winning tool + its margin over the
    /// runner-up. `None` if no valid cell. (Margin-only; for the noise-aware
    /// decision use [`Comparison::decide`].)
    pub fn winner(&self, corpus: &str, threads: ThreadCell) -> Option<(String, f64)> {
        let mut v: Vec<&Cell> = self
            .cells
            .iter()
            .filter(|c| c.corpus == corpus && c.threads == threads && c.valid())
            .collect();
        v.sort_by_key(|c| c.wall_minus_startup);
        let best = v.first()?;
        let margin = if let Some(second) = v.get(1) {
            second.wall_minus_startup.as_secs_f64() / best.wall_minus_startup.as_secs_f64().max(1e-9)
                - 1.0
        } else {
            f64::INFINITY // uncontested
        };
        Some((best.tool.clone(), margin))
    }

    /// The NOISE-AWARE decision for a cell: declare a [`CellVerdict::Win`] only
    /// when the lead's margin over the runner-up exceeds the noise floor (the
    /// larger of the two tools' sample spreads, with a small ~2% epsilon for
    /// timer granularity). Otherwise it's a [`CellVerdict::Tie`]. This is what
    /// the honest scope + the claim audit consume, so a "win" can never rest on
    /// a within-spread gap.
    pub fn decide(&self, corpus: &str, threads: ThreadCell) -> CellVerdict {
        let mut v: Vec<&Cell> = self
            .cells
            .iter()
            .filter(|c| c.corpus == corpus && c.threads == threads && c.valid())
            .collect();
        v.sort_by_key(|c| c.wall_minus_startup);
        let Some(best) = v.first() else {
            return CellVerdict::NoData;
        };
        let Some(second) = v.get(1) else {
            return CellVerdict::Win {
                tool: best.tool.clone(),
            };
        };
        let margin = second.wall_minus_startup.as_secs_f64()
            / best.wall_minus_startup.as_secs_f64().max(1e-9)
            - 1.0;
        // Noise floor: the worse of the two tools' spreads, floored at 2% to
        // cover timer/scheduler granularity even when a single best-of-N sample
        // looked artificially tight.
        let noise = best.spread.max(second.spread).max(0.02);
        if margin > noise {
            CellVerdict::Win {
                tool: best.tool.clone(),
            }
        } else {
            // Everyone within the noise floor of the leader is tied.
            let lead = best.wall_minus_startup.as_secs_f64();
            let tied: Vec<String> = v
                .iter()
                .filter(|c| {
                    c.wall_minus_startup.as_secs_f64() / lead.max(1e-9) - 1.0 <= noise
                })
                .map(|c| c.tool.clone())
                .collect();
            CellVerdict::Tie { tools: tied }
        }
    }

    /// All (corpus, thread) keys present, in a stable order.
    pub fn cells_keys(&self) -> Vec<(String, String, ThreadCell)> {
        let mut seen = Vec::new();
        for c in &self.cells {
            let k = (c.corpus.clone(), c.corpus_kind.clone(), c.threads);
            if !seen.contains(&k) {
                seen.push(k);
            }
        }
        seen
    }

    /// The HONEST SCOPE line for the subject (hole #4): exactly which cells the
    /// subject wins, which it loses, and by how much — never one cherry-picked
    /// cell. Returns one human paragraph.
    pub fn scope_line(&self) -> String {
        let (wins, losses, ties, disq) = self.subject_breakdown();
        let mut out = String::new();
        out.push_str("HONEST SCOPE for ");
        out.push_str(&self.subject);
        out.push_str(":\n");
        out.push_str(&format!(
            "  WINS  : {}\n",
            if wins.is_empty() { "(none)".into() } else { wins.join(", ") }
        ));
        out.push_str(&format!(
            "  TIES  : {}\n",
            if ties.is_empty() { "(none)".into() } else { ties.join(", ") }
        ));
        out.push_str(&format!(
            "  LOSES : {}\n",
            if losses.is_empty() { "(none)".into() } else { losses.join(", ") }
        ));
        if !disq.is_empty() {
            out.push_str(&format!("  DISQUALIFIED: {}\n", disq.join(", ")));
        }
        // The anti-overclaim verdict.
        out.push_str(&self.overclaim_verdict(&wins, &losses, &ties, &disq));
        out
    }

    /// Categorize EVERY scoped cell for the subject into (wins, losses, ties,
    /// disqualified), using the noise-aware [`Comparison::decide`]. Shared by the
    /// scope line and the audit so they cannot disagree.
    pub fn subject_breakdown(&self) -> (Vec<String>, Vec<String>, Vec<String>, Vec<String>) {
        let mut wins = Vec::new();
        let mut losses = Vec::new();
        let mut ties = Vec::new();
        let mut disq = Vec::new();
        for (corpus, kind, threads) in self.cells_keys() {
            let subj = self
                .cells
                .iter()
                .find(|c| c.corpus == corpus && c.threads == threads && c.tool == self.subject);
            let Some(subj) = subj else { continue };
            let cell_label = format!("{}/{}", kind, threads.label());
            if !subj.valid() {
                disq.push(format!(
                    "{cell_label} (subject {})",
                    if subj.errored { "errored" } else { "WRONG BYTES" }
                ));
                continue;
            }
            match self.decide(&corpus, threads) {
                CellVerdict::Win { tool } if tool == self.subject => {
                    // Margin over the runner-up (for the human label).
                    let m = self
                        .winner(&corpus, threads)
                        .map(|(_, margin)| {
                            if margin.is_finite() {
                                format!("+{:.0}%", margin * 100.0)
                            } else {
                                "uncontested".to_string()
                            }
                        })
                        .unwrap_or_default();
                    wins.push(format!("{cell_label} ({m})"));
                }
                CellVerdict::Win { tool: w } => {
                    let win_cell = self
                        .cells
                        .iter()
                        .find(|c| c.corpus == corpus && c.threads == threads && c.tool == w);
                    let behind = win_cell
                        .map(|wc| {
                            subj.wall_minus_startup.as_secs_f64()
                                / wc.wall_minus_startup.as_secs_f64().max(1e-9)
                        })
                        .unwrap_or(1.0);
                    losses.push(format!("{cell_label} (loses to {w} by {behind:.2}×)"));
                }
                CellVerdict::Tie { tools } if tools.contains(&self.subject) => {
                    let others: Vec<&str> = tools
                        .iter()
                        .filter(|t| *t != &self.subject)
                        .map(|s| s.as_str())
                        .collect();
                    ties.push(format!("{cell_label} (within noise vs {})", others.join("/")));
                }
                CellVerdict::Tie { .. } => {
                    // Subject not in the tie set → it's slower than the tied
                    // leaders; count as a loss.
                    losses.push(format!("{cell_label} (outside the tie band)"));
                }
                CellVerdict::NoData => {}
            }
        }
        (wins, losses, ties, disq)
    }

    fn overclaim_verdict(
        &self,
        wins: &[String],
        losses: &[String],
        ties: &[String],
        disq: &[String],
    ) -> String {
        if !disq.is_empty() {
            return format!(
                "  VERDICT: NO blanket claim possible — subject produced wrong/no output in {} cell(s).\n",
                disq.len()
            );
        }
        if !losses.is_empty() {
            return format!(
                "  VERDICT: MIXED — subject wins {} cell(s), TIES {}, and LOSES {} — a 'fastest at every \
                 thread/situation' claim is an OVER-CLAIM; the honest claim is scoped to the WINS list above \
                 (and TIES are NOT wins — within measurement noise).\n",
                wins.len(),
                ties.len(),
                losses.len()
            );
        }
        if wins.is_empty() && !ties.is_empty() {
            return format!(
                "  VERDICT: NO win — subject only TIES (within noise) in {} cell(s) and wins none. \
                 A 'fastest' claim is NOT supported; the honest statement is 'at parity'.\n",
                ties.len()
            );
        }
        // Reached only when there are no losses and no ties.
        if !wins.is_empty() {
            format!(
                "  VERDICT: subject wins ALL {} measured cells with margins ABOVE the noise floor — a \
                 'fastest everywhere measured' claim is supported ONLY within this matrix (corpora × \
                 thread cells actually run).\n",
                wins.len()
            )
        } else {
            "  VERDICT: subject wins NO cell — any 'fastest' claim is FALSE.\n".to_string()
        }
    }

    /// Flag cells whose sample spread exceeds a noise threshold — a SECOND limb
    /// of hole #5: even on a nominally-quiet box (loadavg low), a high
    /// per-cell spread means the timing is dirty and any close call is noise.
    /// Returns the count of dirty cells + the worst spread, with a verdict.
    pub fn dirty_data_warning(&self, threshold: f64) -> String {
        let dirty: Vec<&Cell> = self
            .cells
            .iter()
            .filter(|c| c.valid() && c.spread > threshold)
            .collect();
        let worst = self
            .cells
            .iter()
            .filter(|c| c.valid())
            .map(|c| c.spread)
            .fold(0.0_f64, f64::max);
        if dirty.is_empty() {
            format!(
                "  [DATA QUALITY] all cells spread <= {:.0}% — timings are crisp.",
                threshold * 100.0
            )
        } else {
            format!(
                "  [DATA QUALITY] {} of {} valid cells have spread > {:.0}% (worst {:.0}%) — the box is \
                 JITTERY; close calls are reported as TIES, not wins. Re-run pinned to performance cores \
                 (taskset/`-c`), quiet background load, and raise --samples for a crisp matrix.",
                dirty.len(),
                self.cells.iter().filter(|c| c.valid()).count(),
                threshold * 100.0,
                worst * 100.0
            )
        }
    }

    /// A warning paragraph for interpreter-wrapped tools + dominating startup
    /// (hole #1). For each tool, if it looks interpreted OR its startup is a
    /// large fraction of the fastest corpus's decode wall, say so.
    pub fn startup_warning(&self) -> String {
        let mut lines = Vec::new();
        // The smallest valid decode wall on the matrix, to judge "startup
        // dominates".
        let fastest_decode = self
            .cells
            .iter()
            .filter(|c| c.valid())
            .map(|c| c.wall_minus_startup.as_secs_f64())
            .fold(f64::INFINITY, f64::min);
        for (tool, probe) in &self.probes {
            if probe.looks_interpreted() {
                if let BinaryKind::Interpreted(interp) = &probe.kind {
                    lines.push(format!(
                        "  {tool}: resolved binary is a {interp} SCRIPT (shebang) — likely an interpreter \
                         shim wrapping a slower-than-native core AND paying {interp} startup every run. \
                         Prefer the NATIVE build for a fair comparison.",
                    ));
                }
            }
            let st = probe.startup.as_secs_f64();
            if fastest_decode.is_finite() && fastest_decode > 0.0 && st > 0.25 * fastest_decode {
                lines.push(format!(
                    "  {tool}: per-invocation STARTUP {:.0} ms is {:.0}% of the fastest decode wall \
                     ({:.0} ms) — it would DOMINATE a naive wall comparison. The harness subtracts it; \
                     also amortize with a larger input.",
                    st * 1e3,
                    100.0 * st / fastest_decode,
                    fastest_decode * 1e3
                ));
            }
        }
        if lines.is_empty() {
            "  (no interpreter-wrapped tools; startup is small vs decode wall — hole #1 clean.)"
                .to_string()
        } else {
            lines.join("\n")
        }
    }
}

// ───────────────────────────── the runner ──────────────────────────────────────

/// Knobs for a comparison run.
#[derive(Clone, Debug)]
pub struct RunCfg {
    /// best-of-N samples per cell (interleaved across tools — hole #5).
    pub samples: usize,
    /// Startup-probe samples per tool.
    pub startup_samples: usize,
    /// Refuse to run if the box is contended (vs warn). hole #5.
    pub strict_contention: bool,
    /// Per-run wall ceiling; a tool exceeding it is recorded as errored.
    pub timeout: Duration,
    /// Directory for temp output files (OutputMode::File). Defaults to env temp.
    pub tmp_dir: PathBuf,
}

impl Default for RunCfg {
    fn default() -> Self {
        RunCfg {
            samples: 5,
            startup_samples: 5,
            strict_contention: false,
            timeout: Duration::from_secs(120),
            tmp_dir: std::env::temp_dir(),
        }
    }
}

/// Run the full fair comparison: probe every tool, then sweep the
/// (corpus × thread-cell) matrix with INTERLEAVED best-of-N, verifying every
/// output. `subject` names the tool under test (the first tool by convention).
pub fn run_comparison(
    subject: &str,
    tools: &[ToolSpec],
    corpora: &[Corpus],
    thread_cells: &[ThreadCell],
    cfg: &RunCfg,
) -> Comparison {
    // hole #1: probe binaries (resolve, classify, startup).
    let mut probes = BTreeMap::new();
    for t in tools {
        probes.insert(t.name.clone(), probe_binary(t, cfg.startup_samples));
    }

    // hole #5: contention guard up front.
    let guard = ContentionGuard::new(cfg.strict_contention);
    let guard_warning = guard.warning();

    // hole #5, refusal limb: if strict AND the box is busy, REFUSE to measure —
    // a dirty best-of-N is worse than no number. (The warning still explains why.)
    if cfg.strict_contention && guard.box_is_busy() == Some(true) {
        return Comparison {
            subject: subject.to_string(),
            probes,
            cells: Vec::new(),
            guard_warning,
            samples: cfg.samples,
            refused: true,
        };
    }

    let mut cells = Vec::new();
    for corpus in corpora {
        for &threads in thread_cells {
            // Cold-cache fairness: one UNTIMED warmup invocation per tool before
            // the timed samples, so the first-listed tool doesn't eat the cold
            // page-cache read while later tools in the round read warm. (Without
            // this, interleaving still leaves a systematic first-tool penalty on
            // the very first round.)
            for t in tools {
                let _ = run_once(t, &probes[&t.name].path, corpus, threads, cfg);
            }
            // hole #5: INTERLEAVED best-of-N. Round-robin so background drift hits
            // all tools equally rather than penalizing whoever ran during a spike.
            let mut samples: BTreeMap<String, Vec<RunOutcome>> = BTreeMap::new();
            for _round in 0..cfg.samples {
                for t in tools {
                    let probe = &probes[&t.name];
                    let outcome = run_once(t, &probe.path, corpus, threads, cfg);
                    samples.entry(t.name.clone()).or_default().push(outcome);
                }
            }
            for t in tools {
                let outs = &samples[&t.name];
                let cell = summarize_cell(t, corpus, threads, outs);
                cells.push(cell);
            }
        }
    }

    // hole #1, robustly: subtract per-invocation startup with a cross-tool
    // sanity bound so a contaminated probe can't zero out real work.
    apply_startup_subtraction(&mut cells, &probes);

    Comparison {
        subject: subject.to_string(),
        probes,
        cells,
        guard_warning,
        samples: cfg.samples,
        refused: false,
    }
}

/// Subtract each tool's measured startup from its cell walls — but CLAMP the
/// subtraction so a contaminated startup probe (one whose `--version`/bare run
/// actually performed work, e.g. a shim that always decodes) cannot drive a
/// real decode wall to ~0 and fake a tie/win.
///
/// The bound: startup is a per-process FIXED cost, so it cannot plausibly exceed
/// the FASTEST decode wall observed across ALL tools on the smallest corpus. We
/// take the global minimum raw cell wall `w_min`, and clamp each tool's
/// subtracted startup to at most `0.9 * w_min`. A probe reporting more than that
/// is treated as untrustworthy and only the bounded amount is removed — never
/// enough to invert a large real margin.
fn apply_startup_subtraction(cells: &mut [Cell], probes: &BTreeMap<String, BinaryProbe>) {
    // Smallest valid raw decode wall across the matrix (the tightest fixed-cost
    // ceiling). Cells currently hold RAW medians in `wall_minus_startup`.
    let w_min = cells
        .iter()
        .filter(|c| c.valid())
        .map(|c| c.wall_minus_startup.as_secs_f64())
        .fold(f64::INFINITY, f64::min);
    let cap = if w_min.is_finite() {
        Duration::from_secs_f64(0.9 * w_min)
    } else {
        Duration::ZERO
    };
    for c in cells.iter_mut() {
        let raw = c.wall_minus_startup; // currently the raw median
        let startup = probes
            .get(&c.tool)
            .map(|p| p.startup.min(cap))
            .unwrap_or(Duration::ZERO);
        c.wall_minus_startup = raw.saturating_sub(startup);
        let secs = c.wall_minus_startup.as_secs_f64();
        c.mbps = if secs > 0.0 {
            c.plain_bytes as f64 / 1e6 / secs
        } else {
            0.0
        };
    }
}

/// One run's outcome (raw).
struct RunOutcome {
    wall: Duration,
    digest: [u8; 32],
    ok: bool,
}

/// Run a single (tool, corpus, threads) invocation once, capturing wall + an
/// output digest (hole #3). Stdout mode hashes the captured stdout; File mode
/// reads + hashes (then deletes) the produced file.
fn run_once(
    spec: &ToolSpec,
    bin: &Path,
    corpus: &Corpus,
    threads: ThreadCell,
    cfg: &RunCfg,
) -> RunOutcome {
    let out_path = if spec.writes_to == OutputMode::File {
        Some(cfg.tmp_dir.join(format!(
            "fulcrum_cmp_{}_{}_{}.out",
            spec.name,
            sanitize(&corpus.name),
            threads.label()
        )))
    } else {
        None
    };
    let argv = spec.build_argv(&corpus.path, out_path.as_deref(), threads);

    let mut cmd = Command::new(bin);
    cmd.args(&argv);
    cmd.stderr(std::process::Stdio::null());
    if spec.writes_to == OutputMode::Stdout {
        cmd.stdout(std::process::Stdio::piped());
    } else {
        cmd.stdout(std::process::Stdio::null());
    }
    // Put the child in its OWN process group so a timeout can kill the WHOLE
    // tree (e.g. a shell wrapper's `sleep`/grandchild), which also closes the
    // inherited stdout fd so the drain thread unblocks. Without this, killing
    // only the direct child leaves a grandchild holding the pipe open and the
    // reader (and the sweep) hangs for the grandchild's full duration.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    let t0 = Instant::now();
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(_) => return RunOutcome { wall: t0.elapsed(), digest: [0u8; 32], ok: false },
    };
    #[cfg(unix)]
    let pgid = child.id() as i32; // == pgid since process_group(0)

    // Drain stdout on a thread so a large output can't deadlock the pipe while
    // we poll for the timeout. (Without a concurrent reader, a child that fills
    // the pipe buffer blocks, and so would a wait().)
    let stdout_handle = child.stdout.take().map(|mut out| {
        std::thread::spawn(move || {
            use std::io::Read;
            let mut buf = Vec::new();
            let _ = out.read_to_end(&mut buf);
            buf
        })
    });

    // Poll for completion until the timeout; KILL a hung child (the real
    // timeout, not just a post-hoc wall flag — a pathological tool can't hang
    // the whole sweep).
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) => {
                if t0.elapsed() > cfg.timeout {
                    // Kill the whole process group so wrappers + grandchildren
                    // (and their hold on the stdout pipe) die too.
                    #[cfg(unix)]
                    unsafe {
                        libc_kill_group(pgid);
                    }
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    break None;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(_) => break None,
        }
    };
    let wall = t0.elapsed();
    // On a clean exit, join the drain thread for the bytes. On a timeout we
    // still join, but the group-kill above closed the pipe so it returns
    // promptly (no unbounded hang); the bytes are irrelevant for a killed run.
    let stdout_bytes = stdout_handle.and_then(|h| h.join().ok()).unwrap_or_default();

    let bytes = match (spec.writes_to, &out_path) {
        (OutputMode::Stdout, _) => stdout_bytes,
        (OutputMode::File, Some(p)) => std::fs::read(p).unwrap_or_default(),
        (OutputMode::File, None) => Vec::new(),
    };
    let digest = sha256(&bytes);
    let ok = !timed_out && status.map(|s| s.success()).unwrap_or(false);

    if let Some(p) = &out_path {
        let _ = std::fs::remove_file(p);
    }
    RunOutcome { wall, digest, ok }
}

/// Fold a tool's interleaved samples for one cell into a [`Cell`], applying the
/// correctness check (hole #3) and the startup subtraction (hole #1).
fn summarize_cell(spec: &ToolSpec, corpus: &Corpus, threads: ThreadCell, outs: &[RunOutcome]) -> Cell {
    let mut walls: Vec<Duration> = outs.iter().filter(|o| o.ok).map(|o| o.wall).collect();
    let errored = walls.is_empty();
    walls.sort();
    let median = if errored {
        Duration::ZERO
    } else {
        walls[walls.len() / 2]
    };
    let best = walls.first().copied().unwrap_or(Duration::ZERO);
    let spread = if let (Some(min), Some(max)) = (walls.first(), walls.last()) {
        if min.as_nanos() > 0 {
            max.as_secs_f64() / min.as_secs_f64() - 1.0
        } else {
            0.0
        }
    } else {
        0.0
    };
    // hole #3: every successful run must reproduce the reference digest. We take
    // the digest of the first OK run and verify ALL ok runs agree AND match the
    // reference; any disagreement or mismatch marks the cell incorrect.
    let ok_digests: Vec<[u8; 32]> = outs.iter().filter(|o| o.ok).map(|o| o.digest).collect();
    let digest = ok_digests.first().copied().unwrap_or([0u8; 32]);
    let all_agree = ok_digests.iter().all(|d| *d == digest);
    let correct = !errored && all_agree && digest == corpus.reference;

    // hole #1: the per-invocation startup is subtracted in a cross-tool post-
    // pass (see `apply_startup_subtraction`) so a CONTAMINATED probe (one whose
    // bare/`--version` run actually did work) can't over-subtract. Here we store
    // the RAW median; the post-pass fills the corrected `wall_minus_startup`.
    let wall_minus_startup = median;
    let secs = wall_minus_startup.as_secs_f64();
    let mbps = if secs > 0.0 {
        corpus.plain_bytes as f64 / 1e6 / secs
    } else {
        0.0
    };

    Cell {
        tool: spec.name.clone(),
        corpus: corpus.name.clone(),
        corpus_kind: corpus.kind.clone(),
        threads,
        wall: median,
        wall_minus_startup,
        best_wall: best,
        digest,
        correct,
        spread,
        mbps,
        plain_bytes: corpus.plain_bytes,
        errored,
    }
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

// ───────────────────────────── rendering ───────────────────────────────────────

/// Render the full honest comparison report.
pub fn render(cmp: &Comparison) -> String {
    let mut s = String::new();
    s.push_str("\n========  FAIR CROSS-TOOL COMPARISON  ========\n");
    if cmp.refused {
        s.push_str(&format!(
            "  REFUSED — strict-contention is on and the box is busy:\n  {}\n  \
             No cells were measured; a dirty best-of-N is worse than no number. Quiet the box and re-run.\n",
            cmp.guard_warning.as_deref().unwrap_or("(contended)")
        ));
        return s;
    }
    s.push_str(&format!(
        "subject: {}   tools: {}   best-of-{} INTERLEAVED   (walls are startup-SUBTRACTED)\n\n",
        cmp.subject,
        cmp.probes.keys().cloned().collect::<Vec<_>>().join(", "),
        cmp.samples
    ));

    // hole #5: contention banner.
    if let Some(w) = &cmp.guard_warning {
        s.push_str(&format!("  [CONTENTION] {w}\n\n"));
    } else {
        s.push_str("  [CONTENTION] box looks quiet (load below threshold) — best-of-N trusted.\n\n");
    }

    // hole #1: binary-probe + startup banner.
    s.push_str("  BINARY PROBE (native vs interpreter-wrapped; per-invocation startup):\n");
    for (tool, p) in &cmp.probes {
        let kind = match &p.kind {
            BinaryKind::Native => "native".to_string(),
            BinaryKind::Interpreted(i) => format!("INTERPRETED({i})"),
            BinaryKind::Unknown => "unknown".to_string(),
        };
        s.push_str(&format!(
            "    {:<14} {:<18} startup {:>6.1} ms (spread {:>3.0}%)  [{}]\n",
            tool,
            kind,
            p.startup.as_secs_f64() * 1e3,
            p.startup_spread * 100.0,
            p.path.display()
        ));
    }
    s.push('\n');
    s.push_str(&cmp.startup_warning());
    s.push_str("\n\n");

    // The matrix table.
    s.push_str("  MATRIX (median wall − startup; ✗ = WRONG BYTES / errored, DISQUALIFIED):\n");
    s.push_str(&format!(
        "  {:<14} {:<16} {:<6} {:>10} {:>9} {:>7} {:>6}  {}\n",
        "tool", "corpus(kind)", "cell", "wall-ms", "MB/s", "spread", "ok?", "winner"
    ));
    s.push_str(&format!("  {}\n", "-".repeat(92)));
    for (corpus, kind, threads) in cmp.cells_keys() {
        let verdict = cmp.decide(&corpus, threads);
        for c in cmp
            .cells
            .iter()
            .filter(|c| c.corpus == corpus && c.threads == threads)
        {
            // Noise-aware mark: ◀ WINNER only for a margin above the noise floor;
            // ~TIE~ for a within-noise leader cluster (so the eye can't read a
            // noise gap as a win).
            let mark = match &verdict {
                CellVerdict::Win { tool } if tool == &c.tool && c.valid() => "◀ WINNER",
                CellVerdict::Tie { tools } if tools.contains(&c.tool) && c.valid() => "~tie~",
                _ => "",
            };
            s.push_str(&format!(
                "  {:<14} {:<16} {:<6} {:>10.1} {:>9.0} {:>6.0}% {:>6}  {}\n",
                c.tool,
                format!("{}({})", trunc(&c.corpus, 8), trunc(kind.as_str(), 5)),
                threads.label(),
                c.wall_minus_startup.as_secs_f64() * 1e3,
                c.mbps,
                c.spread * 100.0,
                if c.errored {
                    "ERR"
                } else if !c.correct {
                    "✗BAD"
                } else {
                    "ok"
                },
                mark
            ));
        }
        s.push('\n');
    }

    // hole #5 (second limb): per-cell data-quality / jitter check.
    s.push_str(&cmp.dirty_data_warning(0.15));
    s.push_str("\n\n");

    // hole #4: the honest scope + anti-overclaim verdict.
    s.push_str(&cmp.scope_line());
    s
}

fn trunc(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        s[..n].to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vectors() {
        // FIPS / RFC test vectors.
        assert_eq!(
            hex32(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex32(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex32(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        // A multi-block input (> 64 bytes) to exercise the streaming path.
        let big = vec![b'a'; 1000];
        assert_eq!(
            hex32(&sha256(&big)),
            "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"
        );
    }

    #[test]
    fn interpreter_name_parses_env_form() {
        assert_eq!(interpreter_name("/usr/bin/env python3"), "python");
        assert_eq!(interpreter_name("/usr/bin/python3.11"), "python");
        assert_eq!(interpreter_name("/bin/sh"), "sh");
        assert_eq!(interpreter_name("/usr/bin/perl -w"), "perl");
        assert!(is_script_interpreter("python"));
        assert!(is_script_interpreter("perl"));
        assert!(!is_script_interpreter("ld-linux"));
    }

    #[test]
    fn classify_detects_shebang_and_native() {
        let dir = std::env::temp_dir().join("fulcrum_classify_test");
        let _ = std::fs::create_dir_all(&dir);
        let script = dir.join("shim.sh");
        std::fs::write(&script, "#!/usr/bin/env python3\nprint('hi')\n").unwrap();
        match classify_binary(&script) {
            BinaryKind::Interpreted(i) => assert_eq!(i, "python"),
            other => panic!("expected interpreted, got {other:?}"),
        }
        let elf = dir.join("fake.elf");
        std::fs::write(&elf, b"\x7FELF\x02\x01\x01\x00rest").unwrap();
        assert_eq!(classify_binary(&elf), BinaryKind::Native);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn build_argv_substitutes_and_appends_threads() {
        // stdout decode with an inline {threads} and an auto arg.
        let spec = ToolSpec::stdout("tool-a", "gzip", &["-dc", "{input}"])
            .with_thread_arg("-p{n}")
            .with_auto_arg("-p0");
        let input = Path::new("/tmp/x.gz");
        let argv = spec.build_argv(input, None, ThreadCell::Fixed(4));
        assert_eq!(argv, vec!["-dc", "/tmp/x.gz", "-p4"]);
        let argv_auto = spec.build_argv(input, None, ThreadCell::Auto);
        assert_eq!(argv_auto, vec!["-dc", "/tmp/x.gz", "-p0"]);
    }

    #[test]
    fn contention_guard_flags_busy_box() {
        // A guard with a synthetic high load over few CPUs must report busy +
        // a warning; a quiet one must not.
        let busy = ContentionGuard {
            load1_start: Some(7.0),
            ncpu: 8,
            strict: false,
            busy_ratio: 0.5,
        };
        assert_eq!(busy.box_is_busy(), Some(true));
        assert!(busy.warning().unwrap().contains("contended"));
        let quiet = ContentionGuard {
            load1_start: Some(0.5),
            ncpu: 8,
            strict: false,
            busy_ratio: 0.5,
        };
        assert_eq!(quiet.box_is_busy(), Some(false));
        assert!(quiet.warning().is_none());
        // Unknown loadavg → an honest "cannot verify" warning, never silent OK.
        let unknown = ContentionGuard {
            load1_start: None,
            ncpu: 8,
            strict: false,
            busy_ratio: 0.5,
        };
        assert!(unknown.warning().unwrap().contains("unavailable"));
    }

    #[test]
    fn within_noise_margin_is_a_tie_not_a_win() {
        // Two tools 100ms vs 103ms (3% apart) but each with 20% spread: the gap
        // is well inside the noise floor, so decide() must return a TIE, never a
        // win. (This is the sixth guard: a 'win' can't rest on noise.)
        let mk = |tool: &str, ms: u64, spread: f64| Cell {
            tool: tool.to_string(),
            corpus: "c".to_string(),
            corpus_kind: "compressible".to_string(),
            threads: ThreadCell::Fixed(1),
            wall: Duration::from_millis(ms),
            wall_minus_startup: Duration::from_millis(ms),
            best_wall: Duration::from_millis(ms),
            digest: sha256(b"ref"),
            correct: true,
            spread,
            mbps: 1.0,
            plain_bytes: 1_000_000,
            errored: false,
        };
        let cmp = Comparison {
            subject: "tool-a".to_string(),
            probes: BTreeMap::new(),
            cells: vec![mk("tool-a", 100, 0.20), mk("tool-b", 103, 0.18)],
            guard_warning: None,
            samples: 5,
            refused: false,
        };
        match cmp.decide("c", ThreadCell::Fixed(1)) {
            CellVerdict::Tie { tools } => {
                assert!(tools.contains(&"tool-a".to_string()));
                assert!(tools.contains(&"tool-b".to_string()));
            }
            other => panic!("expected Tie within noise, got {other:?}"),
        }
        // And a margin ABOVE the noise floor IS a win.
        let cmp2 = Comparison {
            subject: "tool-a".to_string(),
            probes: BTreeMap::new(),
            cells: vec![mk("tool-a", 100, 0.03), mk("tool-b", 150, 0.03)],
            guard_warning: None,
            samples: 5,
            refused: false,
        };
        assert_eq!(
            cmp2.decide("c", ThreadCell::Fixed(1)),
            CellVerdict::Win {
                tool: "tool-a".to_string()
            }
        );
    }

    #[test]
    fn winner_excludes_wrong_bytes() {
        // Construct a synthetic comparison: tool-fast produces WRONG bytes (so it
        // must NOT win) and tool-correct produces the reference but slower.
        let reference = sha256(b"correct output");
        let wrong = sha256(b"WRONG output");
        let mk = |tool: &str, ms: u64, dg: [u8; 32], correct: bool| Cell {
            tool: tool.to_string(),
            corpus: "c".to_string(),
            corpus_kind: "compressible".to_string(),
            threads: ThreadCell::Fixed(1),
            wall: Duration::from_millis(ms),
            wall_minus_startup: Duration::from_millis(ms),
            best_wall: Duration::from_millis(ms),
            digest: dg,
            correct,
            spread: 0.0,
            mbps: 1.0,
            plain_bytes: 1_000_000,
            errored: false,
        };
        let cmp = Comparison {
            subject: "tool-fast".to_string(),
            probes: BTreeMap::new(),
            cells: vec![
                mk("tool-fast", 10, wrong, false),   // fast but WRONG
                mk("tool-correct", 50, reference, true), // slow but right
            ],
            guard_warning: None,
            samples: 5,
            refused: false,
        };
        // The fast-but-wrong tool must NOT win; the correct one does.
        let (w, _) = cmp.winner("c", ThreadCell::Fixed(1)).unwrap();
        assert_eq!(w, "tool-correct");
        // And the subject (tool-fast) scope must report it DISQUALIFIED / no claim.
        let scope = cmp.scope_line();
        assert!(scope.contains("DISQUALIFIED") || scope.contains("NO blanket"));
    }
}
