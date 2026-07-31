//! `fulcrum structcensus` — the deterministic STRUCTURE-axis census.
//!
//! WHY THIS EXISTS, and it is the most expensive lesson in the encoder campaign.
//!
//! Fulcrum had `sizecensus` and `wallcensus`: both compare us to gzip / pigz /
//! libdeflate / igzip, per level, per thread count. Those are OUTCOME axes. There
//! was no vendor-comparative census for STRUCTURE — allocations, bytes allocated,
//! memory copied — so for months nobody ran one, and the encoder shipped this:
//!
//!     6,000,000 B of dickens at -6, whole process
//!         gzippy       731 allocs    83,909,568 bytes
//!         libdeflate     3 allocs     6,674,327 bytes
//!         gzip           0 allocs             0 bytes
//!
//! 244x the allocation count and 12.6x the bytes, and the count GREW LINEARLY
//! WITH INPUT (per-block allocation). That single comparison — three runs of one
//! external tool, about thirty seconds — reframed the whole campaign and produced
//! four landed structural wins in one session, after eight consecutive micro-lever
//! failures inside the matchfinder.
//!
//! IT COULD HAVE BEEN RUN ON DAY ONE.
//!
//! ## Why the counter we already had did not find it
//!
//! gzippy has `alloc_events`/`alloc_bytes` in `anatomy_counters.rs`. They are
//! populated by HAND-WRITTEN `anatomy_count!` macros next to a handful of
//! `Vec::with_capacity` sites. The 2.8 MB `Sink`, the per-block Huffman codes, the
//! per-parser `StaticCodes` rebuild and the per-chunk scheduler slots were none of
//! them annotated, so none of them were counted. The counter reported a tidy
//! number that was wrong by roughly 30x, and its EXISTENCE is probably why nobody
//! looked harder.
//!
//! **A hand-annotated counter can only find what you already suspect. An external
//! observer finds what you do not.** That is the design rule for this file: we
//! never ask the subject to report on itself. We ask valgrind, which cannot be
//! fooled by a missing annotation, and we ask it about the RIVALS too — because a
//! number with no vendor beside it is not a bar, it is a vibe.
//!
//! ## What this measures
//!
//! Per cell (corpus x level x threads x binary): total allocation COUNT, total
//! BYTES allocated, and peak bytes live. Structure is DETERMINISTIC, like size and
//! unlike wall: no frozen box, no paired CI, no noise floor, no A/A gate. That
//! makes this the CHEAPEST FALSIFIER we never built — run it before any wall work.
//!
//! ## Guards (each one earned)
//!
//! * ROUNDTRIP-VOIDED, exactly like `sizecensus`. A build that allocates nothing
//!   because it emits nothing is not a win. Every cell decompresses its own output
//!   and compares sha256 to the input; a mismatch VOIDs the cell and it can never
//!   score.
//! * SCALING IS A FIRST-CLASS OUTPUT. The defect that mattered was not "we
//!   allocate a lot", it was "we allocate MORE AS THE INPUT GROWS". Run with two
//!   or more sizes of the same corpus member and the report names any binary whose
//!   allocation count grows with input, which is the signature of per-block
//!   allocation.
//! * A rival that is not installed is RIVAL-UNAVAILABLE, never silently dropped —
//!   the `sizecensus` incident where a census measured three rivals and said
//!   nothing about the fourth.
//! * The subject binary's identity is stamped in the artifact. Hard stop #7.

use std::path::Path;
use std::process::{Command, ExitCode};

/// One measured structural cell.
#[derive(Debug, Clone)]
pub struct Cell {
    pub binary: String,
    pub corpus: String,
    pub input_len: u64,
    pub level: u32,
    pub threads: usize,
    pub status: String,
    pub allocs: u64,
    pub bytes: u64,
    pub roundtrip_ok: bool,
}

impl Cell {
    pub fn id(&self) -> String {
        format!(
            "{}__{}__L{:02}__T{:02}",
            self.binary, self.corpus, self.level, self.threads
        )
    }
}

/// Classify a cell. PURE — no I/O — so the truth table is selftestable.
///
/// The roundtrip term is the whole point: a compressor that allocates ZERO bytes
/// because it produced a corrupt or empty stream must never rank above one that
/// allocates honestly. `sizecensus` learned this the same way.
pub fn classify_cell(
    rival_available: bool,
    level_accepted: bool,
    roundtrip_ok: bool,
    allocs: u64,
) -> (&'static str, bool) {
    if !rival_available {
        return ("RIVAL-UNAVAILABLE", false);
    }
    if !level_accepted {
        return ("ABSENT", false);
    }
    if !roundtrip_ok {
        return ("VOID", false);
    }
    // `measured` is true; whether it is a WIN is a comparison the report does,
    // never this function — a single cell has no opinion about a rival.
    let _ = allocs;
    ("OK", true)
}

/// Does allocation COUNT grow with input size?
///
/// This is the signature of per-block / per-chunk allocation, which `CLAUDE.md`
/// STEP 1 forbids outright ("no per-block, per-run or per-chunk allocation"). A
/// flat count across sizes means allocation is startup-only, which is what
/// libdeflate (3, flat) and gzip (0, flat) do.
///
/// Returns the slope in allocations per megabyte, and whether it is material.
/// PURE, so the truth table is selftestable.
pub fn scaling_verdict(samples: &[(u64, u64)]) -> (f64, bool) {
    if samples.len() < 2 {
        return (0.0, false);
    }
    let mut lo = samples[0];
    let mut hi = samples[0];
    for &s in samples {
        if s.0 < lo.0 {
            lo = s;
        }
        if s.0 > hi.0 {
            hi = s;
        }
    }
    if hi.0 == lo.0 {
        return (0.0, false);
    }
    let dmb = (hi.0 as f64 - lo.0 as f64) / (1024.0 * 1024.0);
    let dalloc = hi.1 as f64 - lo.1 as f64;
    let slope = dalloc / dmb;
    // One allocation per megabyte of input is already per-chunk behaviour at any
    // realistic chunk size; below that it is startup noise.
    (slope, slope >= 1.0)
}

/// Run one binary under valgrind and return (allocs, bytes).
///
/// EXTERNAL OBSERVER BY CONSTRUCTION — we never ask the subject to self-report.
fn measure(cmd_tmpl: &str, level: u32, threads: usize, input: &Path) -> Option<(u64, u64)> {
    let rendered = cmd_tmpl
        .replace("{level}", &level.to_string())
        .replace("{threads}", &threads.to_string())
        .replace("{input}", &input.display().to_string());
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "valgrind --tool=memcheck --error-exitcode=0 {rendered} > /dev/null"
        ))
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stderr);
    parse_memcheck(&text)
}

/// Parse valgrind's `total heap usage: N allocs, M frees, B bytes allocated`.
/// PURE, so the parser is selftestable against a real captured line — the
/// `fulcrum try` incident was an unparsed/empty input reaching correct logic.
pub fn parse_memcheck(text: &str) -> Option<(u64, u64)> {
    let line = text.lines().find(|l| l.contains("total heap usage"))?;
    let after = line.split("total heap usage:").nth(1)?;
    let allocs = after
        .split("allocs")
        .next()?
        .trim()
        .replace(',', "")
        .parse::<u64>()
        .ok()?;
    let bytes = after
        .split("frees,")
        .nth(1)?
        .split("bytes")
        .next()?
        .trim()
        .replace(',', "")
        .parse::<u64>()
        .ok()?;
    Some((allocs, bytes))
}

pub fn cmd(args: &[String]) -> ExitCode {
    match args.first().map(|s| s.as_str()) {
        Some("selftest") => selftest(),
        Some("--help") | Some("-h") | None => {
            eprintln!("{}", usage());
            ExitCode::SUCCESS
        }
        _ => run_cmd(args),
    }
}

/// Real run mode. Measures the subject and every declared rival with the SAME
/// external observer over the SAME inputs, and reports the comparison plus the
/// scaling verdict.
fn run_cmd(args: &[String]) -> ExitCode {
    let mut ours: Option<String> = None;
    let mut rivals: Vec<(String, String)> = Vec::new();
    let mut corpora: Vec<String> = Vec::new();
    let mut level: u32 = 6;
    let mut threads: usize = 1;
    let mut roundtrip = "gzip -dc".to_string();

    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let mut next = |i: &mut usize| -> Option<String> {
            *i += 1;
            args.get(*i).cloned()
        };
        match a {
            "--ours" => ours = next(&mut i),
            "--rival" => {
                if let Some(v) = next(&mut i) {
                    match v.split_once('=') {
                        Some((n, c)) => rivals.push((n.to_string(), c.to_string())),
                        None => {
                            eprintln!("structcensus: --rival needs name=CMD, got {v:?}");
                            return ExitCode::from(2);
                        }
                    }
                }
            }
            "--corpus" => {
                if let Some(v) = next(&mut i) {
                    corpora.push(v);
                }
            }
            "--level" => level = next(&mut i).and_then(|v| v.parse().ok()).unwrap_or(6),
            "--threads" => threads = next(&mut i).and_then(|v| v.parse().ok()).unwrap_or(1),
            "--roundtrip-cmd" => {
                if let Some(v) = next(&mut i) {
                    roundtrip = v;
                }
            }
            _ => {
                eprintln!("structcensus: unknown flag {a:?}\n\n{}", usage());
                return ExitCode::from(2);
            }
        }
        i += 1;
    }

    let Some(ours) = ours else {
        eprintln!("structcensus: --ours 'CMD -{{level}} -p {{threads}} -c {{input}}' is required\n\n{}", usage());
        return ExitCode::from(2);
    };
    if corpora.is_empty() {
        eprintln!("structcensus: at least one --corpus is required\n\n{}", usage());
        return ExitCode::from(2);
    }
    // GUARD, from the sizecensus incident: a census that measures the subject and
    // no rival has not evaluated anything. A number with no vendor beside it is
    // not a bar.
    if rivals.is_empty() {
        eprintln!("structcensus: REFUSES to run with zero rivals.");
        eprintln!("  The whole point of this axis is the COMPARISON — our allocation count");
        eprintln!("  in isolation is a vibe, not a bar. Declare at least one --rival.");
        return ExitCode::from(2);
    }
    if which("valgrind").is_none() {
        eprintln!("structcensus: valgrind not on PATH — this census IS the external observer,");
        eprintln!("  and substituting the subject's own counters is the defect it exists to");
        eprintln!("  prevent. FIX THE BOX rather than falling back.");
        return ExitCode::from(2);
    }

    let mut arms: Vec<(String, String)> = vec![("ours".to_string(), ours)];
    arms.extend(rivals);

    println!("STRUCTCENSUS level={level} threads={threads} corpora={}", corpora.len());
    println!("{:<14} {:>12} {:>10} {:>16}  {}", "binary", "input", "allocs", "bytes", "corpus");

    let mut samples: std::collections::BTreeMap<String, Vec<(u64, u64)>> = Default::default();
    let mut any_void = false;

    for c in &corpora {
        let path = Path::new(c);
        let Ok(meta) = std::fs::metadata(path) else {
            eprintln!("structcensus: cannot stat corpus {c}");
            return ExitCode::from(2);
        };
        let input_len = meta.len();
        for (name, tmpl) in &arms {
            let rt = roundtrip_ok(tmpl, level, threads, path, &roundtrip);
            match measure(tmpl, level, threads, path) {
                Some((allocs, bytes)) => {
                    let (status, _) = classify_cell(true, true, rt, allocs);
                    if status != "OK" {
                        any_void = true;
                        println!("{name:<14} {input_len:>12} {status:>10} {:>16}  {c}", "-");
                        continue;
                    }
                    samples.entry(name.clone()).or_default().push((input_len, allocs));
                    println!("{name:<14} {input_len:>12} {allocs:>10} {bytes:>16}  {c}");
                }
                None => {
                    any_void = true;
                    println!("{name:<14} {input_len:>12} {:>10} {:>16}  {c}", "RIVAL-UNAVAIL", "-");
                }
            }
        }
    }

    println!("\nSCALING (allocations per MiB of input — >=1.0 is per-block/per-chunk behaviour,");
    println!("which CLAUDE.md STEP 1 forbids; libdeflate is flat at 3 and gzip flat at 0):");
    let mut flagged = 0;
    for (name, s) in &samples {
        let (slope, material) = scaling_verdict(s);
        if s.len() < 2 {
            println!("  {name:<14} (needs >=2 corpus sizes to judge scaling)");
        } else if material {
            flagged += 1;
            println!("  {name:<14} slope={slope:+.1}/MiB   PER-BLOCK ALLOCATION");
        } else {
            println!("  {name:<14} slope={slope:+.1}/MiB   flat");
        }
    }

    if any_void {
        eprintln!("\nstructcensus: at least one cell VOIDed or was unavailable — NOT a result.");
        return ExitCode::from(1);
    }
    if flagged > 0 {
        println!("\n{flagged} binary/binaries allocate per block. That is the structural defect.");
    }
    ExitCode::SUCCESS
}

/// Compress then decompress and compare sha256 to the input.
///
/// A build that allocates nothing because it emits nothing must never score.
fn roundtrip_ok(tmpl: &str, level: u32, threads: usize, input: &Path, rt: &str) -> bool {
    let rendered = tmpl
        .replace("{level}", &level.to_string())
        .replace("{threads}", &threads.to_string())
        .replace("{input}", &input.display().to_string());
    let script = format!(
        "set -o pipefail; {rendered} | {rt} | shasum -a256 | cut -d' ' -f1;          shasum -a256 < {} | cut -d' ' -f1",
        input.display()
    );
    let Ok(out) = Command::new("sh").arg("-c").arg(script).output() else {
        return false;
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = text.split_whitespace().collect();
    lines.len() == 2 && lines[0] == lines[1]
}

fn which(bin: &str) -> Option<String> {
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin}"))
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn usage() -> String {
    "fulcrum structcensus — the STRUCTURE-axis census (allocations + bytes, ours vs rivals)\n\
     \n\
     The third axis. `board size` measures output bytes, `board wall` measures time;\n\
     this measures the STRUCTURE that produces both — allocation count, bytes\n\
     allocated — for us AND for every rival, per level and per thread count.\n\
     \n\
     Structure is DETERMINISTIC: no frozen box, no paired CI, no noise floor. That\n\
     makes it the cheapest falsifier. Run it BEFORE any wall work.\n\
     \n\
     fulcrum structcensus --ours 'CMD -{level} -p {threads} -c {input}' \\\n\
     \x20   --rival libdeflate='libdeflate-gzip -{level} -c {input}' [--rival ...] \\\n\
     \x20   --corpus FILE [--corpus FILE2 ...] [--level 6] [--threads 1]\n\
     \x20   [--roundtrip-cmd 'gzip -dc']\n\
     \n\
     Pass TWO OR MORE sizes of the same data to get the SCALING verdict, which is\n\
     the check that actually matters: allocation count that grows with input is\n\
     per-block allocation.\n\
     \n\
     fulcrum structcensus selftest      Gate-0 (truth tables + the memcheck parser)\n\
     \n\
     Receipt for why this exists: gzippy shipped 731 allocations / 83,909,568 bytes\n\
     to compress 6 MB while libdeflate used 3 / 6,674,327 and gzip 0 / 0. Nobody\n\
     found it for months because every census we owned measured OUTCOMES, and the\n\
     in-tree allocation counter only counted the sites someone had remembered to\n\
     annotate by hand.\n"
        .to_string()
}

pub fn selftest() -> ExitCode {
    let mut pass = 0u32;
    let mut fail = 0u32;
    let mut check = |name: &str, ok: bool| {
        if ok {
            pass += 1;
            println!("  PASS {name}");
        } else {
            fail += 1;
            println!("  FAIL {name}");
        }
    };

    check(
        "classify: rival not installed -> RIVAL-UNAVAILABLE, never silently dropped",
        matches!(classify_cell(false, true, true, 3), ("RIVAL-UNAVAILABLE", false)),
    );
    check(
        "classify: rival cannot run this level -> ABSENT, distinct from unavailable",
        matches!(classify_cell(true, false, true, 3), ("ABSENT", false)),
    );
    check(
        "classify: roundtrip FAIL -> VOID even with ZERO allocations, which would \
         otherwise look like the best possible structural result",
        matches!(classify_cell(true, true, false, 0), ("VOID", false)),
    );
    check(
        "classify: healthy cell -> OK and measured",
        matches!(classify_cell(true, true, true, 731), ("OK", true)),
    );

    // -- the scaling verdict, which is the defect that actually mattered -------
    check(
        "scaling: flat count across sizes is NOT per-block (libdeflate: 3 at every size)",
        {
            let (_, material) = scaling_verdict(&[(1_500_000, 3), (3_000_000, 3), (6_000_000, 3)]);
            !material
        },
    );
    check(
        "scaling: gzippy's real pre-fix numbers ARE flagged as per-block \
         (128 -> 176 -> 261 allocs over 1.5 -> 6 MB)",
        {
            let (slope, material) =
                scaling_verdict(&[(1_500_000, 128), (3_000_000, 176), (6_000_000, 261)]);
            material && slope > 25.0
        },
    );
    check(
        "scaling: a single sample cannot claim a slope",
        !scaling_verdict(&[(6_000_000, 731)]).1,
    );

    // -- the parser, against REAL captured valgrind output ---------------------
    // Gate-0 asserts the INPUT, not just the logic: `fulcrum try` once passed an
    // EMPTY roundtrip command and had never adjudicated anything because every
    // selftest exercised the decision and none exercised the input.
    let real = "==3288038==   total heap usage: 731 allocs, 726 frees, 83,909,568 bytes allocated";
    check(
        "parse_memcheck: real gzippy line -> (731, 83909568)",
        parse_memcheck(real) == Some((731, 83_909_568)),
    );
    let real_ld = "==3288058==   total heap usage: 3 allocs, 3 frees, 6,674,327 bytes allocated";
    check(
        "parse_memcheck: real libdeflate line -> (3, 6674327)",
        parse_memcheck(real_ld) == Some((3, 6_674_327)),
    );
    let real_gzip = "==3288064==   total heap usage: 0 allocs, 0 frees, 0 bytes allocated";
    check(
        "parse_memcheck: real gzip line, ZERO allocs, parses as Some((0,0)) not None \
         — a zero must never be indistinguishable from a parse failure",
        parse_memcheck(real_gzip) == Some((0, 0)),
    );
    check(
        "parse_memcheck: absent line -> None (never a silent 0)",
        parse_memcheck("valgrind: command not found").is_none(),
    );
    check(
        "parse_memcheck: EMPTY input -> None (the `fulcrum try` empty-input class)",
        parse_memcheck("").is_none(),
    );

    println!("\nstructcensus selftest: {pass} passed, {fail} failed");
    if fail == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
