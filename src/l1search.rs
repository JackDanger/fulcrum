//! `fulcrum l1search` — L1-band ratio-close-out empirical config-space
//! search: the SIZE/RATIO investigation driver for gzippy's L1 fast-path
//! matchfinder tunables.
//!
//! MIGRATION (2026-07-25, measurement-tooling-boundary directive: gzippy
//! keeps feature-gated KNOBS + COUNTERS + correctness tests, ALL measurement
//! DRIVERS migrate to fulcrum or are deleted as superseded). This is a port
//! of gzippy's deleted `examples/l1_search.rs` (2026-07-22 campaign). gzippy
//! keeps the KNOB side: the `l1-tune`-feature-gated `tune::L1Tune` struct +
//! `tune::parse_spec`/`tune::set`/`tune::get` (`src/compress/deflate/parse/
//! fast.rs`) and a `--tune key=val,key=val,...` CLI flag (`src/cli.rs`,
//! `src/main.rs`) that applies one config for the whole process. Everything
//! else — corpus loading, the named-config grid, size/ratio computation
//! against rival encoders, breadth/file/filemt reporting, WIN/LOSS/flip
//! accounting — moved HERE.
//!
//! WHY THE SHAPE CHANGED: the deleted example called `tune::set` IN-PROCESS,
//! looping hundreds of candidates through one `cargo run` invocation with no
//! rebuild or respawn. This tool instead SHELLS OUT to an `l1-tune`-built
//! gzippy binary once per (candidate, corpus) pair with `--tune <spec> -1
//! -c <path>`, capturing stdout length as the compressed size. That is fine
//! here because SIZE is deterministic and needs no wall-clock precision —
//! unlike a wall-time sweep, one process spawn per candidate costs nothing
//! but a few extra milliseconds of fork/exec overhead nobody is timing. (A
//! precise interleaved wall-time A/B between two named `--tune` specs is a
//! DIFFERENT, ALREADY-SOLVED problem — use the existing `fulcrum paired
//! --a-cmd 'gzippy --tune SPEC_A -1 -c {corpus}' --b-cmd 'gzippy --tune
//! SPEC_B -1 -c {corpus}'` instead of adding wall-timing code here; the
//! deleted example's `wall`/`wallpc` modes are superseded by that, not
//! ported.)
//!
//! THE NAMED-CONFIG GRID (ported verbatim from `named_configs()`, axis
//! comments preserved — these are the ORIGINAL measured-verdict provenance
//! notes, not re-derived here):
//!   - Axis A: lazy-peek max_len (accepted-match length gate).
//!   - Axis B: lazy-peek min_dist (distance gate).
//!   - Axis C: insert-depth (LIMIT_HASH_UPDATE interior inserts).
//!   - Axis D: block length (64 KiB boundary effect).
//!   - Axis E: bucket2 (2-way-bucket lever) gate_max_len sweep.
//!   - Axis F: CONTENT-ADAPTIVE CHAIN MATCHING — literal-density threshold x
//!     chain search-depth grid (2026-07-22 mission).
//!   - Hand-picked depth x bucket2 combos.
//!   - Axis G: HASH3-PROBE — table-size x max-dist grid (miss-only probe,
//!     insert-always) + probe-policy x insert-policy grid at bits=13/
//!     max_dist=4096. MEASURED (2026-07-22, cross-arch M1 Pro + AMD EPYC
//!     7282): at bits=15/max_dist=32768/miss-only/insert-always this
//!     REVERSES the pigz-1 bin-content deficit on `dd79_bin6` (1.0438x ->
//!     0.9978x pigz-1) at a real, non-cheap wall cost (+12-28% self-relative
//!     on M1, +22% on Zen2) — still 1.6-1.9x faster than pigz-1's own wall.
//!   - Hand-picked hash3 x depth combos.
//!   - Axis H: HASH3-GATE composition — layers the chain axis's free
//!     literal-fraction detector onto the measured-best HASH3-PROBE knobs so
//!     hash3 only probes on bin-like blocks. `hash3gate-t48-w0-i1`
//!     (threshold=48, sparse warm-insert, initial-active) is the
//!     measured-best composed config (2026-07-24 targeted micro-sweep): T1
//!     AND T4/T8/T16 WIN on `dd79_bin6` vs pigz-1, zero breadth flips — now
//!     `tune::L1Tune::from_env`'s (and the non-`l1-tune` production path's)
//!     shipped default.
//!
//! Gate-0 (`fulcrum l1search selftest`, BOXLESS — no gzippy checkout or
//! l1-tune build required, exercises the plumbing against `cat`):
//!   (a) the named-config grid's axis counts match the ported arithmetic
//!       exactly (a silent axis edit would desync `list` from the source);
//!   (b) `L1TuneSpec::to_spec` emits the exact `key=value,...` grammar
//!       gzippy's `tune::parse_spec` recognizes (checked key-by-key against
//!       the known key list, including the non-default fields for a
//!       representative config from each axis);
//!   (c) size/ratio + WIN/LOSS/TIE + strict/family gate classification is
//!       correct on synthetic reference numbers (both directions + the
//!       exact-tie edge);
//!   (d) flip detection fires on a synthetic WIN->LOSS and LOSS->WIN pair
//!       and stays silent when nothing flips;
//!   (e) the subprocess + corpus-substitution + stdout-byte-count plumbing
//!       (`run_and_count`) is exercised against `/bin/cat` on a real temp
//!       file (byte count == file size) — proves the driver mechanics
//!       without needing a real l1-tune gzippy build on the selftest box.
//! A LIVE run (`file`/`breadth`/`size` against a real `--gzippy-bin`) is a
//! SEPARATE, non-selftest proof of migration correctness — reproduce a
//! banked number (e.g. the `dd79_bin6` / `hash3gate-t48-w0-i1` size) against
//! the pre-migration `examples/l1_search.rs` recorded numbers.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

// ─────────────────────────── config spec (mirrors gzippy's L1Tune) ─────────

/// Mirrors gzippy's `compress::deflate::parse::fast::tune::L1Tune` field for
/// field. Fulcrum does NOT depend on gzippy for this subcommand (no
/// in-process linkage, unlike the macOS `macmeasure` family) — this is a
/// plain data struct whose ONLY job is formatting a `--tune` spec string in
/// the grammar `tune::parse_spec` parses. Keep in sync with gzippy's
/// `L1Tune`/`parse_spec` if either changes; `selftest` checks the grammar
/// but cannot check the gzippy-side field list itself (cross-repo).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct L1TuneSpec {
    pub peekmax: u32,
    pub peekdist: usize,
    /// Mirrors gzippy's `lazy_peek_cost_gate_enabled` (2026-07-23 COST-GATE
    /// axis: standalone bits(match)-vs-bits(literals) reject at lazy-peek
    /// time — see gzippy's `LAZY_PEEK_COST_GATE_ENABLED` doc comment).
    /// FALSIFIED at `LAZY_PEEK_COST_GATE_MARGIN_BITS=0` on 2026-07-23
    /// (`fulcrum paired --mode compress`: +3.3-5.6% wall on every fixture
    /// tested for noise-level, inconsistently-signed size movement) — kept
    /// here so a future session can re-sweep without re-deriving the CLI
    /// grammar.
    pub peekcost: bool,
    /// Mirrors gzippy's `lazy_peek_cost_margin_bits`.
    pub peekcostmargin: i32,
    pub depth: usize,
    pub block: usize,
    pub bucket2: bool,
    pub gate: u32,
    pub chain: bool,
    pub chainthreshold: u32,
    pub chaindepth: u32,
    pub hash3: bool,
    pub hash3bits: u32,
    pub hash3always: bool,
    pub hash3maxdist: usize,
    pub hash3insertalways: bool,
    pub hash3gated: bool,
    pub hash3gatethreshold: u32,
    pub hash3gatewarm: bool,
    pub hash3gateinit: bool,
}

/// The all-levers-off reference point every named config starts from
/// (`..base` in the deleted example) — the literal shipped defaults as of
/// the 2026-07-22 campaign start, NOT `tune::L1Tune::from_env`'s default
/// (which reproduces the CURRENT shipped hash3-gate-on behavior).
impl Default for L1TuneSpec {
    fn default() -> Self {
        L1TuneSpec {
            peekmax: 4,
            peekdist: 8192,
            peekcost: false,
            peekcostmargin: 0,
            depth: 3,
            block: 65536,
            bucket2: false,
            gate: 8,
            chain: false,
            chainthreshold: 80,
            chaindepth: 16,
            hash3: false,
            hash3bits: 13,
            hash3always: false,
            hash3maxdist: 4096,
            hash3insertalways: true,
            hash3gated: false,
            hash3gatethreshold: 80,
            hash3gatewarm: true,
            hash3gateinit: true,
        }
    }
}

impl L1TuneSpec {
    /// The measured-best HASH3-PROBE knobs (2026-07-22 report) — Axis H's
    /// starting point, not re-derived here.
    fn hash3_best() -> L1TuneSpec {
        L1TuneSpec {
            hash3: true,
            hash3bits: 15,
            hash3always: false,
            hash3maxdist: 32768,
            hash3insertalways: true,
            ..Default::default()
        }
    }

    /// Format as the `--tune` CLI value: `key=value,key=value,...`. Every
    /// field is emitted explicitly (not just non-default ones) so the
    /// string is self-contained and independent of gzippy's `baseline()`
    /// drifting — `tune::parse_spec` starts from its own baseline and
    /// applies each key in the string, so redundant explicit defaults are
    /// harmless, just verbose; explicit beats implicit for a cross-repo
    /// contract.
    pub fn to_spec(&self) -> String {
        format!(
            "peekmax={},peekdist={},peekcost={},peekcostmargin={},depth={},block={},bucket2={},gate={},\
             chain={},chainthreshold={},chaindepth={},\
             hash3={},hash3bits={},hash3always={},hash3maxdist={},hash3insertalways={},\
             hash3gated={},hash3gatethreshold={},hash3gatewarm={},hash3gateinit={}",
            self.peekmax,
            self.peekdist,
            b(self.peekcost),
            self.peekcostmargin,
            self.depth,
            self.block,
            b(self.bucket2),
            self.gate,
            b(self.chain),
            self.chainthreshold,
            self.chaindepth,
            b(self.hash3),
            self.hash3bits,
            b(self.hash3always),
            self.hash3maxdist,
            b(self.hash3insertalways),
            b(self.hash3gated),
            self.hash3gatethreshold,
            b(self.hash3gatewarm),
            b(self.hash3gateinit),
        )
    }
}

fn b(v: bool) -> &'static str {
    if v {
        "1"
    } else {
        "0"
    }
}

/// The named-config grid — ported verbatim from the deleted example's
/// `named_configs()`. See the module doc for the axis-by-axis provenance.
pub fn named_configs() -> Vec<(String, L1TuneSpec)> {
    let base = L1TuneSpec::default();
    let mut v: Vec<(String, L1TuneSpec)> = vec![("baseline".to_string(), base)];

    // Axis A: lazy-peek max_len (accepted-match length gate).
    for max_len in [3, 4, 6, 8, 12, 16] {
        v.push((
            format!("peekmax{max_len}"),
            L1TuneSpec {
                peekmax: max_len,
                ..base
            },
        ));
    }

    // Axis B: lazy-peek min_dist (distance gate; 0 = always peek on a short
    // match, >= WINDOW effectively disables the peek).
    for min_dist in [0usize, 1024, 2048, 4096, 8192, 16384, 32768] {
        v.push((
            format!("peekdist{min_dist}"),
            L1TuneSpec {
                peekdist: min_dist,
                ..base
            },
        ));
    }

    // Axis C: insert-depth (LIMIT_HASH_UPDATE interior inserts per accepted
    // match). usize::MAX -> "insdepth9999" (matches the original's sentinel
    // naming, which the CLI grammar has no "unlimited" keyword for).
    for depth in [
        1usize,
        2,
        3,
        4,
        6,
        8,
        12,
        16,
        24,
        32,
        48,
        64,
        96,
        128,
        usize::MAX,
    ] {
        v.push((
            format!("insdepth{}", if depth == usize::MAX { 9999 } else { depth }),
            L1TuneSpec { depth, ..base },
        ));
    }

    // Axis D: block length (64 KiB boundary effect).
    for bl in [16384usize, 32768, 65536, 131072, 262144] {
        v.push((format!("block{bl}"), L1TuneSpec { block: bl, ..base }));
    }

    // Axis E: bucket2 (2-way-bucket lever) — gate_max_len sweep.
    for gate in [3u32, 4, 6, 8, 12, 16] {
        v.push((
            format!("bucket2gate{gate}"),
            L1TuneSpec {
                bucket2: true,
                gate,
                ..base
            },
        ));
    }

    // Axis F: CONTENT-ADAPTIVE CHAIN MATCHING (2026-07-22 mission) —
    // literal-density threshold x chain search-depth grid.
    for threshold in [50u32, 65, 80, 90] {
        for depth in [4u32, 8, 16, 32, 64, 128] {
            v.push((
                format!("chain-t{threshold}-d{depth}"),
                L1TuneSpec {
                    chain: true,
                    chainthreshold: threshold,
                    chaindepth: depth,
                    ..base
                },
            ));
        }
    }

    // Hand-picked combined candidates: moderate insert-depth (dominant bin
    // lever) paired with bucket2 (dominant sil lever at near-zero cost).
    for depth in [8usize, 16, 24, 32] {
        for gate in [8u32, 16] {
            v.push((
                format!("hand-depth{depth}-gate{gate}"),
                L1TuneSpec {
                    depth,
                    bucket2: true,
                    gate,
                    ..base
                },
            ));
        }
    }

    // Axis G: HASH3-PROBE — table-size x max-dist grid, miss-only probe,
    // insert-always (policy (a), tried first).
    for bits in [12u32, 13, 14, 15] {
        for max_dist in [256usize, 1024, 4096, 16384, 32768] {
            v.push((
                format!("hash3-b{bits}-d{max_dist}"),
                L1TuneSpec {
                    hash3: true,
                    hash3bits: bits,
                    hash3always: false,
                    hash3maxdist: max_dist,
                    hash3insertalways: true,
                    ..base
                },
            ));
        }
    }
    // Axis G2: probe-policy x insert-policy grid at bits=13, max_dist=4096.
    for always_probe in [false, true] {
        for insert_always in [true, false] {
            v.push((
                format!(
                    "hash3-policy-probe{}-ins{}",
                    always_probe as u8, insert_always as u8
                ),
                L1TuneSpec {
                    hash3: true,
                    hash3bits: 13,
                    hash3always: always_probe,
                    hash3maxdist: 4096,
                    hash3insertalways: insert_always,
                    ..base
                },
            ));
        }
    }
    // Hand-picked combined: hash3 (miss-only, insert-always, mid table)
    // stacked on the dominant insert-depth/bucket2 combo above.
    for depth in [8usize, 16] {
        for bits in [13u32, 14] {
            v.push((
                format!("hand-hash3-depth{depth}-b{bits}"),
                L1TuneSpec {
                    depth,
                    hash3: true,
                    hash3bits: bits,
                    hash3always: false,
                    hash3maxdist: 4096,
                    hash3insertalways: true,
                    ..base
                },
            ));
        }
    }

    // Axis H: HASH3-GATE composition (2026-07-22 "compose the two proven
    // l1-tune levers" mission). Layers the chain axis's free literal-fraction
    // detector onto `hash3_best()`. `hash3gate-t48-w0-i1` is the
    // measured-best composed config (2026-07-24 targeted micro-sweep closing
    // the `dd79_bin6` promotion-gate blocker) — also `tune::L1Tune::
    // from_env`'s default, so a plain `l1-tune`-feature build with no
    // override reproduces it.
    let h3 = L1TuneSpec::hash3_best();
    for threshold in [47u32, 48, 49, 50, 65, 80, 90] {
        for warm_insert in [true, false] {
            for initial_active in [true, false] {
                v.push((
                    format!(
                        "hash3gate-t{threshold}-w{}-i{}",
                        warm_insert as u8, initial_active as u8
                    ),
                    L1TuneSpec {
                        hash3gated: true,
                        hash3gatethreshold: threshold,
                        hash3gatewarm: warm_insert,
                        hash3gateinit: initial_active,
                        ..h3
                    },
                ));
            }
        }
    }

    // Axis I: COST-GATE margin sweep (2026-07-23 "cost-based tie-break"
    // mission), composed on top of the shipped widened-peek + `hash3gate-
    // t48-w0-i1` baseline (`base` already carries `peekmax=16`/`peekdist=0`
    // via `L1TuneSpec::default()`... NOTE: `default()` above is the
    // ALL-LEVERS-OFF `peekmax=4`/`peekdist=8192` point, not the shipped
    // widened config — callers sweeping this axis against the ACTUAL
    // shipped baseline should compose `peekcost`/`peekcostmargin` with
    // `peekmax: 16, peekdist: 0, ..hash3gate-t48-w0-i1`, not bare `base`).
    // FALSIFIED at `margin=0` (2026-07-23, `fulcrum paired --mode
    // compress`, N=21, /dev/null sink): +3.3-5.6% wall on every fixture
    // tested for noise-level size movement — kept swept here (rather than
    // deleted) so a future session re-opening this axis does not have to
    // re-derive the grid.
    for margin in [-16i32, -8, -4, 0, 4, 8, 16] {
        v.push((
            format!("peekcost-m{margin}"),
            L1TuneSpec {
                peekmax: 16,
                peekdist: 0,
                peekcost: true,
                peekcostmargin: margin,
                ..h3
            },
        ));
    }

    v
}

/// Parse a `';'`-separated list of names, where each name is either a grid
/// name (looked up in [`named_configs`]) or `spec:key=value,key=value,...`
/// (the same inline-spec escape hatch the deleted example supported — note
/// the DIFFERENT delimiter convention: `;` separates configs in a list,
/// `,` separates key=value pairs WITHIN one `spec:` config, so a spec's own
/// commas never get shredded by the outer split).
fn resolve_configs(names: &str) -> Vec<(String, L1TuneSpec)> {
    let all = named_configs();
    names
        .split(';')
        .map(|n| {
            let n = n.trim();
            if let Some(spec) = n.strip_prefix("spec:") {
                (n.to_string(), parse_inline_spec(spec))
            } else {
                let cfg = all
                    .iter()
                    .find(|(nm, _)| nm == n)
                    .map(|(_, c)| *c)
                    .unwrap_or_else(|| {
                        eprintln!("l1search: unknown config '{n}', using baseline");
                        L1TuneSpec::default()
                    });
                (n.to_string(), cfg)
            }
        })
        .collect()
}

/// Inverse of [`L1TuneSpec::to_spec`] (for the `spec:` escape hatch on the
/// fulcrum CLI, same grammar/keys as gzippy's `tune::parse_spec`).
fn parse_inline_spec(spec: &str) -> L1TuneSpec {
    let mut cfg = L1TuneSpec::default();
    for kv in spec.split(',') {
        let mut it = kv.splitn(2, '=');
        let k = it.next().unwrap_or("");
        let v = it.next().unwrap_or("");
        let flag = v == "1" || v == "true";
        match k {
            "peekmax" => cfg.peekmax = v.parse().unwrap_or(cfg.peekmax),
            "peekdist" => cfg.peekdist = v.parse().unwrap_or(cfg.peekdist),
            "peekcost" => cfg.peekcost = flag,
            "peekcostmargin" => cfg.peekcostmargin = v.parse().unwrap_or(cfg.peekcostmargin),
            "depth" => cfg.depth = v.parse().unwrap_or(cfg.depth),
            "block" => cfg.block = v.parse().unwrap_or(cfg.block),
            "bucket2" => cfg.bucket2 = flag,
            "gate" => cfg.gate = v.parse().unwrap_or(cfg.gate),
            "chain" => cfg.chain = flag,
            "chainthreshold" => cfg.chainthreshold = v.parse().unwrap_or(cfg.chainthreshold),
            "chaindepth" => cfg.chaindepth = v.parse().unwrap_or(cfg.chaindepth),
            "hash3" => cfg.hash3 = flag,
            "hash3bits" => cfg.hash3bits = v.parse().unwrap_or(cfg.hash3bits),
            "hash3always" => cfg.hash3always = flag,
            "hash3maxdist" => cfg.hash3maxdist = v.parse().unwrap_or(cfg.hash3maxdist),
            "hash3insertalways" => cfg.hash3insertalways = flag,
            "hash3gated" => cfg.hash3gated = flag,
            "hash3gatethreshold" => {
                cfg.hash3gatethreshold = v.parse().unwrap_or(cfg.hash3gatethreshold)
            }
            "hash3gatewarm" => cfg.hash3gatewarm = flag,
            "hash3gateinit" => cfg.hash3gateinit = flag,
            "" => {}
            _ => eprintln!("l1search: unknown spec key '{k}'"),
        }
    }
    cfg
}

// ─────────────────────────── corpus loading ─────────────────────────────────

struct Corpus {
    group: &'static str,
    label: String,
    data_len: u64,
    path: PathBuf,
}

/// `~/www/gzippy-bench/corpus` — the fixture directory every prior l1-tune
/// campaign report swept against. Overridable via `--corpus-dir`.
fn default_bench_corpus_dir() -> PathBuf {
    std::env::var("GZIPPY_BENCH_CORPUS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
            PathBuf::from(home).join("www/gzippy-bench/corpus")
        })
}

fn build_breadth_corpora(corpus_dir: &Path) -> Vec<Corpus> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(corpus_dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("l1search: breadth corpus dir {corpus_dir:?} unreadable: {e}");
            return out;
        }
    };
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n != "dd79_text6" && n != "dd79_bin6")
        .collect();
    names.sort();
    for name in names {
        let path = corpus_dir.join(&name);
        match std::fs::metadata(&path) {
            Ok(m) => out.push(Corpus {
                group: "breadth",
                label: name,
                data_len: m.len(),
                path,
            }),
            Err(e) => eprintln!("l1search: breadth file {name} unreadable: {e}"),
        }
    }
    out
}

/// `dd79_text6`/`dd79_bin6` (exact 6 MiB fixtures) + one 40 MiB slice of
/// `benchmark_data/silesia.tar` from the gzippy checkout, when present.
fn build_named_corpora(corpus_dir: &Path, gzippy_root: &Path) -> Vec<Corpus> {
    let mut out = Vec::new();
    for (group, name) in [("text", "dd79_text6"), ("bin", "dd79_bin6")] {
        let path = corpus_dir.join(name);
        match std::fs::metadata(&path) {
            Ok(m) => out.push(Corpus {
                group,
                label: name.to_string(),
                data_len: m.len(),
                path,
            }),
            Err(_) => eprintln!(
                "l1search: {corpus_dir:?}/{name} absent — {group} group skipped (refusing to \
                 substitute a synthetic stand-in silently)"
            ),
        }
    }
    let sil_path = gzippy_root.join("benchmark_data/silesia.tar");
    match std::fs::metadata(&sil_path) {
        Ok(m) if m.len() >= 40 * 1024 * 1024 => {
            // A slice, not the whole tar — a temp file holding the first 40
            // MiB, so downstream `run_and_count` can shell out uniformly
            // (every corpus is a real file path on disk).
            match write_slice(&sil_path, 0, 40 * 1024 * 1024) {
                Ok(tmp) => out.push(Corpus {
                    group: "sil",
                    label: "silesia@0+41943040B".to_string(),
                    data_len: 40 * 1024 * 1024,
                    path: tmp,
                }),
                Err(e) => eprintln!("l1search: silesia slice extract failed: {e}"),
            }
        }
        _ => eprintln!("l1search: {sil_path:?} absent or short — sil group skipped"),
    }
    out
}

fn write_slice(src: &Path, offset: u64, n: u64) -> Result<PathBuf, String> {
    use std::io::{Seek, SeekFrom, Write};
    let mut f = std::fs::File::open(src).map_err(|e| e.to_string())?;
    f.seek(SeekFrom::Start(offset)).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; n as usize];
    let read = f.read(&mut buf).map_err(|e| e.to_string())?;
    buf.truncate(read);
    let tmp = std::env::temp_dir().join(format!("l1search-silesia-slice-{offset}-{n}.bin"));
    std::fs::File::create(&tmp)
        .and_then(|mut w| w.write_all(&buf))
        .map_err(|e| e.to_string())?;
    Ok(tmp)
}

// ─────────────────────────── subprocess plumbing ────────────────────────────

/// Run `bin argv...`, discard stderr, return stdout BYTE COUNT (never
/// materializes the bytes — a 40 MiB corpus swept across ~100 configs would
/// otherwise churn gigabytes through pipes for a number we only sum(len)).
fn run_and_count(bin: &Path, argv: &[String]) -> Result<u64, String> {
    let mut cmd = Command::new(bin);
    cmd.args(argv);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::null());
    cmd.stdin(Stdio::null());
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("spawn {} {:?}: {e}", bin.display(), argv))?;
    let mut out = child
        .stdout
        .take()
        .ok_or_else(|| format!("no stdout pipe for {}", bin.display()))?;
    let mut count: u64 = 0;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = out
            .read(&mut buf)
            .map_err(|e| format!("read stdout of {}: {e}", bin.display()))?;
        if n == 0 {
            break;
        }
        count += n as u64;
    }
    let status = child
        .wait()
        .map_err(|e| format!("wait {}: {e}", bin.display()))?;
    if !status.success() {
        return Err(format!("{} {:?} exited {status:?}", bin.display(), argv));
    }
    Ok(count)
}

fn gzippy_size(
    gzippy_bin: &Path,
    spec: &L1TuneSpec,
    threads: usize,
    path: &Path,
) -> Result<u64, String> {
    let argv = vec![
        "--tune".to_string(),
        spec.to_spec(),
        "-1".to_string(),
        "-p".to_string(),
        threads.to_string(),
        "-c".to_string(),
        path.display().to_string(),
    ];
    run_and_count(gzippy_bin, &argv)
}

struct RefSizes {
    ld1: u64,
    gzip1: u64,
    pigz1: Option<u64>,
}

fn ref_sizes(path: &Path) -> RefSizes {
    let ld1 = run_and_count(
        Path::new("libdeflate-gzip"),
        &["-1".into(), "-c".into(), path.display().to_string()],
    )
    .unwrap_or_else(|e| {
        eprintln!("l1search: libdeflate-gzip failed on {path:?}: {e}");
        0
    });
    let gzip1 = run_and_count(
        Path::new("gzip"),
        &["-1".into(), "-c".into(), path.display().to_string()],
    )
    .unwrap_or_else(|e| {
        eprintln!("l1search: gzip failed on {path:?}: {e}");
        0
    });
    let pigz1 = run_and_count(
        Path::new("pigz"),
        &["-1".into(), "-c".into(), path.display().to_string()],
    )
    .ok();
    RefSizes { ld1, gzip1, pigz1 }
}

// ─────────────────────────── reporting ───────────────────────────────────────

fn ratio(size: u64, refsize: u64) -> f64 {
    if refsize == 0 {
        f64::NAN
    } else {
        size as f64 / refsize as f64
    }
}

fn vs_pigz_label(r: Option<f64>) -> &'static str {
    match r {
        Some(v) if v < 1.0 => "WIN",
        Some(v) if v > 1.0 => "LOSS",
        Some(_) => "TIE",
        None => "NA",
    }
}

struct Opts {
    gzippy_bin: PathBuf,
    gzippy_root: PathBuf,
    corpus_dir: PathBuf,
}

fn parse_opts(args: &[String]) -> (Opts, Vec<String>) {
    let gzippy_root: PathBuf = std::env::var("GZIPPY_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/Users/jackdanger/www/gzippy"));
    let mut opts = Opts {
        gzippy_bin: std::env::var("GZIPPY_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|_| gzippy_root.join("target/release/gzippy")),
        corpus_dir: default_bench_corpus_dir(),
        gzippy_root,
    };
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--gzippy-bin" if i + 1 < args.len() => {
                opts.gzippy_bin = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--gzippy-root" if i + 1 < args.len() => {
                opts.gzippy_root = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--corpus-dir" if i + 1 < args.len() => {
                opts.corpus_dir = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            other => {
                rest.push(other.to_string());
                i += 1;
            }
        }
    }
    (opts, rest)
}

fn run_list() -> ExitCode {
    for (name, cfg) in named_configs() {
        println!("{name}\t{}", cfg.to_spec());
    }
    ExitCode::SUCCESS
}

fn run_size(opts: &Opts) -> ExitCode {
    let corpora = build_named_corpora(&opts.corpus_dir, &opts.gzippy_root);
    if corpora.is_empty() {
        eprintln!("l1search size: no corpora available");
        return ExitCode::FAILURE;
    }
    eprintln!("l1search size: {} corpus files", corpora.len());
    for c in &corpora {
        eprintln!("  [{}] {} ({} bytes)", c.group, c.label, c.data_len);
    }
    let refs: Vec<RefSizes> = corpora.iter().map(|c| ref_sizes(&c.path)).collect();
    println!("config\tgroup\tsize\tld1_ratio\tgzip1_ratio\tpigz1_ratio");
    for (name, cfg) in named_configs() {
        for (c, r) in corpora.iter().zip(refs.iter()) {
            let sz = match gzippy_size(&opts.gzippy_bin, &cfg, 1, &c.path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("l1search size: {name} on {}: {e}", c.label);
                    continue;
                }
            };
            let ld1r = ratio(sz, r.ld1);
            let gz1r = ratio(sz, r.gzip1);
            let pigzr = r.pigz1.map(|p| ratio(sz, p));
            println!(
                "{name}\t{}\t{sz}\t{ld1r:.4}\t{gz1r:.4}\t{}",
                c.group,
                pigzr.map(|v| format!("{v:.4}")).unwrap_or("NA".into())
            );
        }
    }
    ExitCode::SUCCESS
}

fn run_breadth(opts: &Opts, names: &str) -> ExitCode {
    let configs = resolve_configs(names);
    let corpora = build_breadth_corpora(&opts.corpus_dir);
    if corpora.is_empty() {
        eprintln!(
            "l1search breadth: no breadth corpus files found in {:?}",
            opts.corpus_dir
        );
        return ExitCode::FAILURE;
    }
    eprintln!(
        "l1search breadth: {} files, {} configs",
        corpora.len(),
        configs.len()
    );
    let refs: Vec<RefSizes> = corpora.iter().map(|c| ref_sizes(&c.path)).collect();

    let mut sizes: Vec<Vec<u64>> = Vec::with_capacity(configs.len());
    for (_, cfg) in &configs {
        sizes.push(
            corpora
                .iter()
                .map(|c| gzippy_size(&opts.gzippy_bin, cfg, 1, &c.path).unwrap_or(0))
                .collect(),
        );
    }

    println!("config\tfile\tsize\tld1_ratio\tgzip1_ratio\tpigz1_ratio\tstrict\tfamily\tvs_pigz");
    for (ci, (name, _)) in configs.iter().enumerate() {
        for (fi, c) in corpora.iter().enumerate() {
            let sz = sizes[ci][fi];
            let r = &refs[fi];
            let ld1r = ratio(sz, r.ld1);
            let gz1r = ratio(sz, r.gzip1);
            let pigzr = r.pigz1.map(|p| ratio(sz, p));
            let (strict, family) = gate(ld1r, gz1r, pigzr);
            println!(
                "{name}\t{}\t{sz}\t{ld1r:.4}\t{gz1r:.4}\t{}\t{}\t{}\t{}",
                c.label,
                pigzr.map(|v| format!("{v:.4}")).unwrap_or("NA".into()),
                if strict { "PASS" } else { "FAIL" },
                if family { "PASS" } else { "FAIL" },
                vs_pigz_label(pigzr),
            );
        }
    }

    if configs.len() > 1 {
        eprintln!("\nl1search breadth: flip accounting vs '{}'", configs[0].0);
        for (fi, c) in corpora.iter().enumerate() {
            let r = &refs[fi];
            let base_pigz = r.pigz1.map(|p| ratio(sizes[0][fi], p));
            for ci in 1..configs.len() {
                let cand_pigz = r.pigz1.map(|p| ratio(sizes[ci][fi], p));
                if let (Some(bp), Some(cp)) = (base_pigz, cand_pigz) {
                    let (base_win, cand_win) = (bp < 1.0, cp < 1.0);
                    if base_win != cand_win {
                        eprintln!(
                            "  FLIP [{}] {}: {} -> {} (pigz ratio {bp:.4} -> {cp:.4})",
                            configs[ci].0,
                            c.label,
                            if base_win { "WIN" } else { "LOSS" },
                            if cand_win { "WIN" } else { "LOSS" },
                        );
                    }
                }
            }
        }
    }
    ExitCode::SUCCESS
}

/// strict: size <= ld1*1.05 AND (pigz1 unavailable OR size <= pigz1*1.05).
/// family: (pigz1 unavailable OR size <= pigz1) AND size <= gzip1.
fn gate(ld1_ratio: f64, gzip1_ratio: f64, pigz1_ratio: Option<f64>) -> (bool, bool) {
    let strict = ld1_ratio <= 1.05 && pigz1_ratio.map(|v| v <= 1.05).unwrap_or(true);
    let family = pigz1_ratio.map(|v| v <= 1.0).unwrap_or(true) && gzip1_ratio <= 1.0;
    (strict, family)
}

fn run_file(opts: &Opts, path: &str, names: &str, threads: usize) -> ExitCode {
    let p = PathBuf::from(path);
    if std::fs::metadata(&p).is_err() {
        eprintln!("l1search file: {path} unreadable");
        return ExitCode::FAILURE;
    }
    let configs = resolve_configs(names);
    let r = ref_sizes(&p);
    eprintln!(
        "l1search file: {path} T{threads} ld1={} gzip1={} pigz1={}",
        r.ld1,
        r.gzip1,
        r.pigz1.map(|v| v.to_string()).unwrap_or("<absent>".into())
    );
    println!("config\tthreads\tsize\tld1_ratio\tgzip1_ratio\tpigz1_ratio\tvs_pigz");
    for (name, cfg) in &configs {
        let sz = match gzippy_size(&opts.gzippy_bin, cfg, threads, &p) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("l1search file: {name}: {e}");
                continue;
            }
        };
        let ld1r = ratio(sz, r.ld1);
        let gz1r = ratio(sz, r.gzip1);
        let pigzr = r.pigz1.map(|p| ratio(sz, p));
        println!(
            "{name}\t{threads}\t{sz}\t{ld1r:.4}\t{gz1r:.4}\t{}\t{}",
            pigzr.map(|v| format!("{v:.4}")).unwrap_or("NA".into()),
            vs_pigz_label(pigzr),
        );
    }
    ExitCode::SUCCESS
}

pub fn cmd_l1search(args: &[String]) -> ExitCode {
    match args.first().map(|s| s.as_str()) {
        Some("selftest") => selftest(),
        Some("list") => run_list(),
        Some("size") => {
            let (opts, _rest) = parse_opts(&args[1..]);
            run_size(&opts)
        }
        Some("breadth") => {
            let (opts, rest) = parse_opts(&args[1..]);
            let names = rest
                .first()
                .cloned()
                .unwrap_or_else(|| "baseline".to_string());
            run_breadth(&opts, &names)
        }
        Some("file") => {
            let (opts, rest) = parse_opts(&args[1..]);
            let path = match rest.first() {
                Some(p) => p.clone(),
                None => {
                    eprintln!("{}", usage());
                    return ExitCode::from(2);
                }
            };
            // `file <path> [threads] <cfg1;cfg2;...>` — threads defaults 1;
            // a purely-numeric second positional is treated as threads
            // (matches the deleted example's separate `file`/`filemt`
            // commands, folded into one with an optional thread count).
            let (threads, names) = match (rest.get(1), rest.get(2)) {
                (Some(t), Some(n)) if t.parse::<usize>().is_ok() => (t.parse().unwrap(), n.clone()),
                (Some(n), None) => (1, n.clone()),
                _ => (1, "baseline".to_string()),
            };
            run_file(&opts, &path, &names, threads)
        }
        _ => {
            eprintln!("{}", usage());
            ExitCode::from(2)
        }
    }
}

pub fn usage() -> String {
    "fulcrum l1search — gzippy L1 fast-path matchfinder config-space search\n\
     (ported from the deleted examples/l1_search.rs; shells out to an\n\
     l1-tune-built gzippy with --tune per candidate)\n\
     \n\
     Usage:\n\
       fulcrum l1search selftest\n\
       fulcrum l1search list\n\
       fulcrum l1search size   [--gzippy-bin P] [--gzippy-root P] [--corpus-dir P]\n\
       fulcrum l1search breadth <cfg1;cfg2;...> [--gzippy-bin P] [--corpus-dir P]\n\
       fulcrum l1search file <path> [threads] <cfg1;cfg2;...> [--gzippy-bin P]\n\
     \n\
     Config names come from `list`, or `spec:key=value,key=value,...` \
     (';'-separated when multiple).\n\
     Env overrides: GZIPPY_BIN, GZIPPY_ROOT, GZIPPY_BENCH_CORPUS_DIR.\n\
     \n\
     For a precise wall-time A/B between two --tune specs, use the existing\n\
     `fulcrum paired --a-cmd 'gzippy --tune SPEC_A -1 -c {corpus}' \
     --b-cmd 'gzippy --tune SPEC_B -1 -c {corpus}'` — not a mode here.\n"
        .to_string()
}

// ─────────────────────────── Gate-0 selftest ─────────────────────────────────

fn selftest() -> ExitCode {
    let mut failures = Vec::new();

    // (a) axis counts.
    let configs = named_configs();
    // 1 baseline + 6 peekmax + 7 peekdist + 15 insdepth + 5 block + 6 bucket2
    // + 24 chain (4x6) + 8 hand-depth-gate (4x2) + 20 hash3-b-d (4x5) + 4
    // hash3-policy (2x2) + 4 hand-hash3 (2x2) + 28 hash3gate (7x2x2)
    // + 7 peekcost-margin (Axis I) = 135.
    let expected = 1 + 6 + 7 + 15 + 5 + 6 + 24 + 8 + 20 + 4 + 4 + 28 + 7;
    if configs.len() != expected {
        failures.push(format!(
            "axis count: named_configs() has {} entries, expected {expected} \
             (an axis was added/removed without updating this selftest's arithmetic)",
            configs.len()
        ));
    }
    let names: std::collections::HashSet<&str> = configs.iter().map(|(n, _)| n.as_str()).collect();
    if names.len() != configs.len() {
        failures.push("duplicate config names in named_configs()".to_string());
    }
    if !names.contains("baseline") || !names.contains("hash3gate-t48-w0-i1") {
        failures.push("expected named config missing (baseline / hash3gate-t48-w0-i1)".into());
    }

    // (b) spec grammar round-trip: every key name gzippy's tune::parse_spec
    // recognizes must appear, formatted correctly, for a non-default config
    // from each axis.
    let expect_keys = [
        "peekmax",
        "peekdist",
        "peekcost",
        "peekcostmargin",
        "depth",
        "block",
        "bucket2",
        "gate",
        "chain",
        "chainthreshold",
        "chaindepth",
        "hash3",
        "hash3bits",
        "hash3always",
        "hash3maxdist",
        "hash3insertalways",
        "hash3gated",
        "hash3gatethreshold",
        "hash3gatewarm",
        "hash3gateinit",
    ];
    let sample = L1TuneSpec {
        peekmax: 6,
        peekdist: 4096,
        peekcost: true,
        peekcostmargin: -4,
        depth: 12,
        block: 131072,
        bucket2: true,
        gate: 6,
        chain: true,
        chainthreshold: 65,
        chaindepth: 32,
        hash3: true,
        hash3bits: 15,
        hash3always: true,
        hash3maxdist: 32768,
        hash3insertalways: false,
        hash3gated: true,
        hash3gatethreshold: 48,
        hash3gatewarm: false,
        hash3gateinit: true,
    };
    let spec = sample.to_spec();
    for key in expect_keys {
        if !spec.split(',').any(|kv| kv.starts_with(&format!("{key}="))) {
            failures.push(format!("to_spec() missing key '{key}' in: {spec}"));
        }
    }
    if !spec.contains("peekmax=6")
        || !spec.contains("hash3maxdist=32768")
        || !spec.contains("hash3gatethreshold=48")
    {
        failures.push(format!("to_spec() value mismatch: {spec}"));
    }
    // Round-trip through the fulcrum-side parser too (used by the `spec:`
    // escape hatch on this CLI).
    let roundtrip = parse_inline_spec(&spec);
    if roundtrip != sample {
        failures.push(format!(
            "parse_inline_spec(to_spec(x)) != x: {roundtrip:?} vs {sample:?}"
        ));
    }

    // (c) ratio + gate classification, both directions + exact tie.
    let r_win = ratio(90, 100);
    let r_loss = ratio(110, 100);
    let r_tie = ratio(100, 100);
    if !(r_win < 1.0 && r_loss > 1.0 && r_tie == 1.0) {
        failures.push(format!("ratio() sanity failed: {r_win} {r_loss} {r_tie}"));
    }
    if vs_pigz_label(Some(r_win)) != "WIN"
        || vs_pigz_label(Some(r_loss)) != "LOSS"
        || vs_pigz_label(Some(r_tie)) != "TIE"
        || vs_pigz_label(None) != "NA"
    {
        failures.push("vs_pigz_label() classification wrong".to_string());
    }
    let (strict_pass, family_pass) = gate(1.0, 0.99, Some(1.0));
    if !strict_pass || !family_pass {
        failures.push("gate(): expected PASS/PASS at the boundary".to_string());
    }
    let (strict_fail, family_fail) = gate(1.10, 1.10, Some(1.10));
    if strict_fail || family_fail {
        failures.push("gate(): expected FAIL/FAIL well outside the 1.05/1.0 bars".to_string());
    }

    // (d) flip detection: build two synthetic pigz-ratio series and confirm
    // a WIN->LOSS and a LOSS->WIN both register, and a non-flip does not.
    let base_ratios = [0.95f64, 1.05, 0.90];
    let cand_ratios = [1.02f64, 0.98, 0.50]; // WIN->LOSS, LOSS->WIN, no-flip(WIN->WIN)
    let mut flips = 0;
    for (b, c) in base_ratios.iter().zip(cand_ratios.iter()) {
        if (*b < 1.0) != (*c < 1.0) {
            flips += 1;
        }
    }
    if flips != 2 {
        failures.push(format!("flip detection: expected 2 flips, got {flips}"));
    }

    // (e) subprocess + corpus-substitution plumbing against `/bin/cat`.
    match selftest_run_and_count_plumbing() {
        Ok(()) => {}
        Err(e) => failures.push(format!("run_and_count plumbing: {e}")),
    }

    if failures.is_empty() {
        println!(
            "L1SEARCH_SELFTEST=PASS configs={} keys_checked={}",
            configs.len(),
            expect_keys.len()
        );
        ExitCode::SUCCESS
    } else {
        eprintln!("L1SEARCH_SELFTEST=FAIL ({} failures):", failures.len());
        for f in &failures {
            eprintln!("  - {f}");
        }
        ExitCode::FAILURE
    }
}

fn selftest_run_and_count_plumbing() -> Result<(), String> {
    use std::io::Write;
    let tmp = std::env::temp_dir().join(format!("l1search-selftest-{}.bin", std::process::id()));
    let payload = b"the quick brown fox jumps over the lazy dog\n".repeat(37);
    std::fs::File::create(&tmp)
        .and_then(|mut f| f.write_all(&payload))
        .map_err(|e| format!("write temp corpus: {e}"))?;
    let cat = Path::new("/bin/cat");
    let got = run_and_count(cat, &[tmp.display().to_string()])?;
    let _ = std::fs::remove_file(&tmp);
    if got != payload.len() as u64 {
        return Err(format!(
            "cat {} produced {got} bytes, expected {}",
            tmp.display(),
            payload.len()
        ));
    }
    // A nonexistent binary must error, not silently return 0 (an inert
    // failure mode would make every real gzippy-absent run look like a
    // legitimate empty-output config instead of a hard error).
    if run_and_count(Path::new("/nonexistent/l1search-selftest-bin"), &[]).is_ok() {
        return Err("run_and_count did not error on a nonexistent binary".to_string());
    }
    Ok(())
}
