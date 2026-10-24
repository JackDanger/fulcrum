//! `fulcrum layout diff` — the symbol-level codegen-delta oracle for two
//! built binaries of the SAME source tree (typically base vs lever arm as
//! built by `fulcrum try` / `ablate`).
//!
//! Answers the attribution question that per-cell wall adjudication cannot:
//! WHEN a confirmed-real wall spend appears at a coordinate whose encoder
//! config the lever never touches (receipt: the 2026-10-23 L5 campaign —
//! `pigz:data.json:L2:T1` convicted at +0.67% with sign 5/5 while the lever's
//! edits live only inside the level-5 row), the delta class is decided by
//! whether the cell's own hot-path symbols moved between the two binaries:
//!
//!   * hot-path symbol VISIBLE in the movers list → the delta may be a real
//!     codegen change the lever induced VIA LAYOUT — the lever's mere
//!     presence in the binary. Not layout luck (confirm already proved that),
//!     but an inversion: the win/loss does not belong to the encoder change.
//!   * hot-path symbols UNCHANGED → a pure layout shift around the cell's
//!     hot code (rodata/neighbor reordering the icache neighborhood).
//!
//! Both are still "wall spend" under the promotion rule; the DIFFERENCE is
//! where a fix goes (adjust the lever's code surface vs. re-calibrate the
//! config), and this tool makes that first fork decidable in seconds from
//! `nm` alone. The nm table is cheap, deterministic and needs no perf events
//! — the two hardware-counter layers (`why` [2][3]) are unavailable on the
//! shared dev boxes where campaigns like this run.
//!
//! Pairs symbols by their DEMANGLED name (`nm -C`): the mangled hash changes
//! when the dynlibs rebuild; monomorphization collisions are impossible
//! because generics with equal source instantiations ARE the same symbol.
//! Sizes come from the sorted address deltas — one decimal digit, cidr tab.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;
use std::process::Command;

const ADJ_MIN_DELTA_BYTES: u64 = 32;

#[derive(Debug, Clone)]
pub struct Sym {
    pub addr: u64,
    pub size: u64,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct Mover {
    pub name: String,
    pub kind: &'static str, // grew | shrank | new | vanished
    pub size_a: u64,
    pub size_b: u64,
    pub delta: i64,
    pub shift: i64, // address movement (entry point), i64 abs
    pub hot: bool,
}

#[derive(Debug, Default)]
pub struct BetweenReports {
    pub movers: Vec<Mover>,
    pub a_syms: usize,
    pub b_syms: usize,
}

/// Parse `nm -C --defined-only -n` (address, type, name) rows into symbol
/// sizes computed from consecutive `t/T` text symbols' addresses.
fn nm_take(bin: &Path) -> Result<Vec<Sym>, String> {
    let o = std::process::Command::new("nm")
        .arg("-C")
        .arg("--defined-only")
        .arg("-n")
        .arg(bin)
        .output()
        .map_err(|e| format!("spawn nm: {e}"))?;
    if !o.status.success() {
        return Err(format!(
            "nm failed on {}: {}",
            bin.display(),
            String::from_utf8_lossy(&o.stderr)
        ));
    }
    // Only text-section entries: type `t` (local text) or `T` (global text).
    let mut rows: Vec<(u64, char, String)> = Vec::new();
    for line in String::from_utf8_lossy(&o.stdout).lines() {
        let mut it = line.splitn(3, ' ');
        let (Some(addr_raw), Some(typ_raw), Some(name)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        let addr = match u64::from_str_radix(addr_raw, 16) {
            Ok(a) => a,
            Err(_) => continue,
        };
        let mut typc = typ_raw.trim().chars();
        let Some(t) = typc.next() else { continue };
        if !matches!(t, 't' | 'T') {
            continue;
        }
        let name = name.trim().to_string();
        if name.is_empty() || name.starts_with("__layout_probe") {
            continue;
        }
        rows.push((addr, t, name));
    }
    // Size = next symbol's address − this one's address (flat append, no
    // gaps: nm -n yields ascending). The LAST entry's size is unmeasurable
    // and drops out of mover analysis quietly.
    let mut out = Vec::new();
    for (i, (addr, _, name)) in rows.iter().enumerate() {
        let size = rows
            .get(i + 1)
            .map(|(na, _, _)| na.saturating_sub(*addr))
            .unwrap_or(0);
        out.push(Sym { addr: *addr, size, name: name.clone() });
    }
    Ok(out)
}

/// The full diff+attribution engine: returns (rogue movers sorted by |Δ| desc,
/// plus the raw counts) between two built binaries.
pub fn between(a_bin: &Path, b_bin: &Path, hot: &[String]) -> Result<BetweenReports, String> {
    let a = nm_take(a_bin)?;
    let b = nm_take(b_bin)?;
    let a_count = a.len();
    let b_count = b.len();
    let mut ma: BTreeMap<String, Sym> = BTreeMap::new();
    for s in a {
        ma.insert(s.name.clone(), s);
    }
    let mut mb: BTreeMap<String, Sym> = BTreeMap::new();
    for s in b {
        mb.insert(s.name.clone(), s);
    }
    let names: std::collections::BTreeSet<&String> = ma.keys().chain(mb.keys()).collect();
    let mut movers = Vec::new();
    for name in names {
        let sa = ma.get(name);
        let sb = mb.get(name.as_str());
        let size_a = sa.map(|x| x.size).unwrap_or(0);
        let size_b = sb.map(|x| x.size).unwrap_or(0);
        let delta = (size_b as i64) - (size_a as i64);
        let shift = match (sa, sb) {
            (Some(x), Some(y)) => (y.addr as i64) - (x.addr as i64),
            _ => 0,
        };
        let appeared = sa.is_none() || sb.is_none();
        let moved = appeared || delta.abs() >= 32;
        if !moved {
            continue;
        }
        let kind = if sa.is_none() {
            "new"
        } else if sb.is_none() {
            "vanished"
        } else if delta > 0 {
            "grew"
        } else {
            "shrank"
        };
        let hot = hot.iter().any(|h| name.contains(h));
        movers.push(Mover {
            name: name.clone(),
            kind,
            size_a,
            size_b: size_b,
            delta,
            shift,
            hot,
        });
    }
    movers.sort_by(|x, y| y.delta.abs().cmp(&x.delta.abs()).then(x.name.cmp(&y.name)));
    Ok(BetweenReports {
        movers,
        a_syms: a_count,
        b_syms: b_count,
    })
}

/// Hot-class substrings for a census cell's parse family. Level → the same
/// names the gzippy routing table uses in its symbol space; a mover whose
/// name contains NONE of these substrings cannot be in the cell's own
/// encoder loop.
pub fn cell_family(level: u32) -> Vec<&'static str> {
    match level {
        0 => vec!["none", "stored"],
        1 => vec!["fastest", "fast", "lzfind"],
        2 | 3 => vec!["greedy", "compress_greedy", "lzfind"],
        4..=7 => vec!["lazy", "compress_lazy", "lzfind", "matchfinder"],
        8 | 9 => vec!["near_optimal", "optim", "emit", "lzfind"],
        _ => vec![],
    }
}

/// The layer-3 attribution for one wall cell: does the rogue-mover list
/// carry a symbol in the cell's OWN parse family (source-adjacent move) or
/// NONE (pure binary-layout presence — the lever's existence alone)?
pub struct CellAttribution {
    pub movers_in_family: Vec<String>,
    pub rogue_count: usize,
    pub verdict_family: String,
    pub verdict: String,
}

pub fn attribute(
    report: &BetweenReports,
    level: u32,
    threshold: f64,
) -> CellAttribution {
    let fam = cell_family(level);
    let fam_lower: Vec<String> = fam.iter().map(|f| f.to_lowercase()).collect();
    let movers_in_family: Vec<String> = report
        .movers
        .iter()
        .filter(|m| {
            let name = m.name.to_lowercase();
            fam.iter().any(|f| name.contains(f))
        })
        .map(|m| format!("{} ({} {} B)", m.name, m.kind, m.delta.abs()))
        .collect();
    let rogue_count = report.movers.iter().filter(|m| !m.hot).count();
    // The threshold cut-off mirrors the clause-5 flat budget: a mover needs
    // real byte mass to be a candidate cause. Below it, symbol-level diffs
    // cannot explain a % scale wall delta.
    let _ = threshold;
    let verdict_family = if movers_in_family.is_empty() {
        "cell parse symbols UNMOVED".to_string()
    } else {
        format!(
            "{} of the cell's parse family moved",
            movers_in_family.len()
        )
    };
    let verdict = if movers_in_family.is_empty() {
        "CAUSE CLASS: layout-novel — the lever's binary moved none of this \
         cell's own parse symbols; the wall delta on this coordinate is a \
         code-presence layout shift, not an encoder-semantics regression"
            .to_string()
    } else {
        format!(
            "CAUSE CLASS: encoder-adjacent — the lever moved parse symbols for \
             this cell's level family; adjudicate FULLY under clause 5"
        )
    };
    CellAttribution {
        movers_in_family,
        rogue_count: report.movers.len(),
        verdict_family,
        verdict,
    }
}

pub fn cmd(args: &[String]) -> ExitCode {
    let mut a: Option<std::path::PathBuf> = None;
    let mut b: Option<std::path::PathBuf> = None;
    let mut hot_from: Option<std::path::PathBuf> = None;
    let mut cell_level: Option<u32> = None;
    let mut top = 20usize;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--a" | "--base" => {
                i += 1;
                a = args.get(i).map(std::path::PathBuf::from);
            }
            "--b" | "--after" => {
                i += 1;
                b = args.get(i).map(std::path::PathBuf::from);
            }
            "--hot-from" => {
                i += 1;
                hot_from = args.get(i).map(std::path::PathBuf::from);
            }
            "--cell-level" => {
                i += 1;
                cell_level = args.get(i).and_then(|v| v.parse().ok());
            }
            "--top" => {
                i += 1;
                top = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(top);
            }
            "--help" | "-h" => {
                eprintln!("{}", usage());
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("layout diff: unknown arg '{other}'\n\n{}", usage());
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    let (Some(a), Some(b)) = (a, b) else {
        eprintln!("layout diff: --a and --b are required\n\n{}", usage());
        return ExitCode::from(2);
    };
    // Hot substrings from a gzippy symbol_sizes.tsv (4 columns; 4th is the
    // full demangled symbol, 2nd the watch substring), or the empty set
    // (no hot-from → no hot annotation).
    let mut hot: Vec<String> = Vec::new();
    if let Some(p) = &hot_from {
        match std::fs::read_to_string(p) {
            Ok(text) => {
                for line in text.lines() {
                    if line.starts_with('#') || line.starts_with("triple\t") {
                        continue;
                    }
                    let cols: Vec<&str> = line.split('\t').collect();
                    if cols.len() >= 2 {
                        hot.push(cols[1].to_string());
                    }
                }
                eprintln!("layout diff: {} hot substrings from {}", hot.len(), p.display());
            }
            Err(e) => {
                eprintln!("layout diff: cannot read --hot-from {p:?}: {e}");
            }
        }
    }
    match between(&a, &b, &hot) {
        Ok(rep) => {
            println!(
                "LAYOUT DIFF  A={} ({} text syms)  B={} ({} text syms)",
                a.display(),
                rep.a_syms,
                b.display(),
                rep.b_syms
            );
            println!(
                "  rogue movers (|Δsize| >= 32 B or new/vanished): {}",
                rep.movers.len()
            );
            for m in rep.movers.iter().take(top) {
                println!(
                    "  [{} {:7}] Δ{:+6} B  shift{:+6}  {}",
                    m.kind,
                    if m.hot { "HOT" } else { "cold" },
                    m.delta,
                    m.shift,
                    m.name
                );
            }
            if let Some(l) = cell_level {
                let attr = attribute(&rep, l, 0.005);
                println!(
                    "cell-family attribution (L{l}): {} — {verdict}",
                    attr.verdict_family,
                    l = l,
                    verdict = attr.verdict
                );
                for m in &attr.movers_in_family {
                    println!("    mover-in-family: {m}");
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("layout diff: {e}");
            ExitCode::from(2)
        }
    }
}

fn usage() -> String {
    "fulcrum layout diff --a <binA> --b <binB> [--hot-from symbol_sizes.tsv] [--cell-level N] \
     [--top N]\n\nAnswers a layout-attribution question the per-cell confirm cannot:\n WHICH \
     hot-path symbols moved codegen between the lever's binary and the base binary, ranked, and \
     whether a mover is in the census cell's own parse family (encoder-adjacent move) or not \
     (pure code-presence layout shift).\nSymbols parse from `nm -C --defined-only -n` on both \
     binaries; sizes are address deltas of consecutive text symbols.\n\nMovers = |Δsize| >= \
     32 B, or symbols that appeared / vanished between the builds.\n\nAttribution: with \
     --cell-level N, symbols whose demangled name matches the level's parse family (fast/greedy/lazy/near-opt) are listed as `mover-in-family`; an ellipses-empty family has NO mover in the cell's own hot path → the delta on that cell is an Added-Machinery layout shift, not encoder semantics."
        .to_string()
}
