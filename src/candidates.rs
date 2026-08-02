//! `fulcrum candidates` — WHAT COULD I DO ABOUT A FAILING CELL?
//!
//! Cross-references the gzippy repo's `docs/vendor-technique-index.md` (every
//! encoder technique in the rival compressors, each with vendor source
//! citations, parameters, and a verified do-we-do-this verdict) against a
//! failing cell's code path, and surfaces the techniques that have a VENDOR
//! PRECEDENT which we do not already do (Ours: NO) or do differently
//! (Ours: PARTIALLY).
//!
//! THE SCAR: four proposed levers in one session had no vendor counterpart
//! and no precedent that they pay; separately, a variant of an
//! already-FALSIFIED idea was re-attempted because the falsification record
//! lived in a source comment nobody re-read. So this command also scans the
//! gzippy source for `FALSIFY` records and attaches any that textually bear
//! on a candidate — LOUDLY.
//!
//! Every ranked candidate carries: the vendor(s), the exact citation, the
//! vendor's parameter value vs ours, and any FALSIFY record. The index is
//! evidence, not advice: a candidate with a FALSIFY record is printed with
//! the record on top, because re-litigating it needs new evidence, not
//! optimism.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Debug, Clone)]
pub struct Technique {
    /// e.g. "P7" — the index's own id.
    pub id: String,
    pub name: String,
    pub section: String,
    /// Raw field lines from the entry.
    pub identifiers: String,
    pub who: String,
    pub mechanism: String,
    pub parameters: String,
    /// YES / PARTIALLY / NO (+ the rest of the line as evidence).
    pub ours_verdict: String,
    pub ours_detail: String,
    pub applicability: String,
}

/// Parse the technique index's stable entry format:
/// `## <ID>. <Name>` then `- **Field**: value` lines, under `# <Section>`.
pub fn parse_index(md: &str) -> Vec<Technique> {
    let mut out = Vec::new();
    let mut section = String::new();
    let mut cur: Option<Technique> = None;
    for line in md.lines() {
        if let Some(rest) = line.strip_prefix("# ") {
            section = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("## ") {
            if let Some(t) = cur.take() {
                out.push(t);
            }
            let rest = rest.trim();
            let (id, name) = match rest.split_once(". ") {
                Some((id, name)) => (id.trim().to_string(), name.trim().to_string()),
                None => (String::new(), rest.to_string()),
            };
            cur = Some(Technique {
                id,
                name,
                section: section.clone(),
                identifiers: String::new(),
                who: String::new(),
                mechanism: String::new(),
                parameters: String::new(),
                ours_verdict: String::new(),
                ours_detail: String::new(),
                applicability: String::new(),
            });
        } else if let Some(t) = cur.as_mut() {
            let l = line.trim_start_matches('-').trim();
            let grab = |l: &str, key: &str| -> Option<String> {
                l.strip_prefix(&format!("**{key}**:"))
                    .map(|v| v.trim().to_string())
            };
            if let Some(v) = grab(l, "Identifiers") {
                t.identifiers = v;
            } else if let Some(v) = grab(l, "Who") {
                t.who = v;
            } else if let Some(v) = grab(l, "Mechanism") {
                t.mechanism = v;
            } else if let Some(v) = grab(l, "Parameters") {
                t.parameters = v;
            } else if let Some(v) = grab(l, "Ours") {
                let verdict = ["YES", "PARTIALLY", "NO"]
                    .iter()
                    .find(|k| v.trim_start().starts_with(**k))
                    .map(|k| k.to_string())
                    .unwrap_or_else(|| "UNKNOWN".to_string());
                t.ours_verdict = verdict;
                t.ours_detail = v;
            } else if let Some(v) = grab(l, "Applicability") {
                t.applicability = v;
            }
        }
    }
    if let Some(t) = cur.take() {
        out.push(t);
    }
    out
}

/// The level → parse-class map, from the index's own entry-format note:
/// "L0/L1 fast, L2-9 greedy/lazy, L10-12 near-optimal" refined by gzippy's
/// ladder (greedy L2-4, lazy L5-7, lazy2 L8-9).
pub fn level_class(level: u32) -> &'static str {
    match level {
        0 => "store",
        1 => "fast",
        2..=4 => "greedy",
        5..=7 => "lazy",
        8 | 9 => "lazy2",
        _ => "near-optimal",
    }
}

/// Does a technique's Applicability line bear on (level, threads)?
pub fn applicable(t: &Technique, level: u32, threads: u32) -> bool {
    let a = t.applicability.to_ascii_lowercase();
    if a.is_empty() {
        return true; // no claim = cannot exclude; let the ranking demote it
    }
    if threads > 1 && a.contains("t>1") {
        return true;
    }
    let class = level_class(level);
    if a.contains(class) {
        return true;
    }
    // Match explicit level mentions: "L6", "our L5-7", "levels 2-4".
    for token in a
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
        .filter(|s| !s.is_empty())
    {
        if let Some(rest) = token.strip_prefix('l') {
            if let Some((lo, hi)) = rest.split_once('-') {
                if let (Ok(lo), Ok(hi)) = (lo.parse::<u32>(), hi.parse::<u32>()) {
                    if (lo..=hi).contains(&level) {
                        return true;
                    }
                }
            } else if rest.parse::<u32>() == Ok(level) {
                return true;
            }
        }
    }
    false
}

#[derive(Debug, Clone)]
pub struct Falsify {
    pub file: String,
    pub line: usize,
    pub text: String,
}

/// Scan the gzippy source tree for FALSIFY records (in-code falsification
/// comments — the only internal check that has ever worked there).
pub fn scan_falsify(repo: &Path) -> Vec<Falsify> {
    let mut out = Vec::new();
    let mut stack = vec![repo.join("src")];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().and_then(|s| s.to_str()) == Some("rs") {
                let Ok(body) = std::fs::read_to_string(&p) else {
                    continue;
                };
                for (i, line) in body.lines().enumerate() {
                    if line.contains("FALSIFY") {
                        out.push(Falsify {
                            file: p.strip_prefix(repo).unwrap_or(&p).display().to_string(),
                            line: i + 1,
                            text: line.trim().to_string(),
                        });
                    }
                }
            }
        }
    }
    out
}

/// Words from a technique name/identifiers worth matching against a FALSIFY
/// comment (lowercased, len > 3, no stop-words).
fn keywords(t: &Technique) -> Vec<String> {
    const STOP: &[&str] = &[
        "with", "from", "that", "this", "into", "only", "over", "parse",
    ];
    let mut words: Vec<String> = format!("{} {}", t.name, t.identifiers)
        .to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| w.len() > 3 && !STOP.contains(w))
        .map(|w| w.to_string())
        .collect();
    words.sort();
    words.dedup();
    words
}

pub fn falsify_matches<'a>(t: &Technique, records: &'a [Falsify]) -> Vec<&'a Falsify> {
    let kw = keywords(t);
    records
        .iter()
        .filter(|r| {
            // Exact WORD intersection, not substring: "deeper chains" must
            // not flag every chain-adjacent technique, only records that
            // name the technique's own terms.
            let words: Vec<String> = r
                .text
                .to_ascii_lowercase()
                .split(|c: char| !c.is_ascii_alphanumeric())
                .filter(|w| w.len() > 3)
                .map(|w| w.to_string())
                .collect();
            kw.iter().any(|w| words.iter().any(|rw| rw == w))
        })
        .collect()
}

pub struct Ranked<'a> {
    pub technique: &'a Technique,
    pub falsified: Vec<&'a Falsify>,
}

/// Rank: techniques we DON'T do before ones we do PARTIALLY; falsified ones
/// sink to the bottom of their band (they are printed, loudly, never hidden).
pub fn rank<'a>(
    techniques: &'a [Technique],
    records: &'a [Falsify],
    level: u32,
    threads: u32,
) -> Vec<Ranked<'a>> {
    let mut out: Vec<Ranked<'a>> = techniques
        .iter()
        .filter(|t| matches!(t.ours_verdict.as_str(), "NO" | "PARTIALLY"))
        .filter(|t| applicable(t, level, threads))
        .map(|t| Ranked {
            technique: t,
            falsified: falsify_matches(t, records),
        })
        .collect();
    out.sort_by_key(|r| {
        (
            !r.falsified.is_empty(),          // un-falsified first
            r.technique.ours_verdict != "NO", // NO before PARTIALLY
            r.technique.id.clone(),
        )
    });
    out
}

pub fn cmd(args: &[String]) -> ExitCode {
    if args.first().map(|s| s.as_str()) == Some("selftest") {
        return selftest();
    }
    let mut cell: Option<String> = None;
    let mut repo = PathBuf::from("/Users/jackdanger/www/gzippy");
    let mut index: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--repo" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    repo = PathBuf::from(v);
                }
            }
            "--index" => {
                i += 1;
                index = args.get(i).map(PathBuf::from);
            }
            "--no-self-update" => {}
            "--help" | "-h" => {
                eprintln!("{}", usage());
                return ExitCode::SUCCESS;
            }
            other if !other.starts_with("--") && cell.is_none() => cell = Some(other.to_string()),
            other => {
                eprintln!("candidates: unknown arg '{other}'\n\n{}", usage());
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    let Some(cell) = cell else {
        eprintln!("{}", usage());
        return ExitCode::from(2);
    };
    let (level, threads) = match parse_cell(&cell) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("candidates: {e}");
            return ExitCode::from(2);
        }
    };
    let index_path = index.unwrap_or_else(|| repo.join("docs/vendor-technique-index.md"));
    let md = match std::fs::read_to_string(&index_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "candidates: REFUSED — cannot read the technique index {} ({e}). \
                 A candidate list may only cite an index that exists.",
                index_path.display()
            );
            return ExitCode::FAILURE;
        }
    };
    let techniques = parse_index(&md);
    if techniques.is_empty() {
        eprintln!(
            "candidates: REFUSED — {} parsed to zero techniques; the index format changed?",
            index_path.display()
        );
        return ExitCode::FAILURE;
    }
    let records = scan_falsify(&repo);
    let ranked = rank(&techniques, &records, level, threads);
    println!(
        "CANDIDATES for {cell} (L{level} = {} path, T{threads}) — vendor-precedented techniques we do not already do",
        level_class(level)
    );
    println!(
        "  index: {} ({} techniques; {} FALSIFY records scanned in {})",
        index_path.display(),
        techniques.len(),
        records.len(),
        repo.join("src").display()
    );
    println!(
        "  DENOMINATOR: {} techniques applicable to this cell with Ours != YES (of {} total; the rest are done or out of scope for this level)",
        ranked.len(),
        techniques.len()
    );
    for r in &ranked {
        let t = r.technique;
        println!("\n  [{}] {} — Ours: {}", t.id, t.name, t.ours_detail);
        if !t.who.is_empty() {
            println!("      vendor: {}", t.who);
        }
        if !t.parameters.is_empty() {
            println!("      params: {}", t.parameters);
        }
        if !t.applicability.is_empty() {
            println!("      applies: {}", t.applicability);
        }
        for f in &r.falsified {
            println!(
                "      !! FALSIFIED-OR-RELATED RECORD {}:{} — {}",
                f.file, f.line, f.text
            );
            println!("      !! re-attempting this needs NEW evidence against that record, not a variant.");
        }
    }
    if ranked.is_empty() {
        println!("\n  Nothing left with vendor precedent at this level — the gap is implementation, not technique.");
        println!("  NEXT ACTION: fulcrum why {cell}   (locate the implementation excess)");
    } else {
        println!("\n  NEXT ACTION: implement the top un-falsified candidate on a branch, then: fulcrum try <ref>");
    }
    ExitCode::SUCCESS
}

/// A board cell id, fully decomposed. The id already NAMES the rival, the
/// corpus, the level and the thread count — commands that make the caller
/// restate any of that are asking them to get it wrong (`fulcrum why` used to
/// demand `--ours`, `--rival-cmd` and `--corpus` alongside a cell id that
/// already said which rival and which corpus).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CellId {
    pub rival: Option<String>,
    pub corpus: Option<String>,
    pub level: u32,
    pub threads: u32,
    pub axis: Option<String>,
}

/// Decompose `rival:corpus:L6:T1:axis` (or any `:`-joined subset carrying an L
/// token). Tokens are identified by SHAPE — `L<n>`, `T<n>`, a known axis name —
/// and the remaining tokens keep board order: rival first, corpus second.
pub fn parse_cell_full(cell: &str) -> Result<CellId, String> {
    let mut level = None;
    let mut threads = 1u32;
    let mut axis = None;
    let mut rest: Vec<String> = Vec::new();
    for tok in cell.split(':') {
        if tok.is_empty() {
            continue;
        }
        if let Some(n) = tok.strip_prefix('L').and_then(|r| r.parse::<u32>().ok()) {
            level = Some(n);
        } else if let Some(n) = tok.strip_prefix('T').and_then(|r| r.parse::<u32>().ok()) {
            threads = n;
        } else if matches!(tok, "size" | "wall" | "struct" | "structure") {
            axis = Some(tok.to_string());
        } else {
            rest.push(tok.to_string());
        }
    }
    let Some(level) = level else {
        return Err(format!(
            "cell '{cell}' carries no L<level> token — the level names the code path, so \
             candidates cannot be selected without it (e.g. pigz:silesia:L6:T1:size)"
        ));
    };
    Ok(CellId {
        rival: rest.first().cloned(),
        corpus: rest.get(1).cloned(),
        level,
        threads,
        axis,
    })
}

/// Accept `rival:corpus:L6:T1:axis` (board id) or any `:`-joined subset
/// containing an L token, e.g. `silesia:L6:T1` or `L6`.
pub fn parse_cell(cell: &str) -> Result<(u32, u32), String> {
    let mut level = None;
    let mut threads = 1u32;
    for tok in cell.split(':') {
        if let Some(rest) = tok.strip_prefix('L') {
            if let Ok(l) = rest.parse() {
                level = Some(l);
            }
        } else if let Some(rest) = tok.strip_prefix('T') {
            if let Ok(t) = rest.parse() {
                threads = t;
            }
        }
    }
    match level {
        Some(l) => Ok((l, threads)),
        None => Err(format!(
            "cell '{cell}' carries no L<level> token — the level names the code path, so \
             candidates cannot be selected without it (e.g. pigz:silesia:L6:T1:size)"
        )),
    }
}

fn usage() -> String {
    "fulcrum candidates <cell> [--repo GZIPPY_REPO] [--index vendor-technique-index.md]\n\
     \n\
     <cell> is a board cell id (rival:corpus:L6:T1:axis) or any subset with an L token.\n\
     Surfaces vendor-precedented techniques (Ours: NO/PARTIALLY) applicable to the cell's\n\
     code path, each with citation + their parameter vs ours + any FALSIFY record in our\n\
     own source. selftest = Gate-0.\n"
        .to_string()
}

// ---------------------------------------------------------------------------
// Gate-0
// ---------------------------------------------------------------------------

const FIXTURE_INDEX: &str = r#"# A. Parsing strategies

## P1. Greedy parse
- **Identifiers**: libdeflate `deflate_compress_greedy`.
- **Who**: `vendor/libdeflate/lib/deflate_compress.c:2528-2602`.
- **Mechanism**: one match search per position.
- **Parameters**: min length 3.
- **Ours**: YES — `parse/greedy.rs:175-185`.
- **Applicability**: already our L2/L4.

## P9. Hash-4 head table
- **Identifiers**: zlib-ng `deflate_quick` hash4.
- **Who**: `vendor/zlib-ng/deflate_quick.c:100`.
- **Mechanism**: 4-byte hash for the head table.
- **Parameters**: hash bits 16 vs our 15.
- **Ours**: NO.
- **Applicability**: L2-9 greedy/lazy.

## P11. Chain pre-touch
- **Identifiers**: igzip chain prefetch.
- **Who**: `vendor/isa-l/igzip/igzip.c:50`.
- **Mechanism**: prefetch the next chain link before scoring the current.
- **Parameters**: distance 1 link.
- **Ours**: PARTIALLY — only in the L1 path.
- **Applicability**: lazy L5-7.

## Z1. Store-only shortcut
- **Identifiers**: pigz store.
- **Who**: `vendor/pigz/pigz.c:213`.
- **Mechanism**: stored blocks.
- **Parameters**: none.
- **Ours**: NO.
- **Applicability**: L0 store only.
"#;

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

    let ts = parse_index(FIXTURE_INDEX);
    check("parse: all four fixture entries parsed", ts.len() == 4);
    check(
        "parse: verdict extracted (YES/NO/PARTIALLY)",
        ts[0].ours_verdict == "YES"
            && ts[1].ours_verdict == "NO"
            && ts[2].ours_verdict == "PARTIALLY",
    );
    check(
        "parse: citation and parameters preserved verbatim",
        ts[1].who.contains("deflate_quick.c:100") && ts[1].parameters.contains("16 vs our 15"),
    );

    let records = vec![
        Falsify {
            file: "src/compress/deflate/matchfinder/hc.rs".into(),
            line: 10,
            text: "// FALSIFY(2026-07-20): hash4 head table lost 2.1% wall at L6 — deeper chains"
                .into(),
        },
        Falsify {
            file: "src/x.rs".into(),
            line: 1,
            text: "// FALSIFY: unrelated note about crc folding".into(),
        },
    ];

    let ranked = rank(&ts, &records, 6, 1);
    check(
        "filter: YES techniques never surface; L0-only technique excluded at L6",
        ranked
            .iter()
            .all(|r| r.technique.id != "P1" && r.technique.id != "Z1"),
    );
    check(
        "rank: both applicable NO/PARTIALLY techniques surface at L6",
        ranked.len() == 2,
    );
    let p9 = ranked.iter().find(|r| r.technique.id == "P9").unwrap();
    check(
        "falsify: the hash4 FALSIFY record attaches to the hash4 technique, loudly",
        p9.falsified.len() == 1 && p9.falsified[0].text.contains("lost 2.1%"),
    );
    check(
        "rank: an un-falsified candidate outranks a falsified one",
        ranked[0].technique.id == "P11",
    );
    check(
        "cell grammar: board ids and bare L tokens parse; missing L refuses",
        parse_cell("pigz:silesia:L6:T4:size") == Ok((6, 4))
            && parse_cell("L9") == Ok((9, 1))
            && parse_cell("silesia:T4").is_err(),
    );

    println!("candidates selftest: {pass} passed, {fail} failed");
    if fail == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
