//! Claim-validator — bake the adversarial audit discipline into the tool so a
//! human CAN'T accidentally over-claim.
//!
//! `fulcrum audit` takes a STATED performance claim ("subject is fastest at
//! every thread count on a compressible corpus") and re-checks it against the
//! five classic methodology holes ([`crate::compare`]), then reports one of:
//!
//!   * **SURVIVES** — the claim holds as stated under a fair measurement.
//!   * **NARROWS-TO-SCOPE** — a weaker TRUE claim is supported; the stated one
//!     over-reaches. The corrected scope is printed.
//!   * **FALSE** — the claim does not hold even narrowed; the subject loses the
//!     cell(s) it claimed, or its output was wrong.
//!
//! The audit is the same fair comparison the [`crate::compare`] harness runs,
//! plus a CLAIM PARSE: a small structured [`Claim`] (subject, the scope it
//! asserts, the metric) checked against the measured matrix. The point is that
//! the AUDIT, not the human, decides whether "fastest everywhere" is honest —
//! and it can only say SURVIVES when every cell in the asserted scope is a
//! verified (correct-bytes) win.

use crate::compare::{Cell, Comparison, ThreadCell};

/// The breadth a claim asserts over the situation matrix. This is the structured
/// form of phrases like "at EVERY thread count" or "on compressible input".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClaimScope {
    /// "fastest at every thread count AND every corpus we test" — the strongest,
    /// most over-claim-prone form (the one the motivating audit caught).
    EveryCell,
    /// "fastest on this corpus kind, at every thread count we test."
    EveryThreadOnKind(String),
    /// "fastest at this specific thread cell, on this corpus kind."
    SingleCell { kind: String, threads: ThreadCell },
    /// "fastest at every thread count" (any/all corpora pooled).
    EveryThread,
}

impl ClaimScope {
    /// Does a measured cell fall inside the asserted scope?
    fn includes(&self, c: &Cell) -> bool {
        match self {
            ClaimScope::EveryCell | ClaimScope::EveryThread => true,
            ClaimScope::EveryThreadOnKind(k) => &c.corpus_kind == k,
            ClaimScope::SingleCell { kind, threads } => {
                &c.corpus_kind == kind && c.threads == *threads
            }
        }
    }

    fn describe(&self) -> String {
        match self {
            ClaimScope::EveryCell => "fastest at EVERY tested (corpus × thread) cell".to_string(),
            ClaimScope::EveryThread => "fastest at EVERY tested thread count".to_string(),
            ClaimScope::EveryThreadOnKind(k) => {
                format!("fastest at every tested thread count on '{k}' corpora")
            }
            ClaimScope::SingleCell { kind, threads } => {
                format!("fastest on '{kind}' corpora at {}", threads.label())
            }
        }
    }
}

/// A stated performance claim to audit.
#[derive(Clone, Debug)]
pub struct Claim {
    /// The tool the claim is about (must be one of the compared tools).
    pub subject: String,
    /// The breadth the claim asserts.
    pub scope: ClaimScope,
    /// The original human wording, echoed in the report.
    pub wording: String,
}

impl Claim {
    /// Parse a claim from a `subject` + a free-text scope phrase, recognizing the
    /// common shapes. GENERIC: it keys on capability words ("every thread",
    /// "compressible", "auto"), never on a tool's product name.
    pub fn parse(subject: &str, phrase: &str, all_kinds: &[String]) -> Claim {
        let p = phrase.to_ascii_lowercase();
        // A specific thread token?
        let thread = parse_thread_token(&p);
        // A corpus-kind token present in the phrase?
        let kind = all_kinds
            .iter()
            .find(|k| p.contains(&k.to_ascii_lowercase()))
            .cloned();
        let every_thread =
            p.contains("every thread") || p.contains("all thread") || p.contains("each thread");
        let every = p.contains("every") && (p.contains("situation") || p.contains("everywhere"));

        let scope = match (kind, thread, every_thread, every) {
            // "fastest everywhere / every situation" → the strongest claim.
            (_, _, _, true) => ClaimScope::EveryCell,
            // "...on KIND at TN"
            (Some(k), Some(t), _, _) => ClaimScope::SingleCell {
                kind: k,
                threads: t,
            },
            // "...every thread on KIND"
            (Some(k), None, true, _) => ClaimScope::EveryThreadOnKind(k),
            // "...on KIND" (no thread qualifier) — treat as every-thread on kind
            (Some(k), None, false, _) => ClaimScope::EveryThreadOnKind(k),
            // "...every thread" (no kind)
            (None, _, true, _) => ClaimScope::EveryThread,
            // "...at TN" (no kind) → single cell across pooled corpora; model as
            // every-cell-at-that-thread via SingleCell with a wildcard kind.
            (None, Some(t), _, _) => ClaimScope::SingleCell {
                kind: "*".to_string(),
                threads: t,
            },
            // Nothing matched → the strongest interpretation, so the audit is
            // conservative (forces the claim to clear the highest bar).
            (None, None, false, false) => ClaimScope::EveryCell,
        };
        Claim {
            subject: subject.to_string(),
            scope,
            wording: phrase.to_string(),
        }
    }
}

/// Parse a thread token like "t8", "8 threads", "auto" out of a phrase.
fn parse_thread_token(p: &str) -> Option<ThreadCell> {
    if p.contains("auto") || p.contains("all core") || p.contains("-p0") || p.contains("-p 0") {
        return Some(ThreadCell::Auto);
    }
    // "tN"
    for tok in p.split(|c: char| !c.is_ascii_alphanumeric()) {
        if let Some(rest) = tok.strip_prefix('t') {
            if let Ok(n) = rest.parse::<usize>() {
                return Some(ThreadCell::Fixed(n));
            }
        }
    }
    // "N threads" / "N thread"
    let words: Vec<&str> = p.split_whitespace().collect();
    for w in words.windows(2) {
        if (w[1].starts_with("thread")) || w[1] == "threads" {
            if let Ok(n) = w[0].parse::<usize>() {
                return Some(ThreadCell::Fixed(n));
            }
        }
    }
    None
}

/// The audit verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The claim holds as stated.
    Survives,
    /// A weaker TRUE claim is supported; the stated one over-reaches.
    NarrowsToScope,
    /// The claim is false even narrowed.
    False,
}

impl Verdict {
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::Survives => "SURVIVES",
            Verdict::NarrowsToScope => "NARROWS-TO-SCOPE",
            Verdict::False => "FALSE",
        }
    }
}

/// The full audit result.
#[derive(Clone, Debug)]
pub struct AuditResult {
    pub claim: Claim,
    pub verdict: Verdict,
    /// Cells in the asserted scope the subject WON (corrected, correct-bytes).
    pub won: Vec<String>,
    /// Cells in the asserted scope the subject LOST, with by-how-much.
    pub lost: Vec<String>,
    /// Cells in the asserted scope the subject was DISQUALIFIED on (wrong/err).
    pub disqualified: Vec<String>,
    /// The corrected honest claim wording.
    pub corrected: String,
    /// Which of the five holes materially CHANGED the picture (provenance).
    pub holes_that_bit: Vec<String>,
}

/// Audit a claim against a measured comparison. The comparison MUST have been
/// produced by the fair harness (so the five holes are already handled); this
/// step checks the CLAIM'S SCOPE against the verified-win cells.
pub fn audit(claim: Claim, cmp: &Comparison) -> AuditResult {
    let mut won = Vec::new();
    let mut lost = Vec::new();
    let mut disq = Vec::new();

    // Walk every measured cell inside the claim's asserted scope.
    for (corpus, kind, threads) in cmp.cells_keys() {
        let subj = cmp
            .cells
            .iter()
            .find(|c| c.corpus == corpus && c.threads == threads && c.tool == claim.subject);
        let Some(subj) = subj else { continue };
        if !claim.scope.includes(subj) {
            continue;
        }
        let cell_label = format!("{}/{}", kind, threads.label());
        if !subj.valid() {
            disq.push(format!(
                "{cell_label} ({})",
                if subj.errored { "errored" } else { "WRONG BYTES" }
            ));
            continue;
        }
        match cmp.winner(&corpus, threads) {
            Some((w, margin)) if w == claim.subject => {
                let m = if margin.is_finite() {
                    format!("+{:.0}%", margin * 100.0)
                } else {
                    "uncontested".to_string()
                };
                won.push(format!("{cell_label} ({m})"));
            }
            Some((w, _)) => {
                let win_cell = cmp
                    .cells
                    .iter()
                    .find(|c| c.corpus == corpus && c.threads == threads && c.tool == w);
                let behind = win_cell
                    .map(|wc| {
                        subj.wall_minus_startup.as_secs_f64()
                            / wc.wall_minus_startup.as_secs_f64().max(1e-9)
                    })
                    .unwrap_or(1.0);
                lost.push(format!("{cell_label} (loses to {w} by {behind:.2}×)"));
            }
            None => {}
        }
    }

    // Decide the verdict.
    let verdict = if !disq.is_empty() {
        // Wrong/missing bytes anywhere in scope → the claim cannot stand as a
        // performance claim (speed over wrong bytes is not a win).
        Verdict::False
    } else if lost.is_empty() && !won.is_empty() {
        Verdict::Survives
    } else if won.is_empty() {
        Verdict::False
    } else {
        Verdict::NarrowsToScope
    };

    // The corrected honest claim.
    let corrected = match verdict {
        Verdict::Survives => format!(
            "{} IS {} (verified correct in all {} scoped cell(s)).",
            claim.subject,
            claim.scope.describe(),
            won.len()
        ),
        Verdict::NarrowsToScope => format!(
            "{} is NOT '{}'. The TRUE claim is scoped to: WINS [{}]; it LOSES [{}].",
            claim.subject,
            claim.scope.describe(),
            won.join(", "),
            lost.join(", ")
        ),
        Verdict::False => {
            if !disq.is_empty() {
                format!(
                    "{} cannot claim '{}' — it produced WRONG/NO output in: [{}]. A faster-but-incorrect \
                     result is not a win.",
                    claim.subject,
                    claim.scope.describe(),
                    disq.join(", ")
                )
            } else {
                format!(
                    "{} is NOT '{}' — it wins no cell in scope. It LOSES [{}].",
                    claim.subject,
                    claim.scope.describe(),
                    lost.join(", ")
                )
            }
        }
    };

    // Provenance: which holes materially moved the picture? We infer this from
    // the comparison's own findings (interpreter-wrapped tools, dominating
    // startup, contention, any disqualified cell).
    let mut holes = Vec::new();
    if cmp.probes.values().any(|p| p.looks_interpreted()) {
        holes.push(
            "#1 interpreter-wrapped competitor detected (would have inflated the subject's win)"
                .to_string(),
        );
    }
    // Startup dominating: any probe startup > 25% of fastest decode.
    let fastest = cmp
        .cells
        .iter()
        .filter(|c| c.valid())
        .map(|c| c.wall_minus_startup.as_secs_f64())
        .fold(f64::INFINITY, f64::min);
    if fastest.is_finite()
        && cmp
            .probes
            .values()
            .any(|p| p.startup.as_secs_f64() > 0.25 * fastest)
    {
        holes.push(
            "#1 per-invocation startup was a large fraction of decode wall (subtracted here)"
                .to_string(),
        );
    }
    if !disq.is_empty() {
        holes.push("#3 output-correctness check disqualified a fast-but-wrong cell".to_string());
    }
    // #4 bites whenever a multi-cell claim (every-thread and/or every-corpus)
    // loses a cell the sweep surfaced — exactly the "fastest at every thread
    // count" over-claim the motivating audit caught.
    let multi_cell_scope = matches!(
        claim.scope,
        ClaimScope::EveryCell | ClaimScope::EveryThread | ClaimScope::EveryThreadOnKind(_)
    );
    if !lost.is_empty() && multi_cell_scope {
        holes.push(
            "#4 full situation-matrix sweep exposed cells the broad claim ignored".to_string(),
        );
    }
    if let Some(w) = &cmp.guard_warning {
        if w.contains("busy") || w.contains("contended") {
            holes.push("#5 contention guard flagged the box as busy during measurement".to_string());
        }
    }

    AuditResult {
        claim,
        verdict,
        won,
        lost,
        disqualified: disq,
        corrected,
        holes_that_bit: holes,
    }
}

/// Render an audit result as a report.
pub fn render(a: &AuditResult) -> String {
    let mut s = String::new();
    s.push_str("\n========  FULCRUM CLAIM AUDIT  ========\n");
    s.push_str(&format!("  CLAIM   : \"{}\"\n", a.claim.wording));
    s.push_str(&format!("  subject : {}\n", a.claim.subject));
    s.push_str(&format!("  asserts : {}\n", a.claim.scope.describe()));
    s.push_str(&format!("\n  VERDICT : {}\n", a.verdict.label()));
    s.push_str(&format!("  {}\n", a.corrected));
    if !a.won.is_empty() {
        s.push_str(&format!("\n  scoped WINS  : {}\n", a.won.join(", ")));
    }
    if !a.lost.is_empty() {
        s.push_str(&format!("  scoped LOSES : {}\n", a.lost.join(", ")));
    }
    if !a.disqualified.is_empty() {
        s.push_str(&format!("  DISQUALIFIED : {}\n", a.disqualified.join(", ")));
    }
    if !a.holes_that_bit.is_empty() {
        s.push_str("\n  methodology holes that CHANGED the picture (vs a naive benchmark):\n");
        for h in &a.holes_that_bit {
            s.push_str(&format!("    - {h}\n"));
        }
    } else {
        s.push_str("\n  (no methodology hole materially moved this result — the naive and fair numbers agree.)\n");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compare::{sha256, BinaryKind, BinaryProbe};
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::time::Duration;

    fn cell(
        tool: &str,
        kind: &str,
        threads: ThreadCell,
        ms: u64,
        correct: bool,
        errored: bool,
    ) -> Cell {
        Cell {
            tool: tool.to_string(),
            corpus: format!("{kind}-corpus"),
            corpus_kind: kind.to_string(),
            threads,
            wall: Duration::from_millis(ms),
            wall_minus_startup: Duration::from_millis(ms),
            best_wall: Duration::from_millis(ms),
            digest: if correct { sha256(b"ref") } else { sha256(b"bad") },
            correct,
            spread: 0.0,
            mbps: 1.0,
            errored,
        }
    }

    fn cmp_with(cells: Vec<Cell>) -> Comparison {
        Comparison {
            subject: "subject".to_string(),
            probes: BTreeMap::new(),
            cells,
            guard_warning: None,
            samples: 5,
        }
    }

    #[test]
    fn parse_recognizes_scopes() {
        let kinds = vec!["compressible".to_string(), "incompressible".to_string()];
        let c = Claim::parse("subject", "fastest at every thread count on compressible", &kinds);
        assert_eq!(
            c.scope,
            ClaimScope::EveryThreadOnKind("compressible".to_string())
        );
        let c2 = Claim::parse("subject", "the fastest decoder at every thread count, every situation", &kinds);
        assert_eq!(c2.scope, ClaimScope::EveryCell);
        let c3 = Claim::parse("subject", "fastest on compressible at T8", &kinds);
        assert_eq!(
            c3.scope,
            ClaimScope::SingleCell {
                kind: "compressible".to_string(),
                threads: ThreadCell::Fixed(8)
            }
        );
    }

    #[test]
    fn over_claim_narrows_when_subject_loses_a_thread_cell() {
        // The motivating audit: "fastest at every thread count" but it LOSES T8.
        let cells = vec![
            // T1: subject wins.
            cell("subject", "compressible", ThreadCell::Fixed(1), 100, true, false),
            cell("rival", "compressible", ThreadCell::Fixed(1), 130, true, false),
            // T8: subject LOSES to rival.
            cell("subject", "compressible", ThreadCell::Fixed(8), 90, true, false),
            cell("rival", "compressible", ThreadCell::Fixed(8), 40, true, false),
        ];
        let cmp = cmp_with(cells);
        let claim = Claim::parse(
            "subject",
            "fastest at every thread count on compressible",
            &["compressible".to_string()],
        );
        let a = audit(claim, &cmp);
        assert_eq!(a.verdict, Verdict::NarrowsToScope);
        assert!(a.won.iter().any(|w| w.contains("T1")));
        assert!(a.lost.iter().any(|w| w.contains("T8")));
        // hole #4 must be cited as having changed the picture.
        assert!(a.holes_that_bit.iter().any(|h| h.contains("#4")));
    }

    #[test]
    fn wrong_bytes_makes_claim_false() {
        // Subject is FASTER at T1 but produces WRONG bytes → claim FALSE, #3 cited.
        let cells = vec![
            cell("subject", "compressible", ThreadCell::Fixed(1), 10, false, false),
            cell("rival", "compressible", ThreadCell::Fixed(1), 50, true, false),
        ];
        let cmp = cmp_with(cells);
        let claim = Claim::parse(
            "subject",
            "fastest on compressible at T1",
            &["compressible".to_string()],
        );
        let a = audit(claim, &cmp);
        assert_eq!(a.verdict, Verdict::False);
        assert!(a.holes_that_bit.iter().any(|h| h.contains("#3")));
    }

    #[test]
    fn interpreter_wrapped_rival_is_flagged_in_provenance() {
        // Subject wins, but ONLY because the rival is an interpreter shim; the
        // audit must SURVIVE yet cite #1 so the win is honestly contextualized.
        let cells = vec![
            cell("subject", "compressible", ThreadCell::Fixed(1), 100, true, false),
            cell("rival", "compressible", ThreadCell::Fixed(1), 130, true, false),
        ];
        let mut cmp = cmp_with(cells);
        cmp.probes.insert(
            "rival".to_string(),
            BinaryProbe {
                path: PathBuf::from("/usr/bin/rival"),
                kind: BinaryKind::Interpreted("python".to_string()),
                startup: Duration::from_millis(30),
                startup_spread: 0.0,
            },
        );
        let claim = Claim::parse(
            "subject",
            "fastest on compressible at T1",
            &["compressible".to_string()],
        );
        let a = audit(claim, &cmp);
        assert_eq!(a.verdict, Verdict::Survives);
        assert!(a.holes_that_bit.iter().any(|h| h.contains("#1")));
    }

    #[test]
    fn clean_sweep_survives() {
        // Subject wins every scoped cell with correct bytes and no holes → SURVIVES.
        let cells = vec![
            cell("subject", "compressible", ThreadCell::Fixed(1), 50, true, false),
            cell("rival", "compressible", ThreadCell::Fixed(1), 80, true, false),
            cell("subject", "compressible", ThreadCell::Fixed(4), 30, true, false),
            cell("rival", "compressible", ThreadCell::Fixed(4), 60, true, false),
        ];
        let cmp = cmp_with(cells);
        let claim = Claim::parse(
            "subject",
            "fastest at every thread count on compressible",
            &["compressible".to_string()],
        );
        let a = audit(claim, &cmp);
        assert_eq!(a.verdict, Verdict::Survives);
        assert_eq!(a.lost.len(), 0);
    }
}
