//! insn.rs — a CLOSED instruction-accounting ledger (the
//! **INSN-CLOSURE-OR-NO-LEDGER** invariant). A faithful Rust port of
//! `decide/fulcrum/core/insn.py`.
//!
//! The governing model of the gzippy↔rapidgzip campaign is "wall delta ==
//! retired CPU-instruction delta vs the comparator." Locating WHERE a tool's
//! excess instructions go was a hand-built ledger — and that ledger
//! DOUBLE-COUNTED by 690M (a symbol's instructions assigned to two categories,
//! the category buckets summed to MORE than the measured retired total, and the
//! residual was narrated away). Attribution by hand manufactures phantoms
//! exactly the way it does for wall time.
//!
//! The cure is the same one `locate` uses: a CLOSED LEDGER. Every retired
//! instruction is either charged to exactly ONE category, sits in an explicit
//! UNCATEGORIZED bucket (a symbol matched no role), or is REPORT-RESIDUAL
//! (instructions the `perf stat` total accounts for but the `perf report` did
//! not sample). The ledger is conservation-asserted:
//!
//! ```text
//! measured_total (perf stat) == categorized + uncategorized + residual
//! ```
//!
//! and it REFUSES — does not render — three structural impossibilities:
//!
//!   0. **EVENT MISMATCH** ([`InvariantViolation`] `INSN-EVENT-MISMATCH`): the
//!      per-symbol `perf report` was sampled on a DIFFERENT event than the `perf
//!      stat` total it is closed against (e.g. cycles vs instructions). Charging
//!      one event's periods against the other's total "conserves" on the wrong
//!      denominator and yields a meaningless per-category shape — the
//!      2.7-insn/byte hallucination.
//!   1. **OVER-COUNT** (`INSN-CLOSURE`, the 690M class): the per-symbol report
//!      sums to MORE than the measured retired total beyond tolerance.
//!   2. **AMBIGUOUS PARTITION** (`INSN-AMBIGUOUS-PARTITION`, the double-count
//!      SOURCE): a symbol matches more than one category's patterns.
//!
//! CLOSURE IS NECESSARY BUT NOT SUFFICIENT FOR THE PER-CATEGORY ANSWER. The
//! guards above protect the TOTAL and forbid double-counting; they do NOT catch
//! a symbol charged to exactly ONE WRONG category — that mis-attribution
//! conserves perfectly (the total is unchanged) while corrupting the
//! per-category split. Correct bucketing is the CALIBRATION's job (the adapter's
//! category patterns, validated against a real capture), never something a green
//! ledger certifies.
//!
//! A residual/uncategorized fraction above the threshold does not refuse but
//! FLAGS every row (CONSERVATION discipline: the divergence can still hide in
//! the unaccounted instructions), exactly like locate's residual.

use std::collections::HashMap;

use crate::invariants::InvariantViolation;

/// Over-count refusal tolerance: the per-symbol report may slightly exceed the
/// stat total from sampling rounding; beyond this it is a structural over-count.
/// Mirrors `insn.DEFAULT_TOL_PCT`.
pub const DEFAULT_TOL_PCT: f64 = 2.0;

/// Unaccounted (uncategorized + residual) FLAG threshold — tied to the
/// instrument's own A/A spread, like locate's residual threshold. Mirrors
/// `insn.DEFAULT_THRESHOLD_PCT`.
pub const DEFAULT_THRESHOLD_PCT: f64 = 5.0;

/// Pseudo-category name used in the delta ledger so it visibly closes. Mirrors
/// `insn.UNCATEGORIZED`.
pub const UNCATEGORIZED: &str = "(uncategorized)";

/// Pseudo-category name used in the delta ledger so it visibly closes. Mirrors
/// `insn.RESIDUAL`.
pub const RESIDUAL: &str = "(report-residual)";

/// One category definition: `(name, &[substring patterns])`, ordered and
/// matched case-insensitively. The Rust analogue of the Python ordered
/// `[(name, (substring, ...))]`.
pub type CategoryDef = (&'static str, &'static [&'static str]);

/// perf-event name aliases that denote the SAME logical event under different
/// spellings, so the stat<->report event cross-check (INSN-EVENT-MISMATCH) does
/// not false-refuse on a benign alias. Mirrors `insn._EVENT_ALIASES`.
const EVENT_ALIASES: &[(&str, &str)] = &[
    ("inst_retired.any", "instructions"),
    ("inst_retired.any_p", "instructions"),
];

/// Canonicalize a perf-event name for the stat<->report cross-check: lower, drop
/// the `:u`/`:k`/`:upp` modifier, then map known synonyms onto one name. Returns
/// `None` for a missing/blank event (cannot cross-check). Faithful port of
/// `insn._canon_event`.
pub fn canon_event(ev: Option<&str>) -> Option<String> {
    let ev = ev?;
    if ev.is_empty() {
        return None;
    }
    let base = ev.split(':').next().unwrap_or("").trim().to_lowercase();
    let mapped = EVENT_ALIASES
        .iter()
        .find(|(k, _)| *k == base)
        .map(|(_, v)| (*v).to_string())
        .unwrap_or(base);
    if mapped.is_empty() {
        None
    } else {
        Some(mapped)
    }
}

// ---------------------------------------------------------------------------
// Comma formatting (faithful `{:,}` reproduction for refusal messages).
// ---------------------------------------------------------------------------

/// Format an integer with thousands separators (Python `f"{n:,}"`).
fn commafy(n: i64) -> String {
    let neg = n < 0;
    let mut digits = n.unsigned_abs().to_string();
    let mut out = String::new();
    while digits.len() > 3 {
        let split = digits.len() - 3;
        out = format!(",{}{}", &digits[split..], out);
        digits.truncate(split);
    }
    out = format!("{digits}{out}");
    if neg {
        format!("-{out}")
    } else {
        out
    }
}

// ---------------------------------------------------------------------------
// Parsers (FAIL LOUD — a parse that silently finds nothing is the empty-output
// instrument failure class).
// ---------------------------------------------------------------------------

/// A parsed `perf stat` capture. Mirrors the salient keys of the Python dict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerfStat {
    /// The measured retired-instruction total (the ledger anchor).
    pub instructions: i64,
    /// The canonical spelling of the anchor event, for the report cross-check.
    pub instructions_event: Option<String>,
    /// `cycles` count, if present.
    pub cycles: Option<i64>,
    /// Any other `<count> <event>` lines, keyed by lowered event base.
    pub other: HashMap<String, i64>,
}

/// Parse a leading `[\d,]+` run. Returns `(int_value, rest_after_run)` or `None`
/// if the run holds no digit (faithful to `int(group.replace(",", ""))`, which
/// would otherwise fail — we skip such pathological lines rather than panic).
fn take_count(s: &str) -> Option<(i64, &str)> {
    let end = s
        .char_indices()
        .take_while(|(_, c)| c.is_ascii_digit() || *c == ',')
        .map(|(i, c)| i + c.len_utf8())
        .last()
        .unwrap_or(0);
    if end == 0 {
        return None;
    }
    let digits: String = s[..end].chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    let value = digits.parse::<i64>().ok()?;
    Some((value, &s[end..]))
}

/// `\s+` consumer: returns the slice after one-or-more leading ASCII whitespace,
/// or `None` if there is no leading whitespace (the regex `\s+` requires ≥1).
fn skip_ws(s: &str) -> Option<&str> {
    let trimmed = s.trim_start();
    if trimmed.len() == s.len() {
        None
    } else {
        Some(trimmed)
    }
}

/// `perf stat` text -> [`PerfStat`]. Matches `<count> <event>` lines (commas
/// stripped), normalizes the `:u`/`:k`/`:upp` suffix, and keys on the event
/// substring. FAILS LOUD (`INSN-NO-INSTRUCTIONS`) if no retired-instructions
/// line is present. Faithful port of `insn.parse_perf_stat`.
pub fn parse_perf_stat(text: &str) -> Result<PerfStat, InvariantViolation> {
    let mut instructions: Option<i64> = None;
    let mut instructions_event: Option<String> = None;
    let mut cycles: Option<i64> = None;
    let mut other: HashMap<String, i64> = HashMap::new();

    for line in text.lines() {
        let s = line.trim();
        if s.is_empty() || s.starts_with('#') {
            continue;
        }
        // ^([\d,]+)\s+([A-Za-z][\w:.\-/]*)
        let Some((count, after_count)) = take_count(s) else {
            continue;
        };
        let Some(after_ws) = skip_ws(after_count) else {
            continue;
        };
        // Event token: first char [A-Za-z], rest [\w:.\-/]*.
        let mut chars = after_ws.char_indices();
        let Some((_, first)) = chars.next() else {
            continue;
        };
        if !first.is_ascii_alphabetic() {
            continue;
        }
        let mut tok_end = first.len_utf8();
        for (i, c) in chars {
            if c.is_ascii_alphanumeric() || c == '_' || c == ':' || c == '.' || c == '-' || c == '/'
            {
                tok_end = i + c.len_utf8();
            } else {
                break;
            }
        }
        let token = &after_ws[..tok_end];
        // event = token.split(":")[0].lower()
        let event = token.split(':').next().unwrap_or("").to_lowercase();

        if event.contains("instructions")
            || event == "inst_retired.any"
            || event == "inst_retired.any_p"
        {
            // last write wins (perf prints each event once)
            instructions = Some(count);
            instructions_event = canon_event(Some(&event));
        } else if event == "cycles" || event == "cpu-cycles" || event.contains("cycles") {
            cycles.get_or_insert(count); // setdefault — first write wins
        } else {
            other.entry(event).or_insert(count); // setdefault
        }
    }

    match instructions {
        Some(instructions) => Ok(PerfStat {
            instructions,
            instructions_event,
            cycles,
            other,
        }),
        None => Err(InvariantViolation::new(
            "INSN-NO-INSTRUCTIONS",
            "perf stat capture has no retired-instructions line \
             (`instructions` / `instructions:u`). An instruction ledger needs \
             the measured total as its anchor. Capture with \
             `perf stat -e instructions,cycles -- <cmd>`.",
        )),
    }
}

/// Extract the EVENT a `perf report` was sampled on from its header
/// (`# Samples: 4K of event 'instructions:u'`). Returns the canonical event
/// name, or `None` when the header is absent. Faithful port of
/// `insn.parse_perf_report_event` (regex `Samples:.*?\bof events?\s+'([^']+)'`).
pub fn parse_perf_report_event(text: &str) -> Option<String> {
    for line in text.lines() {
        if let Some(ev) = find_event_in_line(line) {
            return canon_event(Some(&ev));
        }
    }
    None
}

/// `Samples:.*?\bof events?\s+'([^']+)'` over one line: find `Samples:`, then
/// (lazily) `of event` / `of events`, then a `'...'` quoted name. The `\b`
/// before `of` is honored by requiring `of`'s preceding char to be a
/// non-word char (or start-of-search).
fn find_event_in_line(line: &str) -> Option<String> {
    let samples_at = line.find("Samples:")?;
    let after_samples = samples_at + "Samples:".len();
    let hay = &line[after_samples..];
    // scan for the earliest `of event`/`of events` with a word boundary before
    // `of`, then the quoted capture (`.*?` is lazy ⇒ earliest match).
    let bytes = hay.as_bytes();
    let mut search_from = 0usize;
    while let Some(rel) = hay[search_from..].find("of event") {
        let of_idx = search_from + rel;
        // \b: char before `of` must not be a word char (or be the boundary).
        let boundary_ok =
            of_idx == 0 || !is_word_byte(bytes[of_idx - 1]) || !hay.is_char_boundary(of_idx); // defensive; ascii here
        if boundary_ok {
            // after "of event", consume optional 's', then \s+, then '...'
            let mut p = of_idx + "of event".len();
            if bytes.get(p) == Some(&b's') {
                p += 1;
            }
            // \s+ (≥1)
            let rest = &hay[p..];
            if let Some(ws_trimmed) = skip_ws(rest) {
                if let Some(q1) = ws_trimmed.find('\'') {
                    let inner = &ws_trimmed[q1 + 1..];
                    if let Some(q2) = inner.find('\'') {
                        return Some(inner[..q2].to_string());
                    }
                }
            }
        }
        search_from = of_idx + 1;
    }
    None
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// `perf report -F period,symbol` text -> `[(symbol, insns)]` with ABSOLUTE
/// per-symbol counts. REFUSES a percentage-only (`-F overhead`) report
/// (`INSN-PERCENT-ONLY`) and an empty/unparseable report (`INSN-EMPTY-REPORT`).
/// Faithful port of `insn.parse_perf_report`.
pub fn parse_perf_report(text: &str) -> Result<Vec<(String, i64)>, InvariantViolation> {
    let mut rows: Vec<(String, i64)> = Vec::new();
    let mut saw_percent = false;

    for line in text.lines() {
        let mut s = line.trim();
        if s.is_empty() || s.starts_with('#') {
            continue;
        }
        // m_pct = ^\d+(?:\.\d+)?%\s+(.*)$  — strip a leading overhead %.
        if let Some(rest) = strip_leading_percent(s) {
            saw_percent = true;
            s = rest;
        }
        // m = ^([\d,]+)\s+(.*)$
        let Some((count, after_count)) = take_count(s) else {
            continue;
        };
        let Some(rest) = skip_ws(after_count) else {
            continue;
        };
        // mk = \[[.kgua]\]\s*(\S.*)$  (search anywhere in rest)
        let sym = match find_symbol_after_marker(rest) {
            Some(after) => after.trim(),
            None => rest.trim(),
        };
        if !sym.is_empty() {
            rows.push((sym.to_string(), count));
        }
    }

    if rows.is_empty() {
        if saw_percent {
            return Err(InvariantViolation::new(
                "INSN-PERCENT-ONLY",
                "perf report is percentage-only (`-F overhead`); there is no \
                 absolute per-symbol count to close an instruction ledger on. \
                 Re-capture with `perf report --stdio -F period,symbol` \
                 (absolute periods).",
            ));
        }
        return Err(InvariantViolation::new(
            "INSN-EMPTY-REPORT",
            "no parseable `<count> [.] <symbol>` rows in the perf report \
             (the 'instrument emitted empty output' class). Capture with \
             `perf report --stdio -F period,symbol`.",
        ));
    }
    Ok(rows)
}

/// `^\d+(?:\.\d+)?%\s+(.*)$` — if `s` starts with a `<number>%` followed by
/// whitespace, return the remainder after the whitespace; else `None`.
fn strip_leading_percent(s: &str) -> Option<&str> {
    let bytes = s.as_bytes();
    let mut i = 0;
    // \d+
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i == 0 {
        return None;
    }
    // (?:\.\d+)?
    if i < bytes.len() && bytes[i] == b'.' {
        let mut j = i + 1;
        let frac_start = j;
        while j < bytes.len() && bytes[j].is_ascii_digit() {
            j += 1;
        }
        if j > frac_start {
            i = j;
        }
        // if no digits after '.', the optional group does not match — i unchanged
    }
    // %
    if i >= bytes.len() || bytes[i] != b'%' {
        return None;
    }
    i += 1;
    // \s+ then (.*)
    skip_ws(&s[i..])
}

/// `\[[.kgua]\]\s*(\S.*)$` searched in `rest`: find a `[x]` marker (x ∈
/// `.kgua`), then skip whitespace and return the slice starting at the first
/// non-space char through end-of-line. Returns `None` if no such marker.
fn find_symbol_after_marker(rest: &str) -> Option<&str> {
    let bytes = rest.as_bytes();
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == b'[' && bytes[i + 2] == b']' && is_marker_kind(bytes[i + 1]) {
            // \s* then require (\S.*) — at least one non-space char.
            let after = &rest[i + 3..];
            let trimmed = after.trim_start();
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
            // marker present but nothing non-space after ⇒ this occurrence fails
            // (\S required); keep scanning for a later marker.
        }
        i += 1;
    }
    None
}

fn is_marker_kind(b: u8) -> bool {
    matches!(b, b'.' | b'k' | b'g' | b'u' | b'a')
}

// ---------------------------------------------------------------------------
// Category resolution (a PARTITION — ambiguity is refused, it is the
// double-count source).
// ---------------------------------------------------------------------------

/// Return the single matching category name, or `None` (uncategorized).
/// `categories`: ordered `[(name, &[substring, ...])]`, matched case-insensitive
/// substring. If a symbol matches MORE THAN ONE category it is NOT a partition —
/// REFUSE (`INSN-AMBIGUOUS-PARTITION`). Faithful port of `insn.resolve_category`.
pub fn resolve_category<'a>(
    symbol: &str,
    categories: &'a [CategoryDef],
) -> Result<Option<&'a str>, InvariantViolation> {
    let low = symbol.to_lowercase();
    let mut hits: Vec<&'a str> = Vec::new();
    for (name, pats) in categories {
        if pats.iter().any(|p| low.contains(&p.to_lowercase())) {
            hits.push(name);
        }
    }
    if hits.len() > 1 {
        let list = hits
            .iter()
            .map(|h| format!("'{h}'"))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(InvariantViolation::new(
            "INSN-AMBIGUOUS-PARTITION",
            format!(
                "symbol '{symbol}' matches categories [{list}] -- a non-partition \
                 would charge the same instructions to >1 bucket (the double-count \
                 source). REFUSING. Make the category patterns mutually exclusive."
            ),
        ));
    }
    Ok(hits.into_iter().next())
}

// ---------------------------------------------------------------------------
// The closed per-binary ledger.
// ---------------------------------------------------------------------------

/// One category row of a [`Ledger`]. Mirrors the per-category dict.
#[derive(Debug, Clone, PartialEq)]
pub struct CategoryRow {
    pub category: String,
    pub insns: i64,
    pub pct_of_total: f64,
    pub insn_per_byte: Option<f64>,
}

/// A closed per-binary instruction ledger. Mirrors the Python `build_ledger`
/// return dict.
#[derive(Debug, Clone, PartialEq)]
pub struct Ledger {
    pub label: String,
    pub measured_total: i64,
    pub report_total: i64,
    pub categorized: i64,
    pub uncategorized: i64,
    pub residual: i64,
    pub residual_pct: f64,
    pub unaccounted: i64,
    pub unaccounted_pct: f64,
    pub flagged: bool,
    pub flag_reason: Option<String>,
    pub tol_pct: f64,
    pub threshold_pct: f64,
    pub volume_bytes: Option<i64>,
    pub insn_per_byte: Option<f64>,
    /// Per-category rows, sorted by `insns` descending (stable).
    pub categories: Vec<CategoryRow>,
    /// category name -> insns (lookup used by [`compare`]).
    pub category_insns: HashMap<String, i64>,
    /// Uncategorized `(symbol, insns)`, sorted by `insns` descending (stable).
    pub uncategorized_symbols: Vec<(String, i64)>,
}

/// Optional parameters for [`build_ledger`] (mirrors the Python keyword args).
#[derive(Debug, Clone, Default)]
pub struct LedgerOpts {
    pub label: Option<String>,
    pub volume_bytes: Option<i64>,
    pub tol_pct: Option<f64>,
    pub threshold_pct: Option<f64>,
    pub stat_event: Option<String>,
    pub report_event: Option<String>,
}

/// `volume_bytes` truthiness mirror: Python `if volume_bytes` is false for
/// `None` AND `0`, so a zero denominator yields `None` per-byte rates.
fn per_byte(n: i64, volume_bytes: Option<i64>) -> Option<f64> {
    match volume_bytes {
        Some(v) if v != 0 => Some(n as f64 / v as f64),
        _ => None,
    }
}

/// Close an instruction ledger for one binary. REFUSES on a stat<->report event
/// mismatch, an over-count, or an ambiguous partition; FLAGS (does not refuse)
/// when the unaccounted fraction exceeds the threshold. Faithful port of
/// `insn.build_ledger`.
///
/// NOTE ON SCOPE (the load-bearing limit — GAP 1): closure is NECESSARY but NOT
/// SUFFICIENT for the per-CATEGORY answer. The guards here catch a wrong TOTAL
/// and a symbol charged to >1 bucket. They do NOT — cannot — catch a symbol
/// charged to exactly ONE WRONG bucket: that mis-attribution conserves perfectly
/// yet corrupts the per-category split. Correct bucketing is the CATEGORY
/// CALIBRATION's responsibility, never something a green ledger certifies.
pub fn build_ledger(
    measured_total: i64,
    symbols: &[(String, i64)],
    categories: &[CategoryDef],
    opts: &LedgerOpts,
) -> Result<Ledger, InvariantViolation> {
    let tol_pct = opts.tol_pct.unwrap_or(DEFAULT_TOL_PCT);
    let threshold_pct = opts.threshold_pct.unwrap_or(DEFAULT_THRESHOLD_PCT);
    let volume_bytes = opts.volume_bytes;

    if measured_total <= 0 {
        return Err(InvariantViolation::new(
            "INSN-NONPOSITIVE-TOTAL",
            format!(
                "measured instruction total must be positive, got {measured_total} \
                 (a zero/negative perf-stat total cannot anchor a ledger)."
            ),
        ));
    }

    // REFUSAL 0 — EVENT MISMATCH (the denominator-mismatch / GAP-2 class).
    let se = canon_event(opts.stat_event.as_deref());
    let re_ = canon_event(opts.report_event.as_deref());
    if let (Some(se), Some(re_)) = (&se, &re_) {
        if se != re_ {
            return Err(InvariantViolation::new(
                "INSN-EVENT-MISMATCH",
                format!(
                    "perf report sampled on event '{re_}' but the stat total is event \
                     '{se}'. Charging '{re_}' periods against an '{se}' total is a \
                     denominator mismatch — the ledger would 'conserve' on the wrong \
                     event and the per-category split would be meaningless. Re-capture \
                     the report with `perf report -F period,symbol` on the SAME event \
                     the stat measured."
                ),
            ));
        }
    }

    // category name -> running insn total, plus a stable order for row building.
    let mut cat_insns: HashMap<String, i64> = HashMap::new();
    for (name, _) in categories {
        cat_insns.entry((*name).to_string()).or_insert(0);
    }
    let mut uncategorized: i64 = 0;
    let mut uncat_syms: Vec<(String, i64)> = Vec::new();

    for (sym, n) in symbols {
        if *n < 0 {
            return Err(InvariantViolation::new(
                "INSN-NEGATIVE-COUNT",
                format!("negative per-symbol count for '{sym}' ({n}) -- corrupt perf report."),
            ));
        }
        match resolve_category(sym, categories)? {
            None => {
                uncategorized += n;
                uncat_syms.push((sym.clone(), *n));
            }
            Some(cat) => {
                *cat_insns.get_mut(cat).expect("category pre-initialized") += n;
            }
        }
    }

    let categorized: i64 = cat_insns.values().sum();
    let report_total = categorized + uncategorized;

    // REFUSAL 1 — OVER-COUNT (the 690M class).
    let over = report_total - measured_total;
    if (over as f64) > measured_total as f64 * tol_pct / 100.0 {
        return Err(InvariantViolation::new(
            "INSN-CLOSURE",
            format!(
                "over-count: perf report sums to {} instructions but perf stat \
                 measured only {} (+{}, {:.2}% > tol {:.1}%). The symbols cannot \
                 retire more than the CPU did — a double-count, a mixed-run pairing, \
                 or the wrong perf event. REFUSING to render a ledger.",
                commafy(report_total),
                commafy(measured_total),
                commafy(over),
                over as f64 / measured_total as f64 * 100.0,
                tol_pct,
            ),
        ));
    }

    let residual = measured_total - report_total;
    // TRIPWIRE, not a guard: residual is DEFINED as measured_total - report_total,
    // so this is an algebraic identity that can never fire here. Kept as defense
    // against a future refactor that recomputes one of these terms independently.
    if ((categorized + uncategorized + residual) - measured_total).abs() > 1 {
        return Err(InvariantViolation::new(
            "INSN-INTERNAL",
            "ledger does not close (internal — algebraic identity violated, \
             a recompute bug)",
        ));
    }

    let unaccounted = uncategorized + residual.max(0);
    let unaccounted_pct = unaccounted as f64 / measured_total as f64 * 100.0;
    let flagged = unaccounted_pct > threshold_pct;
    let flag_reason = if flagged {
        Some(format!(
            "unaccounted {:.1}% of measured instructions (uncategorized {:.1}% + \
             report-residual {:.1}%) exceeds threshold {:.1}% — an instruction \
             divergence can still hide outside the named categories",
            unaccounted_pct,
            uncategorized as f64 / measured_total as f64 * 100.0,
            residual.max(0) as f64 / measured_total as f64 * 100.0,
            threshold_pct,
        ))
    } else {
        None
    };

    // per-category rows in declared order, then stable sort by -insns.
    let mut cat_rows: Vec<CategoryRow> = categories
        .iter()
        .map(|(name, _)| {
            let n = cat_insns[*name];
            CategoryRow {
                category: (*name).to_string(),
                insns: n,
                pct_of_total: n as f64 / measured_total as f64 * 100.0,
                insn_per_byte: per_byte(n, volume_bytes),
            }
        })
        .collect();
    cat_rows.sort_by_key(|r| std::cmp::Reverse(r.insns)); // stable; -insns ordering
    uncat_syms.sort_by_key(|kv| std::cmp::Reverse(kv.1)); // stable; -count ordering

    Ok(Ledger {
        label: opts.label.clone().unwrap_or_else(|| "binary".to_string()),
        measured_total,
        report_total,
        categorized,
        uncategorized,
        residual,
        residual_pct: residual as f64 / measured_total as f64 * 100.0,
        unaccounted,
        unaccounted_pct,
        flagged,
        flag_reason,
        tol_pct,
        threshold_pct,
        volume_bytes,
        insn_per_byte: per_byte(measured_total, volume_bytes),
        categories: cat_rows,
        category_insns: cat_insns,
        uncategorized_symbols: uncat_syms,
    })
}

// ---------------------------------------------------------------------------
// Cross-binary delta — the positive "where do the excess instructions go".
// ---------------------------------------------------------------------------

/// One row of a [`Comparison`]: role-matched category deltas (a - b).
#[derive(Debug, Clone, PartialEq)]
pub struct CompareRow {
    pub category: String,
    pub a_insns: i64,
    pub b_insns: i64,
    pub delta: i64,
    pub a_pb: Option<f64>,
    pub b_pb: Option<f64>,
    pub delta_pb: Option<f64>,
}

/// Cross-binary delta ledger. Mirrors the Python `compare` return dict.
#[derive(Debug, Clone, PartialEq)]
pub struct Comparison {
    pub a_label: String,
    pub b_label: String,
    pub total_delta: i64,
    pub volume_a: Option<i64>,
    pub volume_b: Option<i64>,
    pub volume_mismatch: bool,
    pub both_volume: bool,
    /// Rows ranked by `|delta|` descending (stable).
    pub rows: Vec<CompareRow>,
    pub delta_closes: bool,
}

/// Role-matched per-category insn (and insn/byte) deltas, a - b, ranked by
/// `|delta|`. The DELTA LEDGER is itself conservation-asserted: Σ category
/// deltas + uncategorized delta + residual delta == total delta
/// (`INSN-DELTA-CLOSURE`). Faithful port of `insn.compare`.
pub fn compare(led_a: &Ledger, led_b: &Ledger) -> Result<Comparison, InvariantViolation> {
    let total_delta = led_a.measured_total - led_b.measured_total;
    let va = led_a.volume_bytes;
    let vb = led_b.volume_bytes;
    // both_vol mirrors Python truthiness `va and vb` (None and 0 are falsy).
    let both_vol = va.is_some_and(|v| v != 0) && vb.is_some_and(|v| v != 0);
    let vol_mismatch = both_vol && va != vb;

    // names = unique-in-order over a.categories ++ b.categories.
    let mut names: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for r in led_a.categories.iter().chain(led_b.categories.iter()) {
        if seen.insert(r.category.clone()) {
            names.push(r.category.clone());
        }
    }

    let pb = |n: i64, v: Option<i64>| -> Option<f64> {
        match v {
            Some(v) if v != 0 => Some(n as f64 / v as f64),
            _ => None,
        }
    };

    let mut rows: Vec<CompareRow> = Vec::new();
    for name in &names {
        let an = *led_a.category_insns.get(name).unwrap_or(&0);
        let bn = *led_b.category_insns.get(name).unwrap_or(&0);
        rows.push(CompareRow {
            category: name.clone(),
            a_insns: an,
            b_insns: bn,
            delta: an - bn,
            a_pb: pb(an, va),
            b_pb: pb(bn, vb),
            delta_pb: if both_vol {
                Some(pb(an, va).unwrap() - pb(bn, vb).unwrap())
            } else {
                None
            },
        });
    }
    // pseudo-rows so the delta ledger visibly closes
    rows.push(CompareRow {
        category: UNCATEGORIZED.to_string(),
        a_insns: led_a.uncategorized,
        b_insns: led_b.uncategorized,
        delta: led_a.uncategorized - led_b.uncategorized,
        a_pb: pb(led_a.uncategorized, va),
        b_pb: pb(led_b.uncategorized, vb),
        delta_pb: if both_vol {
            Some(pb(led_a.uncategorized, va).unwrap() - pb(led_b.uncategorized, vb).unwrap())
        } else {
            None
        },
    });
    rows.push(CompareRow {
        category: RESIDUAL.to_string(),
        a_insns: led_a.residual,
        b_insns: led_b.residual,
        delta: led_a.residual - led_b.residual,
        a_pb: pb(led_a.residual, va),
        b_pb: pb(led_b.residual, vb),
        delta_pb: if both_vol {
            Some(pb(led_a.residual, va).unwrap() - pb(led_b.residual, vb).unwrap())
        } else {
            None
        },
    });

    let delta_sum: i64 = rows.iter().map(|r| r.delta).sum();
    let delta_closes = (delta_sum - total_delta).abs() <= 1;
    if !delta_closes {
        return Err(InvariantViolation::new(
            "INSN-DELTA-CLOSURE",
            format!(
                "delta ledger does not close (Σ row deltas {} != total delta {}) \
                 — internal accounting error.",
                commafy(delta_sum),
                commafy(total_delta),
            ),
        ));
    }

    // ranked by -|delta| (stable).
    rows.sort_by_key(|r| std::cmp::Reverse(r.delta.abs()));

    Ok(Comparison {
        a_label: led_a.label.clone(),
        b_label: led_b.label.clone(),
        total_delta,
        volume_a: va,
        volume_b: vb,
        volume_mismatch: vol_mismatch,
        both_volume: both_vol,
        rows,
        delta_closes,
    })
}

// ---------------------------------------------------------------------------
// Top-level: build one or two ledgers from parsed captures.
// ---------------------------------------------------------------------------

/// The over-count tolerance + unaccounted-flag threshold pair (the Python
/// `tol_pct` / `threshold_pct` keyword args, bundled). `Default` yields the
/// module constants.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Thresholds {
    pub tol_pct: f64,
    pub threshold_pct: f64,
}

impl Default for Thresholds {
    fn default() -> Thresholds {
        Thresholds {
            tol_pct: DEFAULT_TOL_PCT,
            threshold_pct: DEFAULT_THRESHOLD_PCT,
        }
    }
}

/// Parse a stat+report capture pair and close one ledger. Faithful port of
/// `insn.insn_from_text`.
pub fn insn_from_text(
    stat_text: &str,
    report_text: &str,
    categories: &[CategoryDef],
    label: Option<&str>,
    volume_bytes: Option<i64>,
    thresholds: Thresholds,
) -> Result<Ledger, InvariantViolation> {
    let stat = parse_perf_stat(stat_text)?;
    let symbols = parse_perf_report(report_text)?;
    let report_event = parse_perf_report_event(report_text);
    build_ledger(
        stat.instructions,
        &symbols,
        categories,
        &LedgerOpts {
            label: label.map(str::to_string),
            volume_bytes,
            tol_pct: Some(thresholds.tol_pct),
            threshold_pct: Some(thresholds.threshold_pct),
            stat_event: stat.instructions_event,
            report_event,
        },
    )
}

/// Inputs for the B (second) binary in [`insn_from_files`].
#[derive(Debug, Clone, Default)]
pub struct BInputs {
    pub stat: Option<String>,
    pub report: Option<String>,
    pub label: Option<String>,
    pub bytes: Option<i64>,
}

/// The result of [`insn_from_files`]: the A ledger, optional B ledger, and the
/// optional cross-binary comparison.
#[derive(Debug, Clone, PartialEq)]
pub struct InsnResult {
    pub a: Ledger,
    pub b: Option<Ledger>,
    pub compare: Option<Comparison>,
}

/// Build the ledger(s) from file paths; the CLI entry. Validates the B pairing
/// BEFORE any file IO (`INSN-HALF-PAIR`) and refuses a missing capture
/// (`INSN-NO-CAPTURE`). Faithful port of `insn.insn_from_files`.
pub fn insn_from_files(
    a_stat: &str,
    a_report: &str,
    categories: &[CategoryDef],
    a_label: Option<&str>,
    a_bytes: Option<i64>,
    b: &BInputs,
    thresholds: Thresholds,
) -> Result<InsnResult, InvariantViolation> {
    let b_requested = b.stat.is_some() || b.report.is_some();
    let b_complete = b.stat.is_some() && b.report.is_some();
    if b_requested && !b_complete {
        return Err(InvariantViolation::new(
            "INSN-HALF-PAIR",
            "the B binary needs BOTH --b-stat and --b-report (a stat \
             without a report, or vice versa, cannot close a ledger).",
        ));
    }

    fn read(path: &str, kind: &str) -> Result<String, InvariantViolation> {
        match std::fs::read_to_string(path) {
            Ok(s) => Ok(s),
            Err(_) => Err(InvariantViolation::new(
                "INSN-NO-CAPTURE",
                format!("no such {kind} capture: {path}"),
            )),
        }
    }

    let led_a = insn_from_text(
        &read(a_stat, "perf stat")?,
        &read(a_report, "perf report")?,
        categories,
        a_label,
        a_bytes,
        thresholds,
    )?;

    let mut led_b = None;
    let mut cmp = None;
    if b_requested {
        let b_stat = b.stat.as_deref().expect("b pairing validated complete");
        let b_report = b.report.as_deref().expect("b pairing validated complete");
        let ledger_b = insn_from_text(
            &read(b_stat, "perf stat")?,
            &read(b_report, "perf report")?,
            categories,
            b.label.as_deref(),
            b.bytes,
            thresholds,
        )?;
        cmp = Some(compare(&led_a, &ledger_b)?);
        led_b = Some(ledger_b);
    }

    Ok(InsnResult {
        a: led_a,
        b: led_b,
        compare: cmp,
    })
}

// ---------------------------------------------------------------------------
// The gzippy adapter's category flavor (port of adapters/gzippy.py
// INSN_CATEGORIES). The adapters are not yet ported to Rust; the calibration
// pins (test_insn_calib.py) close against THIS taxonomy. When the adapter layer
// is ported, this const moves there unchanged.
// ---------------------------------------------------------------------------

/// The gzippy↔rapidgzip instruction-category taxonomy (ordered, mutually
/// exclusive substrings). Faithful port of `adapters/gzippy.py INSN_CATEGORIES`.
pub const INSN_CATEGORIES: &[CategoryDef] = &[
    (
        "marker_emit",
        &[
            "read_internal_compressed",
            "emit_backref_ring",
            "deflate::block<false>::read(",
        ],
    ),
    (
        "clean_contig",
        &[
            "run_contig",
            "huffman_short_bits_cached",
            "decode_clean_into_contig",
        ],
    ),
    ("segmented_ring", &["segmentedu16::push", "segmentedu8"]),
    (
        "marker_read",
        &[
            "resolve_chunk_markers",
            "applywindow",
            "getwindowat",
            "resolve_range_into_buf",
            "setinitialwindow",
        ],
    ),
    (
        "isal_ffi",
        &[
            "loop_block",
            "large_byte_copy",
            "small_byte_copy",
            "decode_len_dist",
            "inflate_in_load",
            "multi_symbol_start",
            "end_loop_block",
            "decode_huffman_code_block",
            "..@",
        ],
    ),
    (
        "tables",
        &[
            "lut_huffman",
            "disttable",
            "make_inflate_huff_code",
            "setup_dynamic_header",
            "set_and_expand_lit_len",
            "read_header",
            "readheader",
            "huffmancodingisal",
        ],
    ),
    (
        "finalize",
        &[
            "finalize_with_deflate",
            "finish_decode_chunk",
            "decode_chunk_with_rapidgzip",
            "chunkdata::finalize(",
            "finishdecodechunk",
            "gzipchunk",
        ],
    ),
    ("crc", &["crc32fast", "crc32_gzip"]),
    (
        "block_finder",
        &["block_finder", "blockfinder", "memchr", "peek2", "read2"],
    ),
    ("kernel", &["0xffffffff"]),
    (
        "sched",
        &[
            "queue_prefetched_marker",
            "__tls_get_addr",
            "__cxa_begin_catch",
            "call_once_force",
        ],
    ),
    (
        "memops",
        &["memcpy", "memmove", "memset", "__memmove", "__memcpy"],
    ),
];

// ---------------------------------------------------------------------------
// The ENCODER (compression) hot-path category flavor. Selected by
// `--feature compress-encode`, this partitions a compression cell's perf-report
// symbols into ROLE buckets so gzippy and a rival encoder (igzip / libdeflate)
// line up BY ROLE — the "where do gzippy's excess ENCODE instructions go"
// answer, without reading gzippy source, purely from symbol names.
//
// ⚠️ FIRST-CUT / UNCALIBRATED (2026-07-18): these substrings are a STARTING
// partition, NOT yet validated against a real gzippy/igzip encode capture (that
// needs perf on a Linux box). Two properties are guaranteed regardless:
//   * a symbol matching TWO categories REFUSES (`INSN-AMBIGUOUS-PARTITION`) —
//     it never silently picks one (the closed-ledger invariant);
//   * a symbol matching NONE lands in `(uncategorized)` and FLAGS the ledger
//     when the unaccounted fraction exceeds the threshold — never invented away.
// So an over-broad substring (e.g. output_io's `write` vs huffman_encode's
// `write_bits`, both firing on a real `write_bits` symbol) surfaces LOUDLY as a
// refusal that PULLS the calibration edit here, rather than a silent mis-split.
// This is the ONE place to edit the map when calibrating against a real capture.
// ---------------------------------------------------------------------------

/// The ENCODE (compression) hot-path role taxonomy (ordered, matched
/// case-insensitively as substrings). A FIRST-CUT partition to be calibrated
/// against a real perf capture; the closure + ambiguity guards make a wrong
/// first cut fail LOUD, not silently. Selected via `--feature compress-encode`.
pub const ENCODE_INSN_CATEGORIES: &[CategoryDef] = &[
    (
        "match_finder",
        &[
            "longest_match",
            "deflate_medium",
            "deflate_quick",
            "match",
            // NARROWED 2026-07-22 (igzip head-to-head re-verification,
            // SF-igzip-symbolization): bare "hash" collided with
            // `crc32fast::hash` (gzippy's CRC32 symbol legitimately contains
            // the substring "hash" -- `INSN-AMBIGUOUS-PARTITION` against
            // `crc`'s "crc" keyword, refused by `resolve_category` on a real
            // igzip-vs-gzippy L1 exec run). Replaced with the SPECIFIC
            // matchfinder identifiers actually used in gzippy's own
            // `compress/deflate/matchfinder/{common,hc,bt,lzfind}.rs`
            // (`lz_hash`, `hash3_tab`, `hash4_tab`, `hash_at`) so real
            // matchfinder hashing still categorizes correctly without the
            // bare substring catching every unrelated "*hash*" symbol
            // (crc32fast::hash, std HashMap internals, etc).
            "lz_hash",
            "hash3_tab",
            "hash4_tab",
            "hash_at",
            "find_match",
            // NARROWED 2026-07-22 (igzip head-to-head re-verification,
            // same campaign as the "hash" narrowing above): bare "icf"
            // collided THREE ways on igzip's real symbol table (nm on
            // /root/isal-src/programs/igzip), because igzip embeds "icf" in
            // every ICF-related function name regardless of PASS:
            //   - `isal_deflate_icf_body_hash_hist_04.*`  -- pass-1 (hash +
            //     match-find + ICF-token build, fused kernel) -- correctly
            //     match_finder.
            //   - `encode_deflate_icf_04.*`  -- pass-2 (ICF-token ->
            //     DEFLATE bitstream) -- this is igzip's EMIT stage, the
            //     direct counterpart of gzippy's `emit_sequences`/
            //     `emit_block` below, and bare "icf" was silently
            //     MISCATEGORIZING it as match_finder (no ambiguity error --
            //     it only hit ONE keyword, just the wrong one; the token-
            //     level "does igzip's emit really run ~4x cheaper per
            //     token" re-verification this fix exists for depends on
            //     this landing in the RIGHT bucket).
            //   - `create_hufftables_icf`  -- huffman table build -- also
            //     matches huffman_build's "create_huff", so bare "icf" made
            //     it INSN-AMBIGUOUS-PARTITION (REFUSED, blocking the whole
            //     igzip exec run).
            // Fixed by using the SPECIFIC longer prefix each pass actually
            // uses instead of the bare 3-letter substring: "deflate_icf_
            // body" stays in match_finder (pass-1 only); "encode_deflate_
            // icf" moves to huffman_encode (pass-2, see that category's
            // list below); `create_hufftables_icf` now matches ONLY
            // huffman_build's "create_huff".
            "deflate_icf_body",
            "skip_match",
            // CALIBRATED 2026-07-22 (gzippy @ 6726cf38, dd79_text6/dd79_bin6
            // L1, cachegrind+`--read-inline-info=yes` vs the gzippy
            // `anatomy-counters` exact side): at L1/L0, LTO fuses the ENTIRE
            // igzip-class chainless single-probe matchfinder
            // (`compress/deflate/parse/fast.rs` -- see that file's own doc
            // comment, "The match finder is a port of igzip's level-0/1
            // deflate body") into one outer `fn=compress` symbol shared with
            // unrelated wrapper code, so the bare function name carries no
            // signal (confirmed: `hc_probe_attempts`/`bt_probe_attempts` are
            // BOTH EXACTLY ZERO at L1 on both corpora -- L1 does not call
            // `HcMatchfinder`/`BtMatchfinder` at all). `FnCost::file` (this
            // module's caller folds it into the categorization haystack)
            // recovers the split via cachegrind's inline-info `fl=`
            // attribution: match this specific file fragment, not `fast`
            // alone (huffman/fast.rs — the UNRELATED L1-named-coincidence
            // Huffman-code builder file — would collide on a bare "fast").
            "parse/fast.rs",
        ],
    ),
    (
        "huffman_build",
        &[
            "build_huff",
            "gen_huff",
            "create_huff",
            "tree",
            "histogram",
            "freq",
            "code_length",
            "count_syms",
            // CALIBRATED 2026-07-22 (see match_finder's note above for the
            // method): `make_huffman_code` (huffman/fast.rs) and
            // `build_dynamic_header` (huffman/header.rs) are REAL,
            // NOT-inlined-away symbols on gzippy's L1/L6 path (confirmed
            // present as their own `fn=` entries in cachegrind, ~1-2% of
            // total Ir each) that the original keyword list missed entirely
            // -- neither symbol's bare name contains any prior keyword, so
            // 100% of their Ir silently fell into `uncategorized_ir`. Cross-
            // checked against the exact `huffman_make_code_calls` counter
            // (gzippy `anatomy-counters`): L1/text6 = 290 calls, reconciling
            // exactly to `2 + 3*blocks_emitted_dynamic` per the integration
            // test's closed-form (`tests/anatomy_counters.rs`).
            "make_huffman",
            "dynamic_header",
        ],
    ),
    (
        "huffman_encode",
        &[
            "encode_block",
            "huff_encode",
            "flush_bits",
            "put_bits",
            "write_bits",
            "compress_block",
            "encode_lit",
            // CALIBRATED 2026-07-22: `emit_sequences` (parse/mod.rs) is the
            // shared token->bitstream encoder EVERY parse strategy funnels
            // through (greedy/lazy/fast/near_optimal all call the same
            // `emit_block`->`emit_sequences`) -- it is gzippy's single
            // largest standalone (non-fused) symbol on the L1 profile
            // (~28% of total Ir) and matched NO prior keyword, so it was
            // 100% uncategorized. `emit_block` (parse/mod.rs) is the
            // block-type dispatch (stored/fixed/dynamic) + header write
            // wrapping `emit_sequences`; kept in this category (not
            // `block_split`, which is reserved for `block_split.rs`'s
            // SPLIT-DECISION heuristic/tally machinery, a distinct concept
            // the gzippy `anatomy_counters` module also keeps separate as
            // `block_split_observations` vs `blocks_emitted_*`).
            "emit_sequences",
            "emit_block",
            // igzip's pass-2 ICF-token -> DEFLATE-bitstream encoder (see
            // match_finder's "icf" narrowing note above) -- the direct
            // structural counterpart of `emit_sequences`/`emit_block` on
            // igzip's side, e.g. `encode_deflate_icf_04.main_loop`.
            "encode_deflate_icf",
        ],
    ),
    (
        "block_split",
        &[
            "split",
            "block_boundary",
            "flush_block",
            "end_block",
            "tally",
        ],
    ),
    ("crc", &["crc", "adler", "checksum", "fold"]),
    (
        "output_io",
        &[
            // "stream" REMOVED 2026-07-22 (calibration pass, see
            // match_finder/huffman_build/huffman_encode's CALIBRATED notes
            // above): once `FnCost::file` folds the cachegrind `fl=` source
            // path into the categorization haystack, a bare "stream" is a
            // landmine in this domain -- gzippy's `bitstream.rs` (the
            // bit-level I/O primitive `emit_sequences` inlines from) matches
            // it on EVERY encode-side profile, colliding with
            // `huffman_encode`'s "emit_sequences"/"write_bits" (REFUSING
            // ambiguity, confirmed: `ANATOMY=VOID ... matches categories
            // ['huffman_encode','output_io']` on gzippy L1/dd79_text6
            // before this fix).
            //
            // bare "write" REMOVED 2026-07-22 (igzip head-to-head
            // re-verification, SF-igzip-symbolization): the exact same
            // landmine as "stream" above -- "write" is a substring of
            // `huffman_encode`'s own "write_bits" keyword AND of igzip's
            // real pass-1-body symbols `write_lit_bits`/`write_lit_bits_
            // finish`/`write_first_byte` (which belong to match_finder/ICF
            // build, not I/O -- confirmed via nm on
            // /root/isal-src/programs/igzip: those are
            // `isal_deflate_icf_body_hash_hist_04.write_lit_bits`, part of
            // the fused hash/ICF-build kernel, NOT `fwrite_safe`, igzip's
            // actual file-write function). `resolve_category` REFUSED with
            // `INSN-AMBIGUOUS-PARTITION` on
            // `isal_deflate_icf_body_hash_hist_04.write_lit_bits` matching
            // ['match_finder','output_io'] before this fix. Replaced with
            // the SPECIFIC stdio identifiers real I/O symbols actually use
            // (igzip: `fread_safe`/`fwrite_safe`; libc: `fwrite`/`fread`) so
            // genuine file I/O still categorizes without the collision.
            "fwrite",
            "fread",
            "copy_bytes",
            "memcpy",
            // bare "output" REMOVED 2026-07-22 (same campaign as "write"
            // above): collided with igzip's real pass-1-body finalizer
            // `isal_deflate_icf_body_hash_hist_04.output_end` (match_finder
            // via the "deflate_icf_body" prefix keyword), REFUSED as
            // INSN-AMBIGUOUS-PARTITION. `flush_output` (kept below) already
            // covers the intended "actual I/O buffer flush" symbols without
            // the bare substring catching every unrelated "*output*" name.
            "flush_output",
        ],
    ),
];

/// Select the category taxonomy for an `insn` run from the `--feature` value.
/// `compress-encode` (alias `encode`) picks the ENCODER role partition; any
/// other value (including `None`/empty, the historical DECODE default) keeps
/// [`INSN_CATEGORIES`]. Case-insensitive, trims surrounding whitespace. Additive:
/// the decode path is unchanged when no encode feature is requested.
pub fn categories_for_feature(feature: Option<&str>) -> &'static [CategoryDef] {
    match feature.map(|f| f.trim().to_ascii_lowercase()).as_deref() {
        Some("compress-encode") | Some("encode") => ENCODE_INSN_CATEGORIES,
        _ => INSN_CATEGORIES,
    }
}

#[cfg(test)]
mod tests;
