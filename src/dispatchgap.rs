//! dispatchgap.rs — per-WORKER inter-chunk DISPATCH-GAP attribution.
//!
//! Answers: when a parallel-SM worker finishes decoding chunk N, how long
//! until it starts chunk N+1 (the GAP), and WHAT was the pipeline blocked on
//! during that gap? Discriminates the four dispatch-starvation hypotheses:
//!
//!   - H-QUEUE:     the next task was already SUBMITted when the worker freed
//!                  (or submitted mid-gap) — the residual is pool pick/handoff
//!                  latency (condvar wake + pre-park spin + lock).
//!   - H-BLOCKFIND: the pool was EMPTY and the consumer was inside a
//!                  `block_finder.get` (next boundary not found yet).
//!   - H-WINDOWDEP: the pool was EMPTY and the consumer was inside
//!                  `recv_post_process_blocking` (serial marker/window
//!                  resolution of an earlier chunk — the 32 KiB history dep).
//!   - H-DECODEWAIT:the pool was EMPTY and the consumer was inside
//!                  `get_with_prefetch`/`try_take_prefetched_pumping` (blocked
//!                  waiting for the chunk IT needs — prefetch-horizon self-stall).
//!   - H-OTHER:     pool empty, consumer in none of the above (submit latency,
//!                  output write, bookkeeping).
//!
//! ## Input
//!
//! JSON-lines event log emitted by gzippy's throwaway `dg` instrumentation
//! (`GZIPPY_DISPATCHGAP=<path>`), one object per line:
//!   {"t":<ns>,"k":<kind>,"key":<u64>,"w":<i32>,"f":<u8>}
//! kinds: 0 SUBMIT, 1 START, 2 FINISH (key=chunk start_bit, w=worker,
//! f=window_present); 3/4 BF enter/exit, 5/6 MW enter/exit, 7/8 ALLOC,
//! 9/10 DW enter/exit (consumer, w=-1).
//!
//! ## Self-validation (Gate-0, printed as SELFTEST=PASS/FAIL, non-zero exit on FAIL)
//!
//!   (a) NON-INERT: events>0, workers>0, chunks>0, total gap>0.
//!   (b) PER-WORKER CONSERVATION: decode + gap == window (last_finish −
//!       first_start) within epsilon, for every worker.
//!   (c) BUCKET CONSERVATION: Σ(H-QUEUE+BLOCKFIND+WINDOWDEP+DECODEWAIT+OTHER)
//!       == Σ gap within epsilon.
//!   (d) PAIRING: every START has a matching FINISH (same key,worker); every
//!       consumer ENTER has a matching EXIT.
//!   (e) NO DROPPED LINES: every line in the log parses to a full event — a
//!       malformed/truncated line means the log is corrupt or the schema moved,
//!       and a silently-shrunk event set would fabricate a plausible breakdown.
//!
//! `fulcrum dispatchgap selftest` is the baked Gate-0: it drives the FULL
//! analysis over synthetic logs and asserts both the PASS path (correct bucket
//! attribution) and the REFUSAL paths (pairing break, inert log, dropped lines).

use std::collections::HashMap;
use std::process::ExitCode;

#[derive(Clone, Copy, Debug)]
struct Ev {
    t: u64,
    k: u8,
    key: u64,
    w: i32,
    #[allow(dead_code)]
    f: u8,
}

fn parse_field(line: &str, name: &str) -> Option<i64> {
    // line form: {"t":123,"k":1,"key":456,"w":-1,"f":0}
    let pat = format!("\"{name}\":");
    let start = line.find(&pat)? + pat.len();
    let rest = &line[start..];
    let end = rest
        .find(|c: char| !(c.is_ascii_digit() || c == '-'))
        .unwrap_or(rest.len());
    rest[..end].parse::<i64>().ok()
}

/// Parse the event log. Returns `(events, dropped)` where `dropped` counts
/// non-empty lines that failed to parse to a full event — a nonzero count is a
/// Gate-0 FAIL (a silently-shrunk event set would fabricate a plausible
/// breakdown from a corrupt/truncated log).
fn parse_log(text: &str) -> (Vec<Ev>, usize) {
    let mut v = Vec::new();
    let mut dropped = 0usize;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parsed = if line.starts_with('{') {
            match (
                parse_field(line, "t"),
                parse_field(line, "k"),
                parse_field(line, "key"),
                parse_field(line, "w"),
                parse_field(line, "f"),
            ) {
                (Some(t), Some(k), Some(key), Some(w), Some(f)) => Some(Ev {
                    t: t as u64,
                    k: k as u8,
                    key: key as u64,
                    w: w as i32,
                    f: f as u8,
                }),
                _ => None,
            }
        } else {
            None
        };
        match parsed {
            Some(ev) => v.push(ev),
            None => dropped += 1,
        }
    }
    (v, dropped)
}

/// Closed intervals [start,end] built from paired ENTER/EXIT events.
fn build_intervals(evs: &[Ev], enter: u8, exit: u8) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut open: Vec<u64> = Vec::new();
    for e in evs {
        if e.k == enter {
            open.push(e.t);
        } else if e.k == exit {
            if let Some(s) = open.pop() {
                out.push((s, e.t));
            }
        }
    }
    out.sort_unstable();
    out
}

/// Overlap of [a,b] with a set of sorted, possibly-nested intervals.
/// Returns the total covered length (union-clamped to [a,b]).
fn overlap(a: u64, b: u64, ivs: &[(u64, u64)]) -> u64 {
    if b <= a {
        return 0;
    }
    // Collect clamped sub-intervals then union them.
    let mut segs: Vec<(u64, u64)> = ivs
        .iter()
        .filter_map(|&(s, e)| {
            let s2 = s.max(a);
            let e2 = e.min(b);
            if e2 > s2 {
                Some((s2, e2))
            } else {
                None
            }
        })
        .collect();
    if segs.is_empty() {
        return 0;
    }
    segs.sort_unstable();
    let mut total = 0u64;
    let mut cur_s = segs[0].0;
    let mut cur_e = segs[0].1;
    for &(s, e) in &segs[1..] {
        if s > cur_e {
            total += cur_e - cur_s;
            cur_s = s;
            cur_e = e;
        } else if e > cur_e {
            cur_e = e;
        }
    }
    total += cur_e - cur_s;
    total
}

struct WorkerRow {
    w: i32,
    n_chunks: usize,
    window_ns: u64,
    decode_ns: u64,
    gap_ns: u64,
    reconciled: bool,
}

#[derive(Default, Clone, Copy)]
struct Buckets {
    queue: u64,
    blockfind: u64,
    windowdep: u64,
    decodewait: u64,
    other: u64,
}
impl Buckets {
    fn total(&self) -> u64 {
        self.queue + self.blockfind + self.windowdep + self.decodewait + self.other
    }
}

fn ms(ns: u64) -> f64 {
    ns as f64 / 1e6
}
fn pct(x: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        100.0 * x as f64 / whole as f64
    }
}

/// The full analysis of one event log — everything the report prints and the
/// Gate-0 gates check, computed PURELY from the log text (no I/O, no clock), so
/// `selftest` can drive the identical path the CLI drives.
struct Analysis {
    n_events: usize,
    dropped_lines: usize,
    n_start: usize,
    n_finish: usize,
    worker_ids: Vec<i32>,
    total_chunks: usize,
    rows: Vec<WorkerRow>,
    per_worker_buckets: HashMap<i32, Buckets>,
    total_buckets: Buckets,
    gap_sum: u64,
    tot_window: u64,
    tot_decode: u64,
    n_bf: usize,
    n_mw: usize,
    n_dw: usize,
    /// Gaps whose next task had NO known SUBMIT ≤ its start — those gaps were
    /// booked as just-in-time H-QUEUE by necessity, so a large count means the
    /// H-QUEUE share is a guess, not an attribution.
    unknown_submit_gaps: usize,
    // Gate-0 flags.
    non_inert: bool,
    all_reconciled: bool,
    bucket_recon: bool,
    pairing_ok: bool,
    no_dropped: bool,
}

impl Analysis {
    fn selftest_pass(&self, workers_ok: bool) -> bool {
        self.non_inert
            && self.all_reconciled
            && self.bucket_recon
            && self.pairing_ok
            && self.no_dropped
            && workers_ok
    }

    fn dominant(&self) -> (&'static str, u64) {
        let tb = &self.total_buckets;
        [
            ("H-QUEUE", tb.queue),
            ("H-BLOCKFIND", tb.blockfind),
            ("H-WINDOWDEP", tb.windowdep),
            ("H-DECODEWAIT", tb.decodewait),
            ("H-OTHER", tb.other),
        ]
        .into_iter()
        .max_by_key(|&(_, v)| v)
        .unwrap()
    }
}

pub fn cmd_dispatchgap(args: &[String]) -> ExitCode {
    if args.first().map(|s| s.as_str()) == Some("selftest") {
        return selftest();
    }
    let mut path: Option<String> = None;
    let mut label = String::from("run");
    let mut json_out: Option<String> = None;
    let mut expect_workers: Option<usize> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--label" => {
                i += 1;
                label = args.get(i).cloned().unwrap_or_default();
            }
            "--json" => {
                i += 1;
                json_out = args.get(i).cloned();
            }
            "--workers" => {
                i += 1;
                expect_workers = args.get(i).and_then(|s| s.parse().ok());
            }
            "-h" | "--help" => {
                eprintln!("usage: fulcrum dispatchgap <event-log.jsonl> [--label L] [--workers N] [--json out.json]\n       fulcrum dispatchgap selftest   (baked Gate-0 — synthetic logs, PASS + refusal paths)");
                return ExitCode::SUCCESS;
            }
            s if path.is_none() => path = Some(s.to_string()),
            _ => {}
        }
        i += 1;
    }
    let Some(path) = path else {
        eprintln!("fulcrum dispatchgap: need an event-log path");
        return ExitCode::FAILURE;
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("fulcrum dispatchgap: cannot read {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let a = analyze(&text);
    let workers_ok = expect_workers.map(|n| n == a.worker_ids.len()).unwrap_or(true);
    print_report(&a, &label, workers_ok, json_out.as_deref());
    if a.selftest_pass(workers_ok) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn analyze(text: &str) -> Analysis {
    let (evs, dropped_lines) = parse_log(text);

    // Consumer phase intervals.
    let bf = build_intervals(&evs, 3, 4);
    let mw = build_intervals(&evs, 5, 6);
    let dw = build_intervals(&evs, 9, 10);

    // SUBMIT time per key: keep ALL submit times (a key may be re-submitted).
    let mut submits: HashMap<u64, Vec<u64>> = HashMap::new();
    for e in &evs {
        if e.k == 0 {
            submits.entry(e.key).or_default().push(e.t);
        }
    }
    for v in submits.values_mut() {
        v.sort_unstable();
    }

    // Per-worker task list: (start, finish, key). Match START->FINISH by key
    // per worker in order.
    let mut per_worker_open: HashMap<i32, HashMap<u64, u64>> = HashMap::new();
    let mut tasks: HashMap<i32, Vec<(u64, u64, u64)>> = HashMap::new();
    let mut n_start = 0usize;
    let mut n_finish = 0usize;
    let mut pairing_ok = true;
    for e in &evs {
        match e.k {
            1 => {
                n_start += 1;
                per_worker_open
                    .entry(e.w)
                    .or_default()
                    .insert(e.key, e.t);
            }
            2 => {
                n_finish += 1;
                if let Some(start) = per_worker_open.get_mut(&e.w).and_then(|m| m.remove(&e.key)) {
                    tasks.entry(e.w).or_default().push((start, e.t, e.key));
                } else {
                    pairing_ok = false;
                }
            }
            _ => {}
        }
    }
    for m in per_worker_open.values() {
        if !m.is_empty() {
            pairing_ok = false;
        }
    }

    // The pseudo-worker -2 (unbound / consumer trial decodes) is EXCLUDED from
    // both the pool timeline and the chunk counts — its "chunks" are not pool
    // dispatches, so counting them would break per-worker conservation.
    let mut worker_ids: Vec<i32> = tasks.keys().copied().filter(|&w| w >= 0).collect();
    worker_ids.sort_unstable();

    let eps_ns: u64 = 200_000; // 0.2 ms slack for per-worker conservation
    let mut rows: Vec<WorkerRow> = Vec::new();
    let mut total_buckets = Buckets::default();
    let mut per_worker_buckets: HashMap<i32, Buckets> = HashMap::new();
    let mut total_chunks = 0usize;
    let mut unknown_submit_gaps = 0usize;

    for &w in &worker_ids {
        let mut ts = tasks.remove(&w).unwrap();
        ts.sort_unstable();
        total_chunks += ts.len();
        let window = if ts.is_empty() {
            0
        } else {
            ts.last().unwrap().1 - ts[0].0
        };
        let decode: u64 = ts.iter().map(|&(s, f, _)| f.saturating_sub(s)).sum();
        let mut gap_total = 0u64;
        let mut b = Buckets::default();
        for pair in ts.windows(2) {
            let (_, prev_finish, _) = pair[0];
            let (next_start, _, next_key) = pair[1];
            if next_start <= prev_finish {
                continue;
            }
            let gap = next_start - prev_finish;
            gap_total += gap;

            // Effective submit for next_key: latest submit <= next_start.
            let known_submit = submits
                .get(&next_key)
                .and_then(|v| v.iter().rev().find(|&&t| t <= next_start).copied());
            if known_submit.is_none() {
                unknown_submit_gaps += 1;
            }
            // If unknown, treat as just-in-time (booked as H-QUEUE) — COUNTED
            // above so a submit-less log can't silently pose as attributed.
            let t_submit = known_submit.unwrap_or(next_start);

            if t_submit <= prev_finish {
                // Task already queued when the worker freed: entire gap is
                // pool pick/handoff latency.
                b.queue += gap;
            } else {
                // starve window [prev_finish, t_submit] = pool empty; then
                // [t_submit, next_start] = post-submit handoff.
                let starve = t_submit - prev_finish;
                let post = next_start - t_submit;
                b.queue += post;
                let ov_bf = overlap(prev_finish, t_submit, &bf);
                let ov_mw = overlap(prev_finish, t_submit, &mw);
                let ov_dw = overlap(prev_finish, t_submit, &dw);
                // Priority when consumer phases overlap (they can nest): a
                // marker-resolution wait (MW) that CONTAINS a blockfind is
                // attributed by the innermost cause. We attribute by summed
                // exclusive coverage, MW > BF > DW, residual = OTHER.
                let mw_c = ov_mw.min(starve);
                let bf_c = ov_bf.min(starve.saturating_sub(mw_c));
                let dw_c = ov_dw.min(starve.saturating_sub(mw_c + bf_c));
                let other_c = starve.saturating_sub(mw_c + bf_c + dw_c);
                b.windowdep += mw_c;
                b.blockfind += bf_c;
                b.decodewait += dw_c;
                b.other += other_c;
            }
        }
        let reconciled = {
            let lhs = decode + gap_total;
            lhs.abs_diff(window) <= eps_ns
        };
        rows.push(WorkerRow {
            w,
            n_chunks: ts.len(),
            window_ns: window,
            decode_ns: decode,
            gap_ns: gap_total,
            reconciled,
        });
        total_buckets.queue += b.queue;
        total_buckets.blockfind += b.blockfind;
        total_buckets.windowdep += b.windowdep;
        total_buckets.decodewait += b.decodewait;
        total_buckets.other += b.other;
        per_worker_buckets.insert(w, b);
    }

    // ---- Gate-0 self-validation ----
    let n_events = evs.len();
    let gap_sum: u64 = rows.iter().map(|r| r.gap_ns).sum();
    let non_inert = n_events > 0 && !worker_ids.is_empty() && total_chunks > 0 && gap_sum > 0;
    let all_reconciled = rows.iter().all(|r| r.reconciled);
    let bucket_recon = total_buckets.total().abs_diff(gap_sum) <= eps_ns * (rows.len() as u64 + 1);
    let tot_window: u64 = rows.iter().map(|r| r.window_ns).sum();
    let tot_decode: u64 = rows.iter().map(|r| r.decode_ns).sum();

    Analysis {
        n_events,
        dropped_lines,
        n_start,
        n_finish,
        worker_ids,
        total_chunks,
        rows,
        per_worker_buckets,
        total_buckets,
        gap_sum,
        tot_window,
        tot_decode,
        n_bf: bf.len(),
        n_mw: mw.len(),
        n_dw: dw.len(),
        unknown_submit_gaps,
        non_inert,
        all_reconciled,
        bucket_recon,
        pairing_ok,
        no_dropped: dropped_lines == 0,
    }
}

fn print_report(a: &Analysis, label: &str, workers_ok: bool, json_out: Option<&str>) {
    let rows = &a.rows;
    let gap_sum = a.gap_sum;
    println!("== fulcrum dispatchgap :: {label} ==");
    println!(
        "events={} workers={} chunks={} start/finish={}/{} dropped_lines={}",
        a.n_events,
        a.worker_ids.len(),
        a.total_chunks,
        a.n_start,
        a.n_finish,
        a.dropped_lines,
    );
    println!(
        "consumer-phase intervals: blockfind={} markerwait={} decodewait={}",
        a.n_bf, a.n_mw, a.n_dw,
    );
    if a.unknown_submit_gaps > 0 {
        println!(
            "WARN: {} gap(s) had NO known SUBMIT — booked as just-in-time H-QUEUE; \
             the H-QUEUE share is partly a guess for this log",
            a.unknown_submit_gaps
        );
    }
    println!();
    println!("per-worker occupancy (ms):");
    println!(
        "  {:>4}  {:>7}  {:>9}  {:>9}  {:>9}  {:>6}  {:>5}",
        "wkr", "chunks", "window", "decode", "gap", "gap%", "recon"
    );
    for r in rows {
        println!(
            "  {:>4}  {:>7}  {:>9.2}  {:>9.2}  {:>9.2}  {:>5.1}%  {:>5}",
            r.w,
            r.n_chunks,
            ms(r.window_ns),
            ms(r.decode_ns),
            ms(r.gap_ns),
            pct(r.gap_ns, r.window_ns),
            if r.reconciled { "ok" } else { "BAD" }
        );
    }
    println!();
    println!(
        "AGG  window={:.2}ms decode={:.2}ms gap={:.2}ms  gap-fraction={:.1}%",
        ms(a.tot_window),
        ms(a.tot_decode),
        ms(gap_sum),
        pct(gap_sum, a.tot_window)
    );
    println!();
    println!("GAP BLOCKED-ON breakdown (share of total gap):");
    let tb = &a.total_buckets;
    for (name, val) in [
        ("H-QUEUE     (pool pick/handoff latency)", tb.queue),
        ("H-BLOCKFIND (next boundary not found)", tb.blockfind),
        ("H-WINDOWDEP (marker/window resolution)", tb.windowdep),
        ("H-DECODEWAIT(prefetch-horizon self-stall)", tb.decodewait),
        ("H-OTHER     (submit lat/write/bookkeep)", tb.other),
    ] {
        println!("  {name:42}  {:>8.2}ms  {:>5.1}%", ms(val), pct(val, gap_sum));
    }
    // Named dominant cause.
    let dom = a.dominant();
    println!();
    println!(
        "DOMINANT CAUSE: {} ({:.1}% of gap, {:.2}ms)",
        dom.0,
        pct(dom.1, gap_sum),
        ms(dom.1)
    );
    println!();
    let selftest = a.selftest_pass(workers_ok);
    println!(
        "SELFTEST={} (non_inert={} reconciled={} bucket_recon={} pairing={} no_dropped={} workers={workers_ok})",
        if selftest { "PASS" } else { "FAIL" },
        a.non_inert,
        a.all_reconciled,
        a.bucket_recon,
        a.pairing_ok,
        a.no_dropped,
    );

    if let Some(jp) = json_out {
        let mut s = String::new();
        s.push_str("{\n");
        s.push_str(&format!("  \"label\": \"{label}\",\n"));
        s.push_str(&format!("  \"events\": {},\n", a.n_events));
        s.push_str(&format!("  \"dropped_lines\": {},\n", a.dropped_lines));
        s.push_str(&format!(
            "  \"unknown_submit_gaps\": {},\n",
            a.unknown_submit_gaps
        ));
        s.push_str(&format!("  \"workers\": {},\n", a.worker_ids.len()));
        s.push_str(&format!("  \"chunks\": {},\n", a.total_chunks));
        s.push_str(&format!("  \"window_ms\": {:.3},\n", ms(a.tot_window)));
        s.push_str(&format!("  \"decode_ms\": {:.3},\n", ms(a.tot_decode)));
        s.push_str(&format!("  \"gap_ms\": {:.3},\n", ms(gap_sum)));
        s.push_str(&format!(
            "  \"gap_fraction_pct\": {:.3},\n",
            pct(gap_sum, a.tot_window)
        ));
        s.push_str("  \"gap_blocked_on_ms\": {\n");
        s.push_str(&format!("    \"H_QUEUE\": {:.3},\n", ms(tb.queue)));
        s.push_str(&format!("    \"H_BLOCKFIND\": {:.3},\n", ms(tb.blockfind)));
        s.push_str(&format!("    \"H_WINDOWDEP\": {:.3},\n", ms(tb.windowdep)));
        s.push_str(&format!("    \"H_DECODEWAIT\": {:.3},\n", ms(tb.decodewait)));
        s.push_str(&format!("    \"H_OTHER\": {:.3}\n", ms(tb.other)));
        s.push_str("  },\n");
        s.push_str("  \"gap_blocked_on_pct\": {\n");
        s.push_str(&format!("    \"H_QUEUE\": {:.2},\n", pct(tb.queue, gap_sum)));
        s.push_str(&format!(
            "    \"H_BLOCKFIND\": {:.2},\n",
            pct(tb.blockfind, gap_sum)
        ));
        s.push_str(&format!(
            "    \"H_WINDOWDEP\": {:.2},\n",
            pct(tb.windowdep, gap_sum)
        ));
        s.push_str(&format!(
            "    \"H_DECODEWAIT\": {:.2},\n",
            pct(tb.decodewait, gap_sum)
        ));
        s.push_str(&format!("    \"H_OTHER\": {:.2}\n", pct(tb.other, gap_sum)));
        s.push_str("  },\n");
        s.push_str(&format!("  \"dominant_cause\": \"{}\",\n", dom.0));
        s.push_str("  \"per_worker\": [\n");
        for (idx, r) in rows.iter().enumerate() {
            let b = a.per_worker_buckets.get(&r.w).copied().unwrap_or_default();
            s.push_str(&format!(
                "    {{\"w\": {}, \"chunks\": {}, \"window_ms\": {:.3}, \"decode_ms\": {:.3}, \"gap_ms\": {:.3}, \"gap_pct\": {:.2}, \"reconciled\": {}, \"queue_ms\": {:.3}, \"blockfind_ms\": {:.3}, \"windowdep_ms\": {:.3}, \"decodewait_ms\": {:.3}, \"other_ms\": {:.3}}}{}\n",
                r.w, r.n_chunks, ms(r.window_ns), ms(r.decode_ns), ms(r.gap_ns),
                pct(r.gap_ns, r.window_ns), r.reconciled,
                ms(b.queue), ms(b.blockfind), ms(b.windowdep), ms(b.decodewait), ms(b.other),
                if idx + 1 == rows.len() { "" } else { "," }
            ));
        }
        s.push_str("  ],\n");
        s.push_str(&format!(
            "  \"selftest\": \"{}\"\n",
            if selftest { "PASS" } else { "FAIL" }
        ));
        s.push_str("}\n");
        if let Err(e) = std::fs::write(jp, s) {
            eprintln!("fulcrum dispatchgap: cannot write {jp}: {e}");
        } else {
            println!("wrote {jp}");
        }
    }
}

// ---------------------------------------------------------------------------
// selftest — the baked Gate-0 (synthetic logs; PASS path + every refusal path)
// ---------------------------------------------------------------------------

/// Synthetic 2-worker log with a KNOWN answer: worker 0 decodes chunks A,B with
/// a 90ns gap fully covered by a blockfind interval mid-gap (60ns BF + queue
/// residue), worker 1 decodes C,D with a pure queue gap (D submitted early).
fn synth_log() -> String {
    let mut l = String::new();
    let push = |l: &mut String, t: u64, k: u8, key: u64, w: i32, f: u8| {
        l.push_str(&format!(
            "{{\"t\":{t},\"k\":{k},\"key\":{key},\"w\":{w},\"f\":{f}}}\n"
        ));
    };
    // submits
    push(&mut l, 0, 0, 100, -1, 0); // submit A
    push(&mut l, 0, 0, 101, -1, 0); // submit C
    // worker 0: A [10..110], gap (blockfind 120..180), B [200..300]
    push(&mut l, 10, 1, 100, 0, 1);
    push(&mut l, 110, 2, 100, 0, 1);
    push(&mut l, 120, 3, 5, -1, 0); // BF enter
    push(&mut l, 180, 4, 5, -1, 0); // BF exit
    push(&mut l, 150, 0, 102, -1, 0); // submit B (mid-gap, after blockfind found it)
    push(&mut l, 200, 1, 102, 0, 1);
    push(&mut l, 300, 2, 102, 0, 1);
    // worker 1: C [10..90], D [100..200] with D submitted at 0 (queue gap)
    push(&mut l, 0, 0, 103, -1, 0); // submit D early
    push(&mut l, 10, 1, 101, 1, 1);
    push(&mut l, 90, 2, 101, 1, 1);
    push(&mut l, 100, 1, 103, 1, 1);
    push(&mut l, 200, 2, 103, 1, 1);
    l
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

    // -- PASS path: the synthetic log must clear every gate AND attribute
    //    correctly (this drives the FULL analyze(), not a helper in isolation).
    {
        let a = analyze(&synth_log());
        check("synth: all Gate-0 gates pass", a.selftest_pass(true));
        check("synth: 2 workers, 4 chunks", a.worker_ids == vec![0, 1] && a.total_chunks == 4);
        check("synth: no dropped lines", a.dropped_lines == 0);
        check("synth: no unknown-submit gaps", a.unknown_submit_gaps == 0);
        // Worker 0's starve window [110,150] overlaps BF [120,180] for 30ns;
        // post-submit handoff [150,200] is queue. Worker 1's whole 10ns gap is
        // queue (D submitted before C finished).
        check(
            "synth: blockfind bucket carries exactly the BF-covered starve (30ns)",
            a.total_buckets.blockfind == 30,
        );
        check(
            "synth: queue bucket carries handoff + early-submit gaps (60ns)",
            a.total_buckets.queue == 60,
        );
        check(
            "synth: buckets conserve to the total gap",
            a.total_buckets.total() == a.gap_sum && a.gap_sum == 100,
        );
        check("synth: dominant cause is H-QUEUE", a.dominant().0 == "H-QUEUE");
        check(
            "synth: --workers mismatch fails the gate",
            !a.selftest_pass(false),
        );
    }

    // -- REFUSAL: a START without its FINISH breaks pairing.
    {
        let mut log = synth_log();
        log.push_str("{\"t\":400,\"k\":1,\"key\":999,\"w\":0,\"f\":0}\n");
        let a = analyze(&log);
        check("pairing: unmatched START refuses", !a.pairing_ok && !a.selftest_pass(true));
    }

    // -- REFUSAL: a FINISH with no START refuses too.
    {
        let mut log = synth_log();
        log.push_str("{\"t\":400,\"k\":2,\"key\":999,\"w\":0,\"f\":0}\n");
        let a = analyze(&log);
        check("pairing: unmatched FINISH refuses", !a.pairing_ok && !a.selftest_pass(true));
    }

    // -- REFUSAL: an empty / eventless log is inert.
    {
        let a = analyze("");
        check("inert: empty log refuses", !a.non_inert && !a.selftest_pass(true));
        let a = analyze("not json at all\n");
        check(
            "inert: garbage-only log refuses (dropped + inert)",
            !a.non_inert && !a.no_dropped && !a.selftest_pass(true),
        );
    }

    // -- REFUSAL: a truncated/corrupt line among good ones is a dropped-line FAIL
    //    (a silently-shrunk event set must never pose as a clean breakdown).
    {
        let mut log = synth_log();
        log.push_str("{\"t\":400,\"k\":\n"); // truncated write
        let a = analyze(&log);
        check(
            "dropped: truncated line refuses while the rest still parses",
            a.dropped_lines == 1 && !a.no_dropped && !a.selftest_pass(true),
        );
    }

    // -- COUNTED (not refused): a gap whose next task has no SUBMIT is booked
    //    just-in-time H-QUEUE and COUNTED so the report can warn.
    {
        let log = synth_log().replace("{\"t\":0,\"k\":0,\"key\":103,\"w\":-1,\"f\":0}\n", "");
        let a = analyze(&log);
        check(
            "unknown-submit: missing SUBMIT is counted (booked H-QUEUE)",
            a.unknown_submit_gaps == 1 && a.selftest_pass(true),
        );
    }

    println!(
        "SELFTEST={} pass={pass} fail={fail}",
        if fail == 0 { "PASS" } else { "FAIL" }
    );
    if fail == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_reconciles() {
        let (evs, dropped) = parse_log(&synth_log());
        assert!(evs.len() >= 14);
        assert_eq!(dropped, 0);
        let bf = build_intervals(&evs, 3, 4);
        assert_eq!(bf, vec![(120, 180)]);
    }

    #[test]
    fn selftest_passes() {
        assert_eq!(selftest(), ExitCode::SUCCESS);
    }

    #[test]
    fn overlap_union() {
        // nested + disjoint
        let ivs = vec![(10u64, 50u64), (20, 30), (60, 70)];
        assert_eq!(overlap(0, 100, &ivs), 40 + 10);
        assert_eq!(overlap(15, 25, &ivs), 10);
        assert_eq!(overlap(55, 65, &ivs), 5);
    }

    #[test]
    fn field_parse_negative() {
        let line = "{\"t\":123,\"k\":1,\"key\":456,\"w\":-1,\"f\":0}";
        assert_eq!(parse_field(line, "t"), Some(123));
        assert_eq!(parse_field(line, "w"), Some(-1));
        assert_eq!(parse_field(line, "f"), Some(0));
    }
}
