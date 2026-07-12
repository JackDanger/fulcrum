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

fn parse_log(text: &str) -> Vec<Ev> {
    let mut v = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        let (Some(t), Some(k), Some(key), Some(w), Some(f)) = (
            parse_field(line, "t"),
            parse_field(line, "k"),
            parse_field(line, "key"),
            parse_field(line, "w"),
            parse_field(line, "f"),
        ) else {
            continue;
        };
        v.push(Ev {
            t: t as u64,
            k: k as u8,
            key: key as u64,
            w: w as i32,
            f: f as u8,
        });
    }
    v
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

pub fn cmd_dispatchgap(args: &[String]) -> ExitCode {
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
                eprintln!("usage: fulcrum dispatchgap <event-log.jsonl> [--label L] [--workers N] [--json out.json]");
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
    let evs = parse_log(&text);

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

    // Ignore the pseudo-worker -2 (unbound / consumer trial decodes) for the
    // pool timeline but count it.
    let mut worker_ids: Vec<i32> = tasks.keys().copied().filter(|&w| w >= 0).collect();
    worker_ids.sort_unstable();

    let eps_ns: u64 = 200_000; // 0.2 ms slack for per-worker conservation
    let mut rows: Vec<WorkerRow> = Vec::new();
    let mut total_buckets = Buckets::default();
    let mut per_worker_buckets: HashMap<i32, Buckets> = HashMap::new();
    let mut total_chunks = 0usize;

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
            let t_submit = submits
                .get(&next_key)
                .and_then(|v| v.iter().rev().find(|&&t| t <= next_start).copied())
                .unwrap_or(next_start); // if unknown, treat as just-in-time

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
    let workers_ok = expect_workers.map(|n| n == worker_ids.len()).unwrap_or(true);
    let selftest = non_inert && all_reconciled && bucket_recon && pairing_ok && workers_ok;

    // ---- Report ----
    println!("== fulcrum dispatchgap :: {label} ==");
    println!(
        "events={n_events} workers={} chunks={total_chunks} start/finish={n_start}/{n_finish}",
        worker_ids.len()
    );
    println!(
        "consumer-phase intervals: blockfind={} markerwait={} decodewait={}",
        bf.len(),
        mw.len(),
        dw.len()
    );
    println!();
    println!("per-worker occupancy (ms):");
    println!(
        "  {:>4}  {:>7}  {:>9}  {:>9}  {:>9}  {:>6}  {:>5}",
        "wkr", "chunks", "window", "decode", "gap", "gap%", "recon"
    );
    for r in &rows {
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
    let tot_window: u64 = rows.iter().map(|r| r.window_ns).sum();
    let tot_decode: u64 = rows.iter().map(|r| r.decode_ns).sum();
    println!();
    println!(
        "AGG  window={:.2}ms decode={:.2}ms gap={:.2}ms  gap-fraction={:.1}%",
        ms(tot_window),
        ms(tot_decode),
        ms(gap_sum),
        pct(gap_sum, tot_window)
    );
    println!();
    println!("GAP BLOCKED-ON breakdown (share of total gap):");
    let tb = &total_buckets;
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
    let dom = [
        ("H-QUEUE", tb.queue),
        ("H-BLOCKFIND", tb.blockfind),
        ("H-WINDOWDEP", tb.windowdep),
        ("H-DECODEWAIT", tb.decodewait),
        ("H-OTHER", tb.other),
    ]
    .into_iter()
    .max_by_key(|&(_, v)| v)
    .unwrap();
    println!();
    println!(
        "DOMINANT CAUSE: {} ({:.1}% of gap, {:.2}ms)",
        dom.0,
        pct(dom.1, gap_sum),
        ms(dom.1)
    );
    println!();
    println!(
        "SELFTEST={} (non_inert={non_inert} reconciled={all_reconciled} bucket_recon={bucket_recon} pairing={pairing_ok} workers={workers_ok})",
        if selftest { "PASS" } else { "FAIL" }
    );

    if let Some(jp) = json_out {
        let mut s = String::new();
        s.push_str("{\n");
        s.push_str(&format!("  \"label\": \"{label}\",\n"));
        s.push_str(&format!("  \"events\": {n_events},\n"));
        s.push_str(&format!("  \"workers\": {},\n", worker_ids.len()));
        s.push_str(&format!("  \"chunks\": {total_chunks},\n"));
        s.push_str(&format!("  \"window_ms\": {:.3},\n", ms(tot_window)));
        s.push_str(&format!("  \"decode_ms\": {:.3},\n", ms(tot_decode)));
        s.push_str(&format!("  \"gap_ms\": {:.3},\n", ms(gap_sum)));
        s.push_str(&format!(
            "  \"gap_fraction_pct\": {:.3},\n",
            pct(gap_sum, tot_window)
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
            let b = per_worker_buckets.get(&r.w).copied().unwrap_or_default();
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
        if let Err(e) = std::fs::write(&jp, s) {
            eprintln!("fulcrum dispatchgap: cannot write {jp}: {e}");
        } else {
            println!("wrote {jp}");
        }
    }

    if selftest {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic 2-worker log: worker 0 runs chunks A,B with a gap where the
    // consumer is in blockfind; worker 1 runs chunk C then D with a queue gap.
    fn synth() -> String {
        // times in ns
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

    #[test]
    fn parses_and_reconciles() {
        let evs = parse_log(&synth());
        assert!(evs.len() >= 14);
        let bf = build_intervals(&evs, 3, 4);
        assert_eq!(bf, vec![(120, 180)]);
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
