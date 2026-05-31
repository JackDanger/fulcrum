#![allow(dead_code)]
// Struct fields are part of the embeddable API surface (used by programmatic
// callers and kept for completeness); not all are exercised by the CLI path.

//! Chrome-trace JSON ingestion + B/E span pairing.
//!
//! Consumes a timeline in the Chrome-trace "JSON array format": a stream of
//! `{"name","ph","ts","pid","tid","args"}` objects, where `ph` is one of
//! `B`(egin), `E`(nd), or `i`(nstant). The loader tolerates a partial array
//! (a trailing comma, or no closing `]`) so a timeline that was being
//! streamed and cut short still parses — the same forgiving handling a
//! line-by-line trace writer needs.
//!
//! The bundled [`probe`](crate::probe) module emits exactly this format when
//! `FULCRUM_TRACE=/path.json` is set, but any producer of Chrome-trace JSON
//! works (e.g. a Chromium `chrome://tracing` capture, or your own emitter).
//!
//! Pairing reconstructs, per `(pid, tid)`, the begin/end nesting into spans
//! with a duration, a parent name (the enclosing open `B`), and the `args`
//! object (which carries correlation keys like `chunk_id` that the
//! critical-path layer joins on).

use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

/// One raw Chrome-trace event.
#[derive(Debug, Deserialize)]
pub struct Event {
    pub name: String,
    pub ph: String,
    #[serde(default)]
    pub ts: f64,
    #[serde(default)]
    pub pid: u64,
    #[serde(default)]
    pub tid: u64,
    #[serde(default)]
    pub args: serde_json::Value,
}

/// A paired span: a begin matched to its end on the same thread.
#[derive(Debug, Clone)]
pub struct Span {
    pub name: String,
    pub parent: String,
    pub pid: u64,
    pub tid: u64,
    pub ts_start: f64,
    pub ts_end: f64,
    /// Duration in microseconds (fractional µs = nanosecond precision).
    pub dur: f64,
    pub args: serde_json::Value,
}

impl Span {
    /// Read an integer arg (e.g. a `chunk_id` correlation key). Accepts the
    /// value being a JSON number or a numeric string.
    pub fn arg_u64(&self, key: &str) -> Option<u64> {
        match self.args.get(key) {
            Some(serde_json::Value::Number(n)) => n.as_u64(),
            Some(serde_json::Value::String(s)) => s.parse().ok(),
            _ => None,
        }
    }

    /// True for the "this thread is blocked on another" span categories —
    /// the wait edges the critical-path layer attributes idle time across.
    /// The convention is that wait spans are named with a `wait.` prefix or a
    /// `.wait` suffix; a few common explicit names are also recognized.
    pub fn is_wait(&self) -> bool {
        self.name.starts_with("wait.")
            || self.name.ends_with(".wait")
            || self.name == "lock.wait"
            || self.name == "pool.pick.wait"
            || self.name == "consumer.wait"
            // A blocking receive on a channel/future is a wait even when its
            // name doesn't follow the wait.* convention — the consumer sits
            // idle here until a producer delivers. Recognized explicitly so a
            // pipeline whose dominant stall is a `recv`/`rx_recv` block is
            // attributed to its producer, not miscounted as consumer busy-work.
            || self.name.contains("rx_recv")
            || self.name.ends_with(".recv")
            || self.name.ends_with("_recv_block")
    }
}

/// Load + repair + parse a Chrome-trace JSON file.
pub fn load_events(path: &Path) -> std::io::Result<Vec<Event>> {
    let mut s = std::fs::read_to_string(path)?;
    let trimmed = s.trim_end();
    s = trimmed.to_string();
    if s.starts_with('[') && !s.ends_with(']') {
        // strip trailing comma/newline, close the array
        while s.ends_with(',') || s.ends_with('\n') {
            s.pop();
        }
        s.push('\n');
        s.push(']');
    } else if s.ends_with(',') {
        while s.ends_with(',') || s.ends_with('\n') {
            s.pop();
        }
        if !s.ends_with(']') {
            s.push(']');
        }
    }
    if !s.starts_with('[') {
        s.insert(0, '[');
    }
    let events: Vec<Event> = serde_json::from_str(&s).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("trace parse {}: {e}", path.display()),
        )
    })?;
    Ok(events)
}

/// Pair B/E events into spans with parent nesting. Mismatched ends are
/// dropped (best-effort).
pub fn pair_spans(events: &[Event]) -> Vec<Span> {
    let mut stacks: HashMap<(u64, u64), Vec<&Event>> = HashMap::new();
    let mut spans = Vec::new();
    for e in events {
        match e.ph.as_str() {
            "B" => stacks.entry((e.pid, e.tid)).or_default().push(e),
            "E" => {
                let key = (e.pid, e.tid);
                if let Some(stack) = stacks.get_mut(&key) {
                    if let Some(b) = stack.pop() {
                        let parent = stack
                            .last()
                            .map(|p| p.name.clone())
                            .unwrap_or_else(|| "<root>".to_string());
                        spans.push(Span {
                            name: b.name.clone(),
                            parent,
                            pid: b.pid,
                            tid: b.tid,
                            ts_start: b.ts,
                            ts_end: e.ts,
                            dur: e.ts - b.ts,
                            args: b.args.clone(),
                        });
                    }
                }
            }
            _ => {}
        }
    }
    spans
}

/// Instant events (`ph == "i"`), e.g. point markers.
pub fn instant_events(events: &[Event]) -> Vec<&Event> {
    events.iter().filter(|e| e.ph == "i").collect()
}

/// Overall wall of the trace (max end − min start across all spans), µs.
pub fn wall_us(spans: &[Span]) -> f64 {
    if spans.is_empty() {
        return 0.0;
    }
    let min = spans
        .iter()
        .map(|s| s.ts_start)
        .fold(f64::INFINITY, f64::min);
    let max = spans
        .iter()
        .map(|s| s.ts_end)
        .fold(f64::NEG_INFINITY, f64::max);
    max - min
}

/// Format µs in human units (ns / µs / ms / s).
pub fn fmt_us(us: f64) -> String {
    if us >= 1_000_000.0 {
        format!("{:.3}s", us / 1_000_000.0)
    } else if us >= 1000.0 {
        format!("{:.2}ms", us / 1000.0)
    } else if us >= 1.0 {
        format!("{:.2}us", us)
    } else {
        format!("{:.0}ns", us * 1000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span_named(name: &str) -> Span {
        Span {
            name: name.to_string(),
            parent: String::new(),
            pid: 1,
            tid: 1,
            ts_start: 0.0,
            ts_end: 1.0,
            dur: 1.0,
            args: serde_json::Value::Null,
        }
    }

    #[test]
    fn is_wait_recognizes_conventional_and_recv_names() {
        // Conventional wait.* / *.wait names.
        assert!(span_named("wait.block_fetcher_get").is_wait());
        assert!(span_named("pool.pick.wait").is_wait());
        assert!(span_named("consumer.wait").is_wait());
        // Blocking receives that don't follow the convention (the gzippy
        // dominant stall) must still be recognized as waits, else they are
        // miscounted as consumer busy-work and hide what gates the wall.
        assert!(span_named("ttp.rx_recv_block").is_wait());
        assert!(span_named("future.recv").is_wait());
        assert!(span_named("chan_recv_block").is_wait());
        // Real work spans are NOT waits.
        assert!(!span_named("worker.bootstrap").is_wait());
        assert!(!span_named("worker.isal_stream_inflate").is_wait());
        assert!(!span_named("consumer.write_data").is_wait());
    }
}
