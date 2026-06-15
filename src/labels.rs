//! labels.rs — shared leaf labels for the locate / report layers.
//!
//! WHY THIS EXISTS
//! ===============
//! `report.print_locate` (the renderer) and `locate.locate` (the analyzer)
//! both need the CONSERVATION-OR-NO-LOCATE *label* for a flagged result. In
//! the Python tree `report.py` imported `locate.flag_label` lazily, inside the
//! function body, purely to dodge an import cycle (`report → locate`, while the
//! pipeline pulls both). That lazy import is a code smell that papers over a
//! layering inversion.
//!
//! `flag_label` is a pure leaf: given a flagged-ness and the per-trace reasons,
//! it formats one banner string. It depends on nothing in `locate` or
//! `report`, so it lives here and BOTH layers can depend on it without a cycle.
//! `locate::LocateResult` implements [`Flagged`]; the (later) Rust `report`
//! renderer will call [`flag_label`] through the same trait.

/// The minimal surface [`flag_label`] needs from a locate result — the
/// flagged-ness and the per-trace flag reasons. Keeping the input abstract is
/// what makes this a true leaf: `labels` never names `locate`'s concrete
/// result type, so there is no `labels → locate` edge.
pub trait Flagged {
    /// Did the result trip a CONSERVATION-OR-NO-LOCATE flag on any trace?
    fn flagged(&self) -> bool;
    /// Per-trace flag reasons; `None` for a conserved (un-flagged) trace.
    fn flag_reasons(&self) -> Vec<Option<String>>;
}

/// The CONSERVATION-OR-NO-LOCATE label for a flagged result (rows are EMITTED
/// flagged, never refused and never silently trusted). Returns `None` for a
/// conserved result. Byte-for-byte the Python `locate.flag_label`:
/// `"FLAGGED [CONSERVATION-OR-NO-LOCATE] " + "; ".join(non-empty reasons)`.
pub fn flag_label<T: Flagged + ?Sized>(result: &T) -> Option<String> {
    if !result.flagged() {
        return None;
    }
    let reasons: Vec<String> = result
        .flag_reasons()
        .into_iter()
        .flatten()
        .filter(|r| !r.is_empty())
        .collect();
    Some(format!(
        "FLAGGED [CONSERVATION-OR-NO-LOCATE] {}",
        reasons.join("; ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeResult {
        flagged: bool,
        reasons: Vec<Option<String>>,
    }
    impl Flagged for FakeResult {
        fn flagged(&self) -> bool {
            self.flagged
        }
        fn flag_reasons(&self) -> Vec<Option<String>> {
            self.reasons.clone()
        }
    }

    #[test]
    fn conserved_result_has_no_label() {
        let r = FakeResult {
            flagged: false,
            reasons: vec![None],
        };
        assert_eq!(flag_label(&r), None);
    }

    #[test]
    fn flagged_label_names_invariant_and_joins_reasons() {
        let r = FakeResult {
            flagged: true,
            reasons: vec![Some("alpha".to_string()), None, Some("beta".to_string())],
        };
        let lbl = flag_label(&r).unwrap();
        assert_eq!(
            lbl, "FLAGGED [CONSERVATION-OR-NO-LOCATE] alpha; beta",
            "label names the invariant and joins only the present reasons"
        );
    }
}
