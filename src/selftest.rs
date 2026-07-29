//! `fulcrum selftest` — run EVERY Gate-0 in one command.
//!
//! A Gate-0 is a command's baked self-test: it proves the instrument's own
//! refusal paths fire (a VOID can never score as a win, a stale control is
//! refused, an A/A bias voids the run) before any measurement is trusted.
//! The instrument set only counts as deployed when this passes on the box
//! that will measure — `docs/deployment.md` makes it part of the deploy
//! step, because a binary that ships without its Gate-0s passing is exactly
//! how a weaker hand-rolled substitute ends up trusted instead.
//!
//! `fulcrum selftest invariants` renders the enforced-rule registry
//! (`invariants.rs`).

use std::process::ExitCode;

/// Every Gate-0 reachable from the new surface, by the command that owns it.
type Gate0 = fn() -> ExitCode;

fn registry() -> Vec<(&'static str, Gate0)> {
    vec![
        ("freeze", crate::freeze::selftest as Gate0),
        ("verify", crate::verify::selftest),
        ("dropin", crate::dropin::selftest),
        ("board", crate::board::selftest),
        ("board size (sizecensus)", crate::sizecensus::selftest),
        ("board wall (wallcensus)", crate::wallcensus::selftest),
        ("goal", crate::goal::selftest),
        ("ab paired", crate::paired::selftest),
        ("ab matrix", crate::matrix::selftest),
        ("ab ablate", crate::ablate::selftest),
        ("ab bisect", crate::bisect::selftest),
        ("why", crate::why::selftest),
        ("candidates", crate::candidates::selftest),
        ("try", crate::promote::selftest),
        ("profile uarch", crate::uarch::selftest),
        ("profile rss (memprofile)", crate::memprofile::selftest),
        ("trace dispatchgap", crate::dispatchgap::selftest),
        ("anatomy ratio", crate::ratio::selftest::run),
        ("anatomy explain", crate::explain::selftest),
        ("lib levelsweep", crate::levelsweep::selftest),
        ("lib cpreflight", crate::cpreflight::selftest),
        ("lib behavior", crate::behavior::selftest),
    ]
}

pub fn cmd(args: &[String]) -> ExitCode {
    match args.first().map(|s| s.as_str()) {
        Some("invariants") => {
            println!("{}", crate::invariants::render());
            ExitCode::SUCCESS
        }
        Some("--list") => {
            for (name, _) in registry() {
                println!("{name}");
            }
            ExitCode::SUCCESS
        }
        Some(one) if !one.starts_with("--") => {
            let reg = registry();
            // Exact name first; only then the first-word convenience form. The
            // other order lets `board wall (wallcensus)` resolve to `board`.
            match reg
                .iter()
                .find(|(n, _)| *n == one)
                .or_else(|| reg.iter().find(|(n, _)| n.split_whitespace().next() == Some(one)))
            {
                Some((name, f)) => {
                    println!("== Gate-0: {name}");
                    f()
                }
                None => {
                    eprintln!(
                        "selftest: no Gate-0 named '{one}' (see `fulcrum selftest --list`)"
                    );
                    ExitCode::from(2)
                }
            }
        }
        _ => run_all(),
    }
}

/// In-process fallback for when the binary cannot locate itself. Retained only
/// for that path; `run_all` is the isolated one and is what normally executes.
fn run_all_in_process() -> ExitCode {
    let mut failed: Vec<&str> = Vec::new();
    let reg = registry();
    let total = reg.len();
    for (name, f) in reg {
        println!("\n== Gate-0: {name}");
        if f() != ExitCode::SUCCESS {
            failed.push(name);
        }
    }
    println!("\nselftest: {}/{} Gate-0s passed", total - failed.len(), total);
    if failed.is_empty() {
        ExitCode::SUCCESS
    } else {
        for f in &failed {
            println!("  FAILED: {f}");
        }
        ExitCode::FAILURE
    }
}

/// Run every Gate-0, each in a FRESH SUBPROCESS.
///
/// FALSIFY: do not "simplify" this back to calling `f()` in-process. Several
/// Gate-0s touch process-wide or on-disk state — the paired gate exercises the
/// freeze state file, the RSS gate spawns a memory hog — so running them in one
/// process lets an earlier gate contaminate a later one. Measured on solvency:
/// `ab paired` and `board wall` each print PASS with exit 0 when run alone, and
/// were both reported FAILED by the in-process aggregator. That false failure
/// made `make deploy` refuse to certify a box that was in fact correct, which
/// pushes the operator straight back to hand-rolled scripts — the exact failure
/// this harness exists to prevent. A slower, isolated suite is worth far more
/// than a fast one that lies.
fn run_all() -> ExitCode {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        // No self-path: fall back to in-process rather than skipping the suite,
        // and say so, because the results are then contamination-prone.
        Err(e) => {
            eprintln!("selftest: cannot locate own binary ({e}); running IN-PROCESS, results may be contaminated");
            return run_all_in_process();
        }
    };
    let mut failed: Vec<&str> = Vec::new();
    let reg = registry();
    let total = reg.len();
    for (name, _) in reg {
        println!("\n== Gate-0: {name}");
        let ok = std::process::Command::new(&exe)
            // The WHOLE name as ONE argument. Passing `name.split_whitespace()`
            // sends "board wall (wallcensus)" as three args, and the lookup below
            // matches on the FIRST word — which silently runs the plain `board`
            // gate and reports it as `board wall` passing. A false PASS in the
            // instrument that certifies every other measurement is the worst
            // possible defect here; it is strictly more dangerous than the false
            // FAIL this subprocess isolation was added to fix.
            .arg("selftest")
            .arg(name)
            .arg("--no-self-update")
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            failed.push(name);
        }
    }
    println!("\nselftest: {}/{} Gate-0s passed", total - failed.len(), total);
    if failed.is_empty() {
        ExitCode::SUCCESS
    } else {
        for f in &failed {
            println!("  FAILED: {f}");
        }
        ExitCode::FAILURE
    }
}
