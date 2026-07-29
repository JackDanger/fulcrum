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
            match reg.iter().find(|(n, _)| n.split_whitespace().next() == Some(one) || *n == one) {
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

fn run_all() -> ExitCode {
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
