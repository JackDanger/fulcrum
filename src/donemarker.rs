//! `--done-marker` — a machine-readable `EXIT:<code>` final line for external
//! monitors.
//!
//! Background jobs in the gzippy campaign signal completion by appending
//! `EXIT:<code>` to their log; monitors tail the log and key off that line.
//! Before this module each long-running invocation (`try`, `board wall`,
//! `layout calibrate`, …) had to be wrapped in shell (`cmd; echo EXIT:$?`),
//! and a wrapper that someone forgot — or that a panic skipped — left the
//! monitor waiting forever on a job that was already dead.
//!
//! The flag is UNIFORM AND CENTRAL: `main` strips `--done-marker` from the
//! argv before any command parses it, so EVERY subcommand accepts it and no
//! per-command flag plumbing can drift. When present, a scope guard
//! ([`DoneMarker`]) is armed before dispatch and prints exactly one
//!
//!   EXIT:<code>
//!
//! line to stdout at process end — on success, on failure, and ON PANIC: the
//! guard's default code is 101 (the process exit code of a Rust panic) and is
//! only overwritten by [`DoneMarker::finish`] on the orderly return path, so
//! an unwind that never reaches `finish` still emits `EXIT:101` as the guard
//! drops. (The release profile keeps the default unwind panic strategy; with
//! `panic = "abort"` no in-process guard could fire, and this one would go
//! silent rather than lie.)
//!
//! Opt-in: without the flag, not a byte of output changes.

use std::process::ExitCode;

pub const FLAG: &str = "--done-marker";

/// What a Rust panic exits the process with — the guard's default, emitted
/// whenever the orderly path never ran.
pub const PANIC_CODE: u8 = 101;

/// Remove every occurrence of `--done-marker` from the argv; report whether it
/// was present. Central stripping is what makes the flag uniform: no command
/// parser ever sees it, so none can reject it and none can forget it.
pub fn strip_flag(args: Vec<String>) -> (Vec<String>, bool) {
    let present = args.iter().any(|a| a == FLAG);
    (args.into_iter().filter(|a| a != FLAG).collect(), present)
}

/// Recover the numeric code from a `std::process::ExitCode`, which is opaque
/// by design: probe equality against every constructible value (0..=255 —
/// the whole exit-code domain on the platforms this runs on). O(256) equality
/// checks once per process; honest, total, and requires no unstable API.
pub fn exit_code_value(code: ExitCode) -> u8 {
    (0u8..=255).find(|&n| ExitCode::from(n) == code).unwrap_or(1)
}

/// The scope guard. Arm it before dispatch; `finish` it with the real exit
/// code on the orderly path. Printing happens in `Drop`, so the panic path
/// (guard dropped mid-unwind, `finish` never called) emits `EXIT:101`.
pub struct DoneMarker {
    code: u8,
}

impl DoneMarker {
    pub fn arm() -> Self {
        DoneMarker { code: PANIC_CODE }
    }

    /// Record the orderly exit code; the `EXIT:` line prints as `self` drops
    /// (immediately, since this consumes the guard).
    pub fn finish(mut self, code: ExitCode) {
        self.code = exit_code_value(code);
    }
}

impl Drop for DoneMarker {
    fn drop(&mut self) {
        use std::io::Write;
        let mut out = std::io::stdout();
        let _ = writeln!(out, "EXIT:{}", self.code);
        let _ = out.flush();
    }
}

// ---------------------------------------------------------------------------
// Gate-0 — proves the marker fires on success, on failure, and on panic, by
// running THIS binary (the shipped dispatch path, not a re-implementation).
// ---------------------------------------------------------------------------

pub fn selftest() -> ExitCode {
    let pass = std::cell::Cell::new(0u32);
    let fail = std::cell::Cell::new(0u32);
    let check = |name: &str, ok: bool| {
        if ok {
            pass.set(pass.get() + 1);
            println!("  PASS {name}");
        } else {
            fail.set(fail.get() + 1);
            println!("  FAIL {name}");
        }
    };

    // -- pure pieces ----------------------------------------------------------
    check(
        "strip_flag: removes the flag and preserves everything else",
        strip_flag(vec!["try".into(), FLAG.into(), "--n".into(), "9".into()])
            == (vec!["try".to_string(), "--n".to_string(), "9".to_string()], true),
    );
    check(
        "strip_flag: absent flag reported absent, argv untouched",
        strip_flag(vec!["version".into()]) == (vec!["version".to_string()], false),
    );
    check(
        "exit_code_value: roundtrips 0, 1, 2, 101, 255",
        [0u8, 1, 2, PANIC_CODE, 255]
            .into_iter()
            .all(|n| exit_code_value(ExitCode::from(n)) == n),
    );

    // -- end-to-end through the real binary ----------------------------------
    let Ok(exe) = std::env::current_exe() else {
        println!("  FAIL exec: cannot locate own binary — end-to-end checks did not run");
        return ExitCode::FAILURE;
    };
    let run = |args: &[&str], panic_env: bool| -> Option<(Vec<String>, i32)> {
        let mut c = std::process::Command::new(&exe);
        c.args(args)
            .env("FULCRUM_IN_SELFTEST", "1")
            .env("FULCRUM_SELFUPDATED", "1");
        if panic_env {
            c.env("FULCRUM_DONEMARKER_PANIC", "1");
        }
        let out = c.output().ok()?;
        let lines: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|l| l.to_string())
            .collect();
        Some((lines, out.status.code().unwrap_or(-1)))
    };
    let last_line = |lines: &[String]| -> String {
        lines
            .iter()
            .rev()
            .find(|l| !l.trim().is_empty())
            .cloned()
            .unwrap_or_default()
    };

    // success: `commands` exits 0 with no network, no measurement.
    match run(&["commands", FLAG], false) {
        None => check("success path: subprocess ran", false),
        Some((lines, code)) => {
            check("success path: process exits 0", code == 0);
            check(
                "success path: LAST stdout line is EXIT:0",
                last_line(&lines) == "EXIT:0",
            );
        }
    }

    // failure: an unknown subcommand exits nonzero; the marker must carry
    // that same code, not 0 and not silence.
    match run(&["definitely-not-a-fulcrum-command", FLAG], false) {
        None => check("failure path: subprocess ran", false),
        Some((lines, code)) => {
            check("failure path: process exits nonzero", code != 0);
            check(
                "failure path: LAST stdout line is EXIT:<that same code>",
                code > 0 && last_line(&lines) == format!("EXIT:{code}"),
            );
        }
    }

    // panic: the induced-panic hook unwinds out of dispatch; the scope guard
    // must still print, with the panic code.
    match run(&["commands", FLAG], true) {
        None => check("panic path: subprocess ran", false),
        Some((lines, code)) => {
            check(
                "panic path: process exits 101 (the panic actually fired)",
                code == i32::from(PANIC_CODE),
            );
            check(
                "panic path: EXIT:101 still printed by the scope guard",
                last_line(&lines) == format!("EXIT:{PANIC_CODE}"),
            );
        }
    }

    // opt-in: without the flag, no EXIT: line appears anywhere.
    match run(&["commands"], false) {
        None => check("opt-in: subprocess ran", false),
        Some((lines, _)) => check(
            "opt-in: WITHOUT the flag no EXIT: line is emitted",
            !lines.iter().any(|l| l.starts_with("EXIT:")),
        ),
    }

    println!(
        "DONEMARKER_SELFTEST={} pass={} fail={}",
        if fail.get() == 0 { "PASS" } else { "FAIL" },
        pass.get(),
        fail.get()
    );
    if fail.get() == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_is_total() {
        let (args, present) = strip_flag(vec![FLAG.into(), FLAG.into()]);
        assert!(present);
        assert!(args.is_empty());
    }

    #[test]
    fn exit_code_probe() {
        assert_eq!(exit_code_value(ExitCode::SUCCESS), 0);
        assert_eq!(exit_code_value(ExitCode::FAILURE), 1);
        assert_eq!(exit_code_value(ExitCode::from(2)), 2);
    }
}
