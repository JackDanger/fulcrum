//! `fulcrum supervise -- <cmd …>` — a supervisor that ALWAYS lands the
//! `EXIT:<code>` done-marker, even when the child is SIGKILLed.
//!
//! Receipt: an OOM SIGKILL looked like a hang for an hour. The in-process
//! `--done-marker` scope guard (donemarker.rs) fires on success, failure and
//! panic — but nothing in-process can fire on SIGKILL, because SIGKILL is
//! never delivered to the process's own code. The only marker that survives
//! the child's death is one printed by a DIFFERENT process. That is this
//! command: spawn the child, wait, and append exactly one
//!
//!   EXIT:<code>
//!
//! line to stdout — the child's exit code, or 128+signal when a signal killed
//! it (SIGKILL ⇒ EXIT:137), or 127 when the child could not be spawned at
//! all. The supervisor then exits with that same code, so shell callers see
//! the child's status unchanged.
//!
//! Monitors tail the log for `EXIT:` exactly as they do for `--done-marker`;
//! the marker vocabulary is shared on purpose. `scripts/supervise.sh` is the
//! bash equivalent for boxes whose fulcrum binary predates this subcommand.
//!
//! Everything after `--` is the child argv, verbatim: the dispatcher's argv
//! preprocessing (help interception, `--done-marker` stripping) stops at the
//! `--` boundary so a supervised child's own flags are payload, never parsed.

use std::process::ExitCode;

/// Exit code when the child cannot be spawned at all (the shell's own
/// convention for "command not found").
pub const SPAWN_FAILURE_CODE: i32 = 127;

/// The code a signal death maps to: 128 + signal number, the shell convention
/// (SIGKILL(9) ⇒ 137, SIGTERM(15) ⇒ 143).
pub fn signal_code(sig: i32) -> i32 {
    128 + sig
}

fn emit(code: i32) {
    use std::io::Write;
    let mut out = std::io::stdout();
    let _ = writeln!(out, "EXIT:{code}");
    let _ = out.flush();
}

/// Spawn and wait; map the outcome to a shell-convention exit code. Never
/// panics: every failure path is a code, because the whole point is that the
/// marker always lands.
fn run_child(argv: &[String]) -> i32 {
    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    match cmd.status() {
        Ok(st) => {
            if let Some(c) = st.code() {
                c
            } else {
                // No exit code means a signal death on unix.
                #[cfg(unix)]
                {
                    use std::os::unix::process::ExitStatusExt;
                    signal_code(st.signal().unwrap_or(0))
                }
                #[cfg(not(unix))]
                {
                    1
                }
            }
        }
        Err(e) => {
            eprintln!("supervise: cannot spawn '{}': {e}", argv[0]);
            SPAWN_FAILURE_CODE
        }
    }
}

pub fn cmd(args: &[String]) -> ExitCode {
    if args.first().map(|s| s.as_str()) == Some("selftest") {
        return selftest();
    }
    // Help only BEFORE the `--` boundary: after it, `--help` belongs to the
    // child.
    if args
        .iter()
        .take_while(|a| a.as_str() != "--")
        .any(|a| a == "--help" || a == "-h" || a == "help")
    {
        eprintln!("{}", usage());
        return ExitCode::SUCCESS;
    }
    let child: Vec<String> = if args.first().map(|s| s.as_str()) == Some("--") {
        args[1..].to_vec()
    } else {
        args.to_vec()
    };
    if child.is_empty() {
        eprintln!("{}", usage());
        // Even a refusal lands a marker: a monitor tailing the log must never
        // wait forever on a supervisor that mis-launched.
        emit(2);
        return ExitCode::from(2);
    }
    let code = run_child(&child);
    emit(code);
    // Mirror the child's status for shell callers. Out-of-range codes (never
    // produced by wait(2), but be total) collapse to 1, not 0: a supervisor
    // must not manufacture success.
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

fn usage() -> String {
    "fulcrum supervise -- <cmd …>\n\
     \n\
     Runs <cmd …> and ALWAYS appends a final `EXIT:<code>` line to stdout —\n\
     the child's exit code, 128+signal when a signal killed it (OOM SIGKILL\n\
     => EXIT:137), or 127 when it could not be spawned. The in-process\n\
     --done-marker cannot fire on SIGKILL; this out-of-process supervisor is\n\
     the marker that survives it. The supervisor exits with the same code,\n\
     so callers see the child's status unchanged.\n\
     \n\
     Example:\n\
     \x20 fulcrum supervise -- fulcrum try my-branch --repo ~/www/gzippy … \\\n\
     \x20     >> /tmp/wave-my-branch.log 2>&1\n"
        .to_string()
}

// ---------------------------------------------------------------------------
// Gate-0 — drives the real binary end to end, including the SIGKILL path.
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

    check("signal_code: SIGKILL(9) => 137", signal_code(9) == 137);
    check("signal_code: SIGTERM(15) => 143", signal_code(15) == 143);

    let Ok(exe) = std::env::current_exe() else {
        println!("  FAIL exec: cannot locate own binary — end-to-end checks did not run");
        return ExitCode::FAILURE;
    };
    let run = |args: &[&str]| -> Option<(Vec<String>, i32)> {
        let out = std::process::Command::new(&exe)
            .args(args)
            .env("FULCRUM_IN_SELFTEST", "1")
            .env("FULCRUM_SELFUPDATED", "1")
            .output()
            .ok()?;
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

    // Success: marker EXIT:0 and exit 0.
    match run(&["supervise", "--", "sh", "-c", "exit 0"]) {
        None => check("success: subprocess ran", false),
        Some((lines, code)) => {
            check("success: supervisor exits 0", code == 0);
            check("success: LAST stdout line is EXIT:0", last_line(&lines) == "EXIT:0");
        }
    }

    // Failure: the child's code is carried, after its own output.
    match run(&["supervise", "--", "sh", "-c", "echo child-out; exit 3"]) {
        None => check("failure: subprocess ran", false),
        Some((lines, code)) => {
            check("failure: supervisor exits with the child's code (3)", code == 3);
            check(
                "failure: marker EXIT:3 lands AFTER the child's own stdout",
                last_line(&lines) == "EXIT:3" && lines.iter().any(|l| l == "child-out"),
            );
        }
    }

    // THE reason this command exists: kill -9 the child; the marker must
    // still appear. An in-process guard cannot do this.
    match run(&["supervise", "--", "sh", "-c", "kill -9 $$"]) {
        None => check("SIGKILL: subprocess ran", false),
        Some((lines, code)) => {
            check(
                "SIGKILL: child killed -9 still lands the marker EXIT:137",
                last_line(&lines) == "EXIT:137",
            );
            check("SIGKILL: supervisor exits 137 (128+9)", code == 137);
        }
    }

    // Spawn failure: marker EXIT:127, never silence.
    match run(&["supervise", "--", "/nonexistent-fulcrum-supervise-child"]) {
        None => check("spawn-failure: subprocess ran", false),
        Some((lines, code)) => {
            check(
                "spawn-failure: unspawnable child lands EXIT:127",
                last_line(&lines) == "EXIT:127" && code == SPAWN_FAILURE_CODE,
            );
        }
    }

    // The `--` boundary protects the child argv from the dispatcher's argv
    // preprocessing: `--done-marker` after `--` is the child's payload (echo
    // prints it), and `--help` after `--` is executed, not answered.
    match run(&["supervise", "--", "echo", "--done-marker"]) {
        None => check("boundary: subprocess ran", false),
        Some((lines, _)) => check(
            "boundary: --done-marker after -- reaches the child verbatim (central strip stops at --)",
            lines.iter().any(|l| l == "--done-marker") && last_line(&lines) == "EXIT:0",
        ),
    }
    match run(&["supervise", "--", "echo", "--help"]) {
        None => check("boundary: subprocess ran", false),
        Some((lines, _)) => check(
            "boundary: --help after -- is the child's flag — supervise runs it instead of printing usage",
            lines.iter().any(|l| l == "--help") && last_line(&lines) == "EXIT:0",
        ),
    }

    // A refusal still lands a marker — the monitor never waits forever.
    match run(&["supervise", "--"]) {
        None => check("refusal: subprocess ran", false),
        Some((lines, code)) => check(
            "refusal: empty child argv refuses with EXIT:2, never silence",
            last_line(&lines) == "EXIT:2" && code == 2,
        ),
    }

    println!(
        "SUPERVISE_SELFTEST={} pass={} fail={}",
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
