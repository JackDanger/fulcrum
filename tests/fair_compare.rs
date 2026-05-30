//! End-to-end trust test for the FAIR cross-tool comparison harness.
//!
//! This builds a CONTROLLED toy where the correct answer is known, then asserts
//! the harness enforces each anti-overclaim guarantee:
//!
//!   * a fast-but-WRONG tool is DISQUALIFIED, never a winner (hole #3);
//!   * an interpreter-wrapped (shebang) tool is FLAGGED + its startup measured
//!     (hole #1);
//!   * a claim that the wrong tool is "fastest" is audited FALSE (the validator
//!     refuses speed-over-wrong-bytes).
//!
//! It uses tiny POSIX shell/python shims as the "tools" so it needs only a
//! shell + python3 on PATH (skips gracefully if python3 is absent). All tool
//! names are GENERIC (tool-correct / tool-wrong / tool-python).

use fulcrum::audit::{self, Verdict};
use fulcrum::compare::{
    self, BinaryKind, Corpus, OutputMode, RunCfg, ThreadCell, ToolSpec,
};
use std::path::PathBuf;
use std::time::Duration;

/// Make an executable shim file with the given contents.
fn write_exec(dir: &std::path::Path, name: &str, body: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, body).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&p).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&p, perms).unwrap();
    }
    p
}

fn have(cmd: &str) -> bool {
    compare::resolve_in_path(cmd).is_some()
}

#[test]
fn fast_but_wrong_is_disqualified_and_python_is_flagged() {
    // Need a POSIX sh; skip on platforms without it.
    if !have("sh") {
        eprintln!("skipping: no `sh` on PATH");
        return;
    }
    let dir = std::env::temp_dir().join("fulcrum_fair_compare_test");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Reference payload + its correct digest.
    let payload = dir.join("payload.bin");
    let data: Vec<u8> = (0..50_000u32)
        .map(|i| i.wrapping_mul(2654435761) as u8)
        .collect();
    std::fs::write(&payload, &data).unwrap();
    let reference = compare::sha256(&data);

    // tool-correct: a native-ish shim that emits the bytes verbatim.
    let correct = write_exec(&dir, "decode_correct.sh", "#!/bin/sh\ncat \"$1\"\n");
    // tool-wrong: emits TRUNCATED bytes (fast, but wrong).
    let wrong = write_exec(&dir, "decode_wrong.sh", "#!/bin/sh\nhead -c 49999 \"$1\"\n");

    let mut tools = vec![
        ToolSpec {
            name: "tool-correct".into(),
            bin: correct.display().to_string(),
            argv: vec!["{input}".into()],
            thread_arg: None,
            auto_threads_arg: None,
            writes_to: OutputMode::Stdout,
            version_arg: "".into(),
        },
        ToolSpec {
            name: "tool-wrong".into(),
            bin: wrong.display().to_string(),
            argv: vec!["{input}".into()],
            thread_arg: None,
            auto_threads_arg: None,
            writes_to: OutputMode::Stdout,
            version_arg: "".into(),
        },
    ];

    // tool-python: correct bytes but an interpreter shim (only if python3 exists).
    let have_python = have("python3");
    if have_python {
        let py = write_exec(
            &dir,
            "decode_py.py",
            "#!/usr/bin/env python3\nimport sys\nwith open(sys.argv[1],'rb') as f: sys.stdout.buffer.write(f.read())\n",
        );
        tools.push(ToolSpec {
            name: "tool-python".into(),
            bin: py.display().to_string(),
            argv: vec!["{input}".into()],
            thread_arg: None,
            auto_threads_arg: None,
            writes_to: OutputMode::Stdout,
            version_arg: "".into(),
        });
    }

    let corpora = vec![Corpus {
        name: "payload".into(),
        kind: "binary".into(),
        path: payload,
        plain_bytes: data.len() as u64,
        reference,
    }];

    let cfg = RunCfg {
        samples: 3,
        startup_samples: 2,
        strict_contention: false,
        timeout: Duration::from_secs(30),
        tmp_dir: dir.clone(),
    };

    let cmp = compare::run_comparison(
        "tool-wrong", // subject is the WRONG tool — it must not get to win
        &tools,
        &corpora,
        &[ThreadCell::Fixed(1)],
        &cfg,
    );

    // ── hole #3: the wrong tool's cell is INVALID (wrong bytes) ──
    let wrong_cell = cmp
        .cells
        .iter()
        .find(|c| c.tool == "tool-wrong")
        .expect("tool-wrong cell present");
    assert!(
        !wrong_cell.correct,
        "tool-wrong emits truncated bytes; the cell MUST be marked incorrect"
    );
    assert!(
        !wrong_cell.valid(),
        "a wrong-bytes cell must not be a valid datapoint"
    );

    // The correct tool's cell IS valid.
    let correct_cell = cmp
        .cells
        .iter()
        .find(|c| c.tool == "tool-correct")
        .expect("tool-correct cell present");
    assert!(
        correct_cell.correct && correct_cell.valid(),
        "tool-correct emits the reference bytes; its cell must be valid"
    );

    // The winner (if any) must NOT be the wrong tool.
    if let Some((w, _)) = cmp.winner("payload", ThreadCell::Fixed(1)) {
        assert_ne!(w, "tool-wrong", "a fast-but-wrong tool must never win");
    }

    // ── the subject (wrong) scope must yield NO claim ──
    let scope = cmp.scope_line();
    assert!(
        scope.contains("DISQUALIFIED") && scope.contains("NO blanket claim"),
        "wrong-bytes subject must be disqualified with no blanket claim; got:\n{scope}"
    );

    // ── hole #1: the python shim is classified INTERPRETED + nonzero startup ──
    if have_python {
        let probe = cmp.probes.get("tool-python").expect("python probe present");
        assert_eq!(
            probe.kind,
            BinaryKind::Interpreted("python".into()),
            "the python shebang shim must be classified as interpreter-wrapped"
        );
        assert!(probe.looks_interpreted());
        let warn = cmp.startup_warning();
        assert!(
            warn.contains("tool-python") && warn.to_lowercase().contains("python"),
            "startup warning must call out the python-wrapped tool; got:\n{warn}"
        );
    }

    // ── the claim-validator audits a 'fastest' claim on the wrong tool as FALSE ──
    let claim = audit::Claim::parse(
        "tool-wrong",
        "fastest on binary at T1",
        &["binary".to_string()],
    );
    let result = audit::audit(claim, &cmp);
    assert_eq!(
        result.verdict,
        Verdict::False,
        "a 'fastest' claim by a wrong-bytes tool must be FALSE"
    );
    assert!(
        result.holes_that_bit.iter().any(|h| h.contains("#3")),
        "the audit must cite hole #3 (output-correctness disqualification)"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A correct tool that genuinely wins (above the noise floor) should SURVIVE an
/// honest scoped claim — the harness must not be so conservative it rejects real
/// wins. Uses a deliberately-slowed shim vs a fast one so the margin is large.
#[test]
fn a_real_win_survives_a_scoped_claim() {
    if !have("sh") {
        eprintln!("skipping: no `sh` on PATH");
        return;
    }
    let dir = std::env::temp_dir().join("fulcrum_fair_compare_win_test");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let payload = dir.join("payload.bin");
    let data: Vec<u8> = (0..20_000u32).map(|i| i as u8).collect();
    std::fs::write(&payload, &data).unwrap();
    let reference = compare::sha256(&data);

    // tool-fast: cat. tool-slow: sleep then cat (a big, above-noise margin).
    let fast = write_exec(&dir, "fast.sh", "#!/bin/sh\ncat \"$1\"\n");
    let slow = write_exec(&dir, "slow.sh", "#!/bin/sh\nsleep 0.15\ncat \"$1\"\n");

    let tools = vec![
        ToolSpec {
            name: "tool-fast".into(),
            bin: fast.display().to_string(),
            argv: vec!["{input}".into()],
            thread_arg: None,
            auto_threads_arg: None,
            writes_to: OutputMode::Stdout,
            version_arg: "".into(),
        },
        ToolSpec {
            name: "tool-slow".into(),
            bin: slow.display().to_string(),
            argv: vec!["{input}".into()],
            thread_arg: None,
            auto_threads_arg: None,
            writes_to: OutputMode::Stdout,
            version_arg: "".into(),
        },
    ];
    let corpora = vec![Corpus {
        name: "payload".into(),
        kind: "binary".into(),
        path: payload,
        plain_bytes: data.len() as u64,
        reference,
    }];
    let cfg = RunCfg {
        samples: 3,
        startup_samples: 2,
        strict_contention: false,
        timeout: Duration::from_secs(30),
        tmp_dir: dir.clone(),
    };
    let cmp = compare::run_comparison(
        "tool-fast",
        &tools,
        &corpora,
        &[ThreadCell::Fixed(1)],
        &cfg,
    );

    // Both correct; tool-fast must WIN above the noise floor (150ms margin).
    let claim = audit::Claim::parse(
        "tool-fast",
        "fastest on binary at T1",
        &["binary".to_string()],
    );
    let result = audit::audit(claim, &cmp);
    assert_eq!(
        result.verdict,
        Verdict::Survives,
        "a genuine 150ms-margin win on correct bytes must SURVIVE the claim; got {:?}\nscope:\n{}",
        result.verdict,
        cmp.scope_line()
    );

    let _ = std::fs::remove_dir_all(&dir);
}
