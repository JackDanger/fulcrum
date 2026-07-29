//! `fulcrum dropin` — the executable DROP-IN COMPATIBILITY census.
//!
//! Genesis (`project_goal_alignment_system`, user 2026-07-26): the campaign's
//! real goal is *"anyone who needs to compress or decompress using DEFLATE
//! can swap their existing tool for ours and be better off"* — but every
//! scoreboard built so far (`sizecensus`/`wallcensus`/`goal`) measures ONLY
//! level x rival x corpus x threads SIZE/WALL. That matrix can go 100% green
//! while a user's actual invocation — `gzip file`, `gzip -dk archive.gz`,
//! `gzip file` a second time without `-f` — silently does something
//! DIFFERENT with gzippy. This module is the missing half: for a matrix of
//! REAL invocations a user would actually type, run the incumbent (gzip or
//! pigz) and gzippy and diff EVERYTHING OBSERVABLE — exit code, stdout
//! bytes/content, stderr shape, which files got created/removed/modified,
//! permission bits on anything newly created, and roundtrip correctness
//! (does the plaintext survive) — never just the compressed-byte count or
//! the wall-clock.
//!
//! REUSE, NOT REIMPLEMENTATION (same ethos as `wallcensus`'s module doc):
//!   * [`crate::levelsweep::{Rival, parse_rival, resolve_ours_binary,
//!     read_meta, write_meta, unix_now, SweepMeta}`] — command resolution,
//!     the gzippy-sha provenance stamp, and the resume-refusal rule.
//!   * [`crate::sizecensus::{RivalProvenance, CorpusProvenance,
//!     rival_provenance, capture_version, host_string, git_commit_for_binary,
//!     basename}`] — the provenance SHAPE (rival-version capture, host
//!     string, commit-for-binary anchoring) is identical to both censuses;
//!     reused verbatim.
//!   * [`crate::compare::{sha256, sha256_reader, hex32}`] — hashing.
//!
//! WHAT A "SCENARIO" IS: a fixed (setup, shell command template, expected
//! [`Kind`]) triple exercised inside a throwaway sandbox directory that
//! starts from a known state. [`scenarios`] is the hardcoded minimum
//! surface — CLI file semantics (in-place vs `-c`, `-k`, `-f`), error
//! behaviour (missing input, refuse-without-force, corrupt input), and the
//! `-t`/`-l` inspect surface. A spec cannot narrow it (same anti-scope-
//! narrowing stance as `goal.rs`'s hardcoded minimum — an excluded axis
//! rots).
//!
//! THE PURE CLASSIFICATION CORE — [`observation_diffs`] + [`classify_status`]
//! — takes no I/O: given two [`Observation`]s (already captured) it computes
//! the list of observable differences and, combined with availability +
//! a matched [`Declared`] exception, the cell's status. This is what
//! `selftest` exhaustively truth-tables without ever spawning a process.
//!
//! STATUSES: MATCH / DIVERGENT (a real, unreasoned behavioural difference —
//! the finding this tool exists to surface) / DECLARED (a difference that
//! matches a `--declared` entry — visible, reasoned, capped, never silently
//! dropped) / ERROR (the instrument itself failed — sandbox I/O, spawn
//! failure — never conflated with a product finding) / OURS-UNAVAILABLE /
//! RIVAL-UNAVAILABLE (binary not on PATH — loud, never silent).
//!
//! A DECLARED entry is exactly `goal.rs`'s `Waiver` shape: `{rival,scenario,
//! fixture,reason}` with `"*"` wildcards and a [`MIN_DECLARED_REASON`]
//! minimum length — a reasonless declared divergence is how excluded axes
//! rot (the same lesson `goal.rs`'s `MIN_WAIVER_REASON` encodes).
//!
//! RESUMABLE, AND A DIVERGENT/ERROR IS NEVER TRUSTED ON RESUME: each cell
//! banks to `DIR/cells/<rival>__<scenario>__<fixture>.json`. A resume that
//! finds a cached `MATCH`/`DECLARED`/`OURS-UNAVAILABLE`/`RIVAL-UNAVAILABLE`
//! reuses it; a cached `DIVERGENT` or `ERROR` is ALWAYS re-measured — a real
//! finding should keep getting re-verified until it is actually fixed
//! (fixing it flips the cell to `MATCH` on the very next resume), and an
//! instrument failure should never freeze into a permanent verdict.
//!
//! USAGE:
//!   fulcrum dropin --ours PATH --rival name=CMD [--rival ...] \
//!       --fixture FILE [--fixture FILE ...] --out DIR \
//!       [--oracle-gzip CMD] [--declared FILE.json]
//!   fulcrum dropin report --out DIR [--out DIR2 ...]   (merge banked runs)
//!   fulcrum dropin selftest                            (Gate-0)
//!
//! Exit code: 0 unless a DIVERGENT or ERROR cell exists (module law shared
//! with sizecensus/wallcensus — a failed or divergent measurement is never
//! silently treated as passing).

use crate::compare::{hex32, sha256};
use crate::levelsweep::{read_meta, resolve_ours_binary, unix_now, write_meta, Rival, SweepMeta};
use crate::sizecensus::{
    basename, git_commit_for_binary, host_string, rival_provenance, CorpusProvenance,
    RivalProvenance,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Fixture {
    pub name: String,
    pub bytes: Vec<u8>,
    pub sha256: String,
}

fn load_fixture(path: &Path) -> Result<Fixture, String> {
    let bytes = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let sha256 = hex32(&sha256(&bytes));
    Ok(Fixture {
        name: basename(path),
        bytes,
        sha256,
    })
}

/// A stable, deliberately-invalid gzip stream — used to test "refuse without
/// `-f`" / "overwrite with `-f`" without depending on any tool to produce it.
const STALE_GZ_GARBAGE: &[u8] = b"NOT-A-VALID-GZIP-STREAM-STALE-FIXTURE\n";

/// Fixed embedded payload backing the fully TOOL-CONSTRUCTED synthetic
/// fixtures below — self-contained (not derived from any `--fixture` the
/// caller passed) so the census reproduces on any box with zero extra setup.
const SYNTHETIC_UNIT: &[u8] =
    b"dropin synthetic fixture payload: the quick brown fox jumps over the lazy dog.\n";

/// Fixture kind 4 — a filename with a SPACE and a non-ASCII character.
/// Crossed against every EXISTING scenario (zero new scenario code needed)
/// this exercises `shq()` for real across actual scenario invocations, not
/// just the one synthetic case `selftest` already covered.
fn synth_spaces_unicode_fixture() -> Fixture {
    let bytes = SYNTHETIC_UNIT.repeat(3);
    let name = "dropin naive file 名前 with spaces.txt".to_string();
    Fixture {
        sha256: hex32(&sha256(&bytes)),
        name,
        bytes,
    }
}

/// Fixture kind 5 — plain (non-gzip) content in a file already named `*.gz`.
/// Crossed against the existing `compress_*` scenarios this is exactly what
/// exposes the real "gzip -c already.gz" / "gzip already.gz (no -f)"
/// already-has-.gz-suffix divergence class.
fn synth_already_gz_fixture() -> Fixture {
    let bytes = SYNTHETIC_UNIT.repeat(5);
    let name = "already-named.gz".to_string();
    Fixture {
        sha256: hex32(&sha256(&bytes)),
        name,
        bytes,
    }
}

// ---------------------------------------------------------------------------
// Scenario kind + table — the hardcoded minimum surface
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Compresses input; compressed bytes are NOT required to match the
    /// rival byte-for-byte (byte-identity with another encoder is an
    /// inherited accident, not a goal) — only that the output ROUNDTRIPS
    /// (via the independent oracle) to the exact original plaintext.
    Compress,
    /// Decompresses input; the produced plaintext MUST match the original
    /// bytes exactly — this is the real, user-visible correctness axis.
    Decompress,
    /// `-t` / `-l`: no content transform, checked via exit class + an
    /// optional scenario-specific semantic check (`Observation::semantic_ok`).
    Inspect,
    /// The scenario is EXPECTED to fail on a correct implementation (missing
    /// input, refuse-without-force, corrupt input) — the cross-arm check is
    /// "did both arms fail", not "did either arm produce output".
    ErrorExpected,
}

impl Kind {
    pub fn token(self) -> &'static str {
        match self {
            Kind::Compress => "Compress",
            Kind::Decompress => "Decompress",
            Kind::Inspect => "Inspect",
            Kind::ErrorExpected => "ErrorExpected",
        }
    }
}

pub struct Scenario {
    pub name: &'static str,
    pub kind: Kind,
    pub setup: fn(&Path, &Fixture, &Path) -> Result<(), String>,
    pub build_cmd: fn(&str, &Fixture) -> String,
    pub doc: &'static str,
}

/// Single-quote a token for `sh -c`: wraps in `'...'`, escaping any embedded
/// `'` as `'\''`. Handles fixture names with spaces safely.
pub fn shq(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

fn setup_plain(sandbox: &Path, fx: &Fixture, _oracle: &Path) -> Result<(), String> {
    let dest = sandbox.join(&fx.name);
    fs::write(&dest, &fx.bytes).map_err(|e| format!("write {}: {e}", dest.display()))?;
    // A non-default mode (0640, not the umask-default 0644) so a tool that
    // fails to preserve permissions on its OWN created file is visible.
    let mut perm = fs::metadata(&dest)
        .map_err(|e| format!("stat {}: {e}", dest.display()))?
        .permissions();
    perm.set_mode(0o640);
    fs::set_permissions(&dest, perm).map_err(|e| format!("chmod {}: {e}", dest.display()))
}

fn setup_gz(sandbox: &Path, fx: &Fixture, oracle: &Path) -> Result<(), String> {
    let bytes = canonical_gz_bytes(oracle, &fx.bytes)?;
    let dest = sandbox.join(format!("{}.gz", fx.name));
    fs::write(&dest, &bytes).map_err(|e| format!("write {}: {e}", dest.display()))
}

fn setup_corrupt_gz(sandbox: &Path, fx: &Fixture, oracle: &Path) -> Result<(), String> {
    let mut bytes = canonical_gz_bytes(oracle, &fx.bytes)?;
    if bytes.len() > 4 {
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xFF;
    } else if !bytes.is_empty() {
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
    }
    let dest = sandbox.join(format!("{}.gz", fx.name));
    fs::write(&dest, &bytes).map_err(|e| format!("write {}: {e}", dest.display()))
}

fn setup_stale_plus_plain(sandbox: &Path, fx: &Fixture, oracle: &Path) -> Result<(), String> {
    setup_plain(sandbox, fx, oracle)?;
    let dest = sandbox.join(format!("{}.gz", fx.name));
    fs::write(&dest, STALE_GZ_GARBAGE).map_err(|e| format!("write {}: {e}", dest.display()))
}

fn setup_none(_sandbox: &Path, _fx: &Fixture, _oracle: &Path) -> Result<(), String> {
    Ok(())
}

/// Fixture kind 1 — a DIRECTORY as the sole input. No `--fixture FILE` can
/// represent this (`fs::read` on a dir fails), so it must be tool-constructed
/// directly. `fx.bytes` is ignored; only `fx.name` names the directory.
fn setup_directory(sandbox: &Path, fx: &Fixture, _oracle: &Path) -> Result<(), String> {
    let dest = sandbox.join(&fx.name);
    fs::create_dir(&dest).map_err(|e| format!("mkdir {}: {e}", dest.display()))
}

/// Fixture kind 2 — a symlink whose target does not exist.
fn setup_broken_symlink(sandbox: &Path, fx: &Fixture, _oracle: &Path) -> Result<(), String> {
    let dest = sandbox.join(&fx.name);
    let target = sandbox.join("dropin-broken-symlink-target-does-not-exist");
    symlink(&target, &dest).map_err(|e| format!("symlink {}: {e}", dest.display()))
}

/// Fixture kind 3 — mode 000 (unreadable, unwritable, even by the owner
/// beyond metadata ops). Exercises "permission denied" on read.
fn setup_mode000(sandbox: &Path, fx: &Fixture, _oracle: &Path) -> Result<(), String> {
    let dest = sandbox.join(&fx.name);
    fs::write(&dest, &fx.bytes).map_err(|e| format!("write {}: {e}", dest.display()))?;
    let mut perm = fs::metadata(&dest)
        .map_err(|e| format!("stat {}: {e}", dest.display()))?
        .permissions();
    perm.set_mode(0o000);
    fs::set_permissions(&dest, perm).map_err(|e| format!("chmod000 {}: {e}", dest.display()))
}

/// Fixture kind 9 — a hard-linked file (nlink > 1): a second directory entry
/// pointing at the same inode as the primary fixture file, constructed
/// alongside it so gzip's real "N has 1 other link -- file ignored" /
/// gzippy's existing nlink-skip logic actually gets exercised.
fn setup_hardlink(sandbox: &Path, fx: &Fixture, oracle: &Path) -> Result<(), String> {
    setup_plain(sandbox, fx, oracle)?;
    let dest = sandbox.join(&fx.name);
    let link = sandbox.join(format!("{}.hardlink-sibling", fx.name));
    fs::hard_link(&dest, &link).map_err(|e| format!("hardlink {}: {e}", link.display()))
}

/// Fixture kind 6 — a MULTI-MEMBER `.gz`: two real gzip members concatenated,
/// built via the independent oracle twice (each member encodes `fx.bytes`).
/// Per gzip's actual multi-member semantics, the correct decompressed output
/// is the CONCATENATION of both members' plaintext — `compute_checks` special-
/// cases scenario name `"multi_member_decompress"` to expect `fx.bytes` TWICE
/// rather than once, so this reuses the generic fixture set without needing
/// a dedicated Fixture whose `.bytes` field disagrees with what setup writes.
fn setup_multi_member_gz(sandbox: &Path, fx: &Fixture, oracle: &Path) -> Result<(), String> {
    let member = canonical_gz_bytes(oracle, &fx.bytes)?;
    let mut bytes = member.clone();
    bytes.extend_from_slice(&member);
    let dest = sandbox.join(format!("{}.gz", fx.name));
    fs::write(&dest, &bytes).map_err(|e| format!("write {}: {e}", dest.display()))
}

/// Fixture kind 7 — a TRUNCATED `.gz`: a valid stream with its trailing bytes
/// (at minimum the whole CRC32+ISIZE trailer, usually more) cut off.
fn setup_truncated_gz(sandbox: &Path, fx: &Fixture, oracle: &Path) -> Result<(), String> {
    let bytes = canonical_gz_bytes(oracle, &fx.bytes)?;
    let cut = (bytes.len() * 2 / 3).min(bytes.len());
    let dest = sandbox.join(format!("{}.gz", fx.name));
    fs::write(&dest, &bytes[..cut]).map_err(|e| format!("write {}: {e}", dest.display()))
}

/// Fixture kind 8 — a `.gz` with a CORRUPTED CRC32 trailer field ONLY: flips
/// one byte inside the last-8-bytes trailer's FIRST 4 bytes (CRC32), leaving
/// the DEFLATE body and the ISIZE (trailer's last 4 bytes) intact. A decoder
/// that doesn't independently verify CRC32 against the trailer will decompress
/// this fine and only a real CRC check catches it — a different bug class
/// than `setup_corrupt_gz`, which flips a byte in the body and likely breaks
/// the DEFLATE stream itself mid-decode.
fn setup_corrupt_gz_crc_only(sandbox: &Path, fx: &Fixture, oracle: &Path) -> Result<(), String> {
    let mut bytes = canonical_gz_bytes(oracle, &fx.bytes)?;
    let len = bytes.len();
    if len >= 8 {
        let crc_field_start = len - 8; // trailer = CRC32 (4 bytes) then ISIZE (4 bytes)
        bytes[crc_field_start] ^= 0xFF;
    } else if !bytes.is_empty() {
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
    }
    let dest = sandbox.join(format!("{}.gz", fx.name));
    fs::write(&dest, &bytes).map_err(|e| format!("write {}: {e}", dest.display()))
}

fn cmd_compress_stdout(tool: &str, fx: &Fixture) -> String {
    format!("{} -c {}", shq(tool), shq(&fx.name))
}
fn cmd_compress_inplace(tool: &str, fx: &Fixture) -> String {
    format!("{} {}", shq(tool), shq(&fx.name))
}
fn cmd_compress_inplace_keep(tool: &str, fx: &Fixture) -> String {
    format!("{} -k {}", shq(tool), shq(&fx.name))
}
fn cmd_compress_level1(tool: &str, fx: &Fixture) -> String {
    format!("{} -1 -c {}", shq(tool), shq(&fx.name))
}
fn cmd_compress_level9(tool: &str, fx: &Fixture) -> String {
    format!("{} -9 -c {}", shq(tool), shq(&fx.name))
}
fn cmd_compress_rsyncable(tool: &str, fx: &Fixture) -> String {
    format!("{} -c --rsyncable {}", shq(tool), shq(&fx.name))
}
fn cmd_stdin_pipe_compress(tool: &str, fx: &Fixture) -> String {
    format!("cat {} | {} -c", shq(&fx.name), shq(tool))
}
fn cmd_compress_force(tool: &str, fx: &Fixture) -> String {
    format!("{} -f {}", shq(tool), shq(&fx.name))
}
fn cmd_decompress_stdout(tool: &str, fx: &Fixture) -> String {
    format!("{} -dc {}.gz", shq(tool), shq(&fx.name))
}
fn cmd_decompress_inplace(tool: &str, fx: &Fixture) -> String {
    format!("{} -d {}.gz", shq(tool), shq(&fx.name))
}
fn cmd_decompress_keep(tool: &str, fx: &Fixture) -> String {
    format!("{} -dk {}.gz", shq(tool), shq(&fx.name))
}
fn cmd_missing_input(tool: &str, _fx: &Fixture) -> String {
    format!("{} -d nonexistent-file-xyz123.gz", shq(tool))
}
fn cmd_test(tool: &str, fx: &Fixture) -> String {
    format!("{} -t {}.gz", shq(tool), shq(&fx.name))
}
fn cmd_list(tool: &str, fx: &Fixture) -> String {
    format!("{} -l {}.gz", shq(tool), shq(&fx.name))
}

/// The hardcoded minimum scenario surface. `goal.rs`'s "HARDCODED MINIMUM
/// SURFACE" lesson applies verbatim: an axis excluded here rots invisibly
/// (list-mode reporting the wrong size, or a refuse-without-`-f` path
/// silently clobbering data, are exactly the class of user-visible failure
/// the level x rival x corpus x threads matrix cannot see at all).
pub fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario { name: "compress_stdout", kind: Kind::Compress, setup: setup_plain, build_cmd: cmd_compress_stdout, doc: "gzip -c file > stdout, original kept" },
        Scenario { name: "compress_inplace", kind: Kind::Compress, setup: setup_plain, build_cmd: cmd_compress_inplace, doc: "gzip file: creates file.gz, removes file" },
        Scenario { name: "compress_inplace_keep", kind: Kind::Compress, setup: setup_plain, build_cmd: cmd_compress_inplace_keep, doc: "gzip -k file: creates file.gz, keeps file" },
        Scenario { name: "compress_level1", kind: Kind::Compress, setup: setup_plain, build_cmd: cmd_compress_level1, doc: "gzip -1 -c file (fastest level accepted + roundtrips)" },
        Scenario { name: "compress_level9", kind: Kind::Compress, setup: setup_plain, build_cmd: cmd_compress_level9, doc: "gzip -9 -c file (best level accepted + roundtrips)" },
        Scenario { name: "compress_rsyncable", kind: Kind::Compress, setup: setup_plain, build_cmd: cmd_compress_rsyncable, doc: "gzip -c --rsyncable file" },
        Scenario { name: "stdin_pipe_compress", kind: Kind::Compress, setup: setup_plain, build_cmd: cmd_stdin_pipe_compress, doc: "cat file | gzip -c (no filename arg at all)" },
        Scenario { name: "decompress_stdout", kind: Kind::Decompress, setup: setup_gz, build_cmd: cmd_decompress_stdout, doc: "gzip -dc file.gz > stdout — the core user correctness path" },
        Scenario { name: "decompress_inplace", kind: Kind::Decompress, setup: setup_gz, build_cmd: cmd_decompress_inplace, doc: "gzip -d file.gz: creates file, removes file.gz" },
        Scenario { name: "decompress_keep", kind: Kind::Decompress, setup: setup_gz, build_cmd: cmd_decompress_keep, doc: "gzip -dk file.gz: creates file, keeps file.gz" },
        Scenario { name: "missing_input", kind: Kind::ErrorExpected, setup: setup_none, build_cmd: cmd_missing_input, doc: "gzip -d nonexistent.gz: must fail loudly, create nothing" },
        Scenario { name: "refuse_overwrite_without_force", kind: Kind::ErrorExpected, setup: setup_stale_plus_plain, build_cmd: cmd_compress_inplace, doc: "gzip file when file.gz already exists, no -f: must refuse, leave the stale .gz untouched" },
        Scenario { name: "force_overwrite", kind: Kind::Compress, setup: setup_stale_plus_plain, build_cmd: cmd_compress_force, doc: "gzip -f file when file.gz already exists: must succeed, replace the stale .gz with a real one" },
        Scenario { name: "test_valid", kind: Kind::Inspect, setup: setup_gz, build_cmd: cmd_test, doc: "gzip -t file.gz on a VALID stream: exit 0, no file changes" },
        Scenario { name: "test_corrupt", kind: Kind::ErrorExpected, setup: setup_corrupt_gz, build_cmd: cmd_test, doc: "gzip -t file.gz on a CORRUPTED stream: must fail loudly" },
        Scenario { name: "decompress_corrupt", kind: Kind::ErrorExpected, setup: setup_corrupt_gz, build_cmd: cmd_decompress_stdout, doc: "gzip -dc file.gz on a CORRUPTED stream: must fail loudly, never silently emit wrong plaintext" },
        Scenario { name: "list_mode", kind: Kind::Inspect, setup: setup_gz, build_cmd: cmd_list, doc: "gzip -l file.gz: exit 0, stdout reports the CORRECT uncompressed size (format may legitimately differ)" },
        // -- Real-world drop-in classes added 2026-07-26 (dropin-coverage-gap) --
        Scenario { name: "directory_input", kind: Kind::ErrorExpected, setup: setup_directory, build_cmd: cmd_compress_inplace, doc: "gzip DIR (no -r): real gzip exits 2 (WARNING), touches nothing — must fail loudly, never crash or silently succeed" },
        Scenario { name: "broken_symlink_input", kind: Kind::ErrorExpected, setup: setup_broken_symlink, build_cmd: cmd_compress_inplace, doc: "gzip on a symlink whose target does not exist: must fail loudly, create nothing" },
        Scenario { name: "mode000_input", kind: Kind::ErrorExpected, setup: setup_mode000, build_cmd: cmd_compress_inplace, doc: "gzip on a mode-000 (unreadable) file: must fail loudly with permission denied, create nothing" },
        Scenario { name: "hardlink_input", kind: Kind::ErrorExpected, setup: setup_hardlink, build_cmd: cmd_compress_inplace, doc: "gzip file when a second hardlink (nlink>1) exists: real gzip refuses ('N has 1 other link -- file ignored'), leaves both links untouched" },
        Scenario { name: "multi_member_decompress", kind: Kind::Decompress, setup: setup_multi_member_gz, build_cmd: cmd_decompress_stdout, doc: "gzip -dc on TWO concatenated gzip members: correct output is the CONCATENATION of both members' plaintext (fx.bytes twice)" },
        Scenario { name: "test_truncated", kind: Kind::ErrorExpected, setup: setup_truncated_gz, build_cmd: cmd_test, doc: "gzip -t on a stream missing its trailing bytes: must fail loudly" },
        Scenario { name: "decompress_truncated", kind: Kind::ErrorExpected, setup: setup_truncated_gz, build_cmd: cmd_decompress_stdout, doc: "gzip -dc on a stream missing its trailing bytes: must fail loudly, never silently emit wrong/partial output as if it were complete" },
        Scenario { name: "test_corrupt_crc", kind: Kind::ErrorExpected, setup: setup_corrupt_gz_crc_only, build_cmd: cmd_test, doc: "gzip -t on a stream with ONLY the CRC32 trailer field corrupted (body+ISIZE intact): must fail loudly — a decoder that skips CRC verification will wrongly pass this" },
        Scenario { name: "decompress_corrupt_crc", kind: Kind::ErrorExpected, setup: setup_corrupt_gz_crc_only, build_cmd: cmd_decompress_stdout, doc: "gzip -dc on a stream with ONLY the CRC32 trailer field corrupted: must fail loudly even though the DEFLATE body decodes to the right bytes" },
    ]
}

// ---------------------------------------------------------------------------
// Oracle (independent gzip used to prepare/verify fixtures — fixed regardless
// of which arm is under test, so the correctness oracle is never the same
// process as either arm being compared)
// ---------------------------------------------------------------------------

fn canonical_gz_bytes(oracle_gzip: &Path, plain: &[u8]) -> Result<Vec<u8>, String> {
    let mut child = Command::new(oracle_gzip)
        .arg("-c")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn oracle `{}` -c: {e}", oracle_gzip.display()))?;
    let mut stdin = child.stdin.take().ok_or("no stdin pipe for oracle -c")?;
    let mut stdout = child.stdout.take().ok_or("no stdout pipe for oracle -c")?;
    let plain_owned = plain.to_vec();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&plain_owned);
    });
    let mut out = Vec::new();
    stdout
        .read_to_end(&mut out)
        .map_err(|e| format!("read oracle -c stdout: {e}"))?;
    let status = child.wait().map_err(|e| format!("wait oracle -c: {e}"))?;
    let _ = writer.join();
    if !status.success() {
        return Err(format!(
            "oracle `{}` -c failed to compress a fixture — cannot prepare test .gz",
            oracle_gzip.display()
        ));
    }
    Ok(out)
}

fn oracle_decompress(oracle_gzip: &Path, bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut child = Command::new(oracle_gzip)
        .arg("-dc")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn oracle `{}` -dc: {e}", oracle_gzip.display()))?;
    let mut stdin = child.stdin.take().ok_or("no stdin pipe for oracle -dc")?;
    let mut stdout = child.stdout.take().ok_or("no stdout pipe for oracle -dc")?;
    let bytes_owned = bytes.to_vec();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&bytes_owned);
    });
    let mut out = Vec::new();
    // Deliberately IGNORE read errors / nonzero exit here: a Compress arm
    // under test may have produced garbage, and "the oracle also choked on
    // it" is exactly the correct signal (whatever partial bytes came out
    // will simply fail the plaintext-equality check below) — never an Err
    // that would abort the whole cell.
    let _ = stdout.read_to_end(&mut out);
    let _ = child.wait();
    let _ = writer.join();
    Ok(out)
}

// ---------------------------------------------------------------------------
// Sandbox snapshot + capture
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct FileSnap {
    sha256: String,
    mode: u32,
}

fn snapshot_dir(dir: &Path) -> Result<BTreeMap<String, FileSnap>, String> {
    let mut out = BTreeMap::new();
    for entry in fs::read_dir(dir).map_err(|e| format!("readdir {}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| format!("readdir entry in {}: {e}", dir.display()))?;
        let path = entry.path();
        let meta = entry
            .metadata()
            .map_err(|e| format!("stat {}: {e}", path.display()))?;
        if !meta.is_file() {
            continue; // regular files only — no `-r` recursion in this module's scope
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let mode = meta.permissions().mode() & 0o777;
        // A mode that denies the OWNER read access (the mode-000 fixture)
        // cannot be hashed by content — `fs::read` returns EACCES. Fall back
        // to a mode+size sentinel rather than aborting the whole capture: a
        // legitimate mode-000 fixture must not turn into a hard ERROR cell.
        // Both arms compute the same sentinel given the same mode+len, so no
        // phantom diff is introduced when nothing actually changed.
        let content_sha = match fs::read(&path) {
            Ok(data) => hex32(&sha256(&data)),
            Err(_) => format!("<unreadable mode={:o} len={}>", mode, meta.len()),
        };
        out.insert(
            name,
            FileSnap {
                sha256: content_sha,
                mode,
            },
        );
    }
    Ok(out)
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Observation {
    pub exit_code: Option<i32>,
    pub success: bool,
    pub stdout_len: u64,
    pub stdout_sha256: String,
    pub stderr_empty: bool,
    pub stderr_first_line: String,
    pub created: Vec<String>,
    pub removed: Vec<String>,
    pub modified: Vec<String>,
    pub created_modes: BTreeMap<String, u32>,
    /// Compress: does the output ROUNDTRIP (via the oracle) to the exact
    /// original plaintext? Decompress: does the produced plaintext match the
    /// original exactly? `None` for Inspect/ErrorExpected (not applicable).
    pub roundtrip_ok: Option<bool>,
    /// Scenario-specific extra semantic check (currently: does `-l`'s stdout
    /// report the correct uncompressed size?). `None` when not applicable.
    pub semantic_ok: Option<bool>,
}

static SANDBOX_SEQ: AtomicU64 = AtomicU64::new(0);

/// Defensive permission restore before `remove_dir_all`. POSIX only requires
/// write+exec on a file's PARENT dir to unlink it — a mode-000 FILE is
/// already removable — so the real hazard this guards is a mode-000
/// DIRECTORY (nothing here creates one today, but any future addition must
/// not leave one behind). Best-effort: every entry gets a mode that is at
/// least owner-rw(x), recursively; failures are ignored (e.g. chmod on a
/// dangling symlink target) since the goal is "never BLOCK cleanup", not to
/// perfectly restore original modes.
fn harden_permissions_for_removal(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if let Ok(meta) = entry.metadata() {
            let is_dir = meta.is_dir();
            let mut perm = meta.permissions();
            perm.set_mode(if is_dir { 0o755 } else { 0o644 });
            let _ = fs::set_permissions(&path, perm);
            if is_dir {
                harden_permissions_for_removal(&path);
            }
        }
    }
}

fn compute_checks(
    scenario: &Scenario,
    fx: &Fixture,
    sandbox: &Path,
    stdout: &[u8],
    success: bool,
    oracle_gzip: &Path,
) -> Result<(Option<bool>, Option<bool>), String> {
    match scenario.kind {
        Kind::Compress => {
            if !success {
                return Ok((Some(false), None));
            }
            let compressed: Vec<u8> = if !stdout.is_empty() {
                stdout.to_vec()
            } else {
                let gz_path = sandbox.join(format!("{}.gz", fx.name));
                if gz_path.is_file() {
                    fs::read(&gz_path).map_err(|e| format!("read {}: {e}", gz_path.display()))?
                } else {
                    Vec::new()
                }
            };
            if compressed.is_empty() {
                // A SUCCESSFUL exit with NO compressed bytes anywhere (empty
                // stdout, and no `<name>.gz` written into the sandbox) is not
                // "produced garbage that fails to roundtrip" — it means the
                // tool correctly declined to do anything at all (e.g. real
                // gzip's own "already has .gz suffix -- unchanged" no-op on
                // `gzip already.gz`, or pigz's "skipping: X ends with .gz").
                // Roundtrip correctness isn't APPLICABLE to a no-op, so this
                // reports `None`, not `Some(false)`. Forcing `Some(false)`
                // here previously made `observation_diffs` synthesize "BOTH
                // arms produced output that fails to roundtrip" whenever both
                // tools correctly did nothing — a harness false positive
                // (`dropin-coverage-gap` census: fixture `already-named.gz`
                // x `compress_inplace`/`compress_inplace_keep`, both gzip AND
                // pigz rivals — confirmed by direct execution: `gzip
                // already-named.gz` and `pigz already-named.gz` both print a
                // no-op notice, exit 0, and touch nothing).
                //
                // This does NOT mask a real asymmetric bug: if only one arm
                // declined while the other actually compressed, that arm's
                // `roundtrip_ok` is `Some(_)` and this arm's is `None` — the
                // `!=` check in `observation_diffs` still flags the
                // difference (see e.g. `compress_stdout`/`already-named.gz`
                // vs pigz, where gzippy compresses through and pigz skips).
                return Ok((None, None));
            }
            let plain = oracle_decompress(oracle_gzip, &compressed)?;
            Ok((Some(plain == fx.bytes), None))
        }
        Kind::Decompress => {
            if !success {
                return Ok((Some(false), None));
            }
            // `multi_member_decompress`'s setup writes TWO real gzip members,
            // each encoding `fx.bytes` — per gzip's actual multi-member
            // semantics the correct decompressed output is the
            // CONCATENATION of both members' plaintext (`fx.bytes` twice),
            // not `fx.bytes` once. Special-cased by scenario name, same
            // pattern `Kind::Inspect` already uses for `list_mode` below.
            let expected: Vec<u8> = if scenario.name == "multi_member_decompress" {
                let mut e = fx.bytes.clone();
                e.extend_from_slice(&fx.bytes);
                e
            } else {
                fx.bytes.clone()
            };
            let produced: Vec<u8> = if !stdout.is_empty() || expected.is_empty() {
                stdout.to_vec()
            } else {
                let plain_path = sandbox.join(&fx.name);
                if plain_path.is_file() {
                    fs::read(&plain_path)
                        .map_err(|e| format!("read {}: {e}", plain_path.display()))?
                } else {
                    Vec::new()
                }
            };
            Ok((Some(produced == expected), None))
        }
        Kind::Inspect => {
            if scenario.name == "list_mode" {
                let text = String::from_utf8_lossy(stdout);
                Ok((None, Some(text.contains(&fx.bytes.len().to_string()))))
            } else {
                Ok((None, None))
            }
        }
        Kind::ErrorExpected => Ok((None, None)),
    }
}

/// Run ONE (tool, scenario, fixture) in a fresh, throwaway sandbox and
/// capture everything observable. The sandbox is removed before returning —
/// this module never retains fixture copies or run artifacts beyond the
/// JSON/TSV summary (coordinator note: keep artifacts small).
fn capture(
    tool_abs: &str,
    scenario: &Scenario,
    fx: &Fixture,
    tmp_root: &Path,
    oracle_gzip: &Path,
) -> Result<Observation, String> {
    let seq = SANDBOX_SEQ.fetch_add(1, Ordering::Relaxed);
    let sandbox = tmp_root.join(format!("sb-{}-{seq}", std::process::id()));
    fs::create_dir_all(&sandbox).map_err(|e| format!("mkdir {}: {e}", sandbox.display()))?;
    let result = (|| -> Result<Observation, String> {
        (scenario.setup)(&sandbox, fx, oracle_gzip)?;
        let before = snapshot_dir(&sandbox)?;
        let cmd = (scenario.build_cmd)(tool_abs, fx);
        let output = Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .current_dir(&sandbox)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("spawn `{cmd}`: {e}"))?;
        let after = snapshot_dir(&sandbox)?;

        let mut created = Vec::new();
        let mut removed = Vec::new();
        let mut modified = Vec::new();
        let mut created_modes = BTreeMap::new();
        for (name, snap) in &after {
            match before.get(name) {
                None => {
                    created.push(name.clone());
                    created_modes.insert(name.clone(), snap.mode);
                }
                Some(b) => {
                    if b.sha256 != snap.sha256 {
                        modified.push(name.clone());
                    }
                }
            }
        }
        for name in before.keys() {
            if !after.contains_key(name) {
                removed.push(name.clone());
            }
        }
        created.sort();
        removed.sort();
        modified.sort();

        let exit_code = output.status.code();
        let success = output.status.success();
        let stdout_len = output.stdout.len() as u64;
        let stdout_sha256 = hex32(&sha256(&output.stdout));
        let stderr_text = String::from_utf8_lossy(&output.stderr);
        let stderr_empty = stderr_text.trim().is_empty();
        let stderr_first_line = stderr_text
            .lines()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("")
            .chars()
            .take(200)
            .collect();

        let (roundtrip_ok, semantic_ok) =
            compute_checks(scenario, fx, &sandbox, &output.stdout, success, oracle_gzip)?;

        Ok(Observation {
            exit_code,
            success,
            stdout_len,
            stdout_sha256,
            stderr_empty,
            stderr_first_line,
            created,
            removed,
            modified,
            created_modes,
            roundtrip_ok,
            semantic_ok,
        })
    })();
    // Mode-000 cleanup gate: harden any restrictive mode left by a fixture
    // (or by the tool under test) BEFORE removal — see
    // `harden_permissions_for_removal` doc for why this is defensive rather
    // than strictly required by POSIX for a lone mode-000 file.
    harden_permissions_for_removal(&sandbox);
    let _ = fs::remove_dir_all(&sandbox);
    result
}

// ---------------------------------------------------------------------------
// Pure classification core
// ---------------------------------------------------------------------------

/// Every observable difference between `ours` and `rival`, kind-aware. Pure:
/// takes already-captured observations, does no I/O, and is exhaustively
/// truth-tabled by `selftest`.
pub fn observation_diffs(kind: Kind, ours: &Observation, rival: &Observation) -> Vec<String> {
    let mut diffs = Vec::new();
    if ours.success != rival.success {
        diffs.push(format!(
            "exit-code class differs: ours={:?} (success={}) rival={:?} (success={})",
            ours.exit_code, ours.success, rival.exit_code, rival.success
        ));
    } else if ours.exit_code != rival.exit_code {
        // Same success/failure CLASS but a different exact code — e.g. real
        // gzip's WARNING class (exit 2, `gzip: X is a directory -- ignored`)
        // vs its ERROR class (exit 1). The success-bool check above cannot
        // see this (both are "failure"); this is what makes that distinction
        // observable at all, per the module's stated goal of diffing
        // "everything observable — exit code, stdout...".
        diffs.push(format!(
            "exit code differs despite same success class: ours={:?} rival={:?}",
            ours.exit_code, rival.exit_code
        ));
    }
    if ours.stderr_empty != rival.stderr_empty {
        diffs.push(format!(
            "stderr shape differs: ours_empty={} rival_empty={} (ours first line: {:?}, rival first line: {:?})",
            ours.stderr_empty, rival.stderr_empty, ours.stderr_first_line, rival.stderr_first_line
        ));
    }
    if ours.created != rival.created {
        diffs.push(format!(
            "created-file set differs: ours={:?} rival={:?}",
            ours.created, rival.created
        ));
    }
    if ours.removed != rival.removed {
        diffs.push(format!(
            "removed-file set differs: ours={:?} rival={:?}",
            ours.removed, rival.removed
        ));
    }
    if ours.modified != rival.modified {
        diffs.push(format!(
            "modified-file set differs: ours={:?} rival={:?}",
            ours.modified, rival.modified
        ));
    }
    for (name, ours_mode) in &ours.created_modes {
        if let Some(rival_mode) = rival.created_modes.get(name) {
            if ours_mode != rival_mode {
                diffs.push(format!(
                    "created-file '{name}' permission bits differ: ours={ours_mode:o} rival={rival_mode:o}"
                ));
            }
        }
    }
    match kind {
        Kind::Compress => {
            if ours.roundtrip_ok != rival.roundtrip_ok {
                diffs.push(format!(
                    "compressed-output roundtrip correctness differs: ours={:?} rival={:?}",
                    ours.roundtrip_ok, rival.roundtrip_ok
                ));
            } else if ours.roundtrip_ok == Some(false) {
                diffs.push(
                    "BOTH arms produced output that fails to roundtrip to the original plaintext (shared defect, still flagged)"
                        .to_string(),
                );
            }
        }
        Kind::Decompress => {
            if ours.roundtrip_ok != rival.roundtrip_ok {
                diffs.push(format!(
                    "decompressed-content correctness differs: ours={:?} rival={:?}",
                    ours.roundtrip_ok, rival.roundtrip_ok
                ));
            } else if ours.roundtrip_ok == Some(false) {
                diffs.push(
                    "BOTH arms produced incorrect plaintext from this input (shared defect, still flagged)"
                        .to_string(),
                );
            }
        }
        Kind::Inspect => {
            if ours.semantic_ok != rival.semantic_ok {
                diffs.push(format!(
                    "semantic content check differs (e.g. -l reported size): ours={:?} rival={:?}",
                    ours.semantic_ok, rival.semantic_ok
                ));
            }
        }
        Kind::ErrorExpected => {
            // Exit-class already checked above (both arms must fail); the
            // generic file-lifecycle axes above cover "did either arm
            // destructively clobber something while refusing/erroring".
        }
    }
    diffs
}

/// The pure precedence table (mirrors `wallcensus::classify_status`'s
/// shape): availability beats everything, an instrument failure is `ERROR`
/// (never conflated with a product finding), a zero-diff cell is `MATCH`,
/// and a nonzero-diff cell is `DECLARED` only if an operator-supplied
/// [`Declared`] entry actually matched it — otherwise `DIVERGENT`.
pub fn classify_status(
    ours_available: bool,
    rival_available: bool,
    run_error: bool,
    declared_match: bool,
    diff_count: usize,
) -> &'static str {
    if run_error {
        return "ERROR";
    }
    if !rival_available {
        return "RIVAL-UNAVAILABLE";
    }
    if !ours_available {
        return "OURS-UNAVAILABLE";
    }
    if diff_count == 0 {
        "MATCH"
    } else if declared_match {
        "DECLARED"
    } else {
        "DIVERGENT"
    }
}

// ---------------------------------------------------------------------------
// Declared exceptions — exactly goal.rs's Waiver shape
// ---------------------------------------------------------------------------

fn star() -> String {
    "*".to_string()
}

/// Minimum declared-reason length: a declared divergence must say something.
/// Mirrors `goal::MIN_WAIVER_REASON` — a reasonless declared exception is how
/// excluded axes rot invisibly (that module's own `dd79_text6xL1` lesson).
pub const MIN_DECLARED_REASON: usize = 20;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Declared {
    #[serde(default = "star")]
    pub rival: String,
    #[serde(default = "star")]
    pub scenario: String,
    #[serde(default = "star")]
    pub fixture: String,
    pub reason: String,
}

impl Declared {
    fn field_matches(pat: &str, val: &str) -> bool {
        pat == "*" || pat == val
    }
    pub fn matches(&self, rival: &str, scenario: &str, fixture: &str) -> bool {
        Self::field_matches(&self.rival, rival)
            && Self::field_matches(&self.scenario, scenario)
            && Self::field_matches(&self.fixture, fixture)
    }
}

pub fn validate_declared(list: &[Declared]) -> Result<(), String> {
    for d in list {
        if d.reason.trim().len() < MIN_DECLARED_REASON {
            return Err(format!(
                "declared exception {{rival:{},scenario:{},fixture:{}}} has a {}-char reason; \
                 a declared divergence is a visible, argued exception (min {} chars) — \
                 reasonless declarations are how excluded axes rot silently",
                d.rival,
                d.scenario,
                d.fixture,
                d.reason.trim().len(),
                MIN_DECLARED_REASON
            ));
        }
    }
    Ok(())
}

fn load_declared(path: Option<&str>) -> Result<Vec<Declared>, String> {
    let Some(path) = path else {
        return Ok(Vec::new());
    };
    let text = fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let list: Vec<Declared> =
        serde_json::from_str(&text).map_err(|e| format!("parse {path}: {e}"))?;
    validate_declared(&list)?;
    Ok(list)
}

// ---------------------------------------------------------------------------
// Cell + provenance + artifact
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DropinCell {
    pub rival: String,
    pub scenario: String,
    pub fixture: String,
    pub kind: String,
    /// MATCH | DIVERGENT | DECLARED | ERROR | OURS-UNAVAILABLE | RIVAL-UNAVAILABLE
    pub status: String,
    pub diffs: Vec<String>,
    pub declared_reason: Option<String>,
    pub ours_exit: Option<i32>,
    pub rival_exit: Option<i32>,
    pub error: Option<String>,
}

fn cell_id(rival: &str, scenario: &str, fixture: &str) -> String {
    format!("{rival}__{scenario}__{fixture}")
}

fn load_cell(path: &Path) -> Option<DropinCell> {
    serde_json::from_str(&fs::read_to_string(path).ok()?).ok()
}

fn save_cell(path: &Path, cell: &DropinCell) {
    if let Ok(js) = serde_json::to_string_pretty(cell) {
        let _ = fs::write(path, js);
    }
}

fn placeholder_cell(
    rival: &str,
    scenario: &Scenario,
    fx: &Fixture,
    status: &str,
    error: Option<String>,
) -> DropinCell {
    DropinCell {
        rival: rival.to_string(),
        scenario: scenario.name.to_string(),
        fixture: fx.name.clone(),
        kind: scenario.kind.token().to_string(),
        status: status.to_string(),
        diffs: Vec::new(),
        declared_reason: None,
        ours_exit: None,
        rival_exit: None,
        error,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DropinProvenance {
    /// selfver stamp of the fulcrum that ran the census.
    #[serde(default)]
    pub fulcrum_commit: String,
    pub ours_cmd: String,
    pub ours_bin: Option<String>,
    pub ours_sha256: Option<String>,
    pub ours_commit: Option<String>,
    pub host: String,
    pub rivals: Vec<RivalProvenance>,
    pub fixtures: Vec<CorpusProvenance>,
    pub oracle_gzip: String,
    pub created_unix: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DropinArtifact {
    pub provenance: DropinProvenance,
    pub cells: Vec<DropinCell>,
}

pub struct DropinConfig {
    pub ours: String,
    pub rivals: Vec<Rival>,
    pub fixtures: Vec<PathBuf>,
    pub out_dir: PathBuf,
    pub oracle_gzip: String,
    pub declared: Vec<Declared>,
}

#[allow(clippy::too_many_arguments)]
fn measure_cell(
    rival: &Rival,
    rival_available: bool,
    rival_abs: Option<&str>,
    ours_available: bool,
    ours_abs: Option<&str>,
    scenario: &Scenario,
    fx: &Fixture,
    tmp_root: &Path,
    oracle_gzip: &Path,
    declared: &[Declared],
) -> DropinCell {
    if !rival_available {
        return placeholder_cell(&rival.name, scenario, fx, "RIVAL-UNAVAILABLE", None);
    }
    if !ours_available {
        return placeholder_cell(&rival.name, scenario, fx, "OURS-UNAVAILABLE", None);
    }
    let (Some(ours_abs), Some(rival_abs)) = (ours_abs, rival_abs) else {
        return placeholder_cell(
            &rival.name,
            scenario,
            fx,
            "ERROR",
            Some("resolved-available but no absolute path captured (internal)".to_string()),
        );
    };
    let ours_obs = capture(ours_abs, scenario, fx, tmp_root, oracle_gzip);
    let rival_obs = capture(rival_abs, scenario, fx, tmp_root, oracle_gzip);
    match (ours_obs, rival_obs) {
        (Ok(o), Ok(r)) => {
            let diffs = observation_diffs(scenario.kind, &o, &r);
            let matched_decl = declared
                .iter()
                .find(|d| d.matches(&rival.name, scenario.name, &fx.name));
            let status = classify_status(true, true, false, matched_decl.is_some(), diffs.len());
            DropinCell {
                rival: rival.name.clone(),
                scenario: scenario.name.to_string(),
                fixture: fx.name.clone(),
                kind: scenario.kind.token().to_string(),
                status: status.to_string(),
                diffs,
                declared_reason: matched_decl.map(|d| d.reason.clone()),
                ours_exit: o.exit_code,
                rival_exit: r.exit_code,
                error: None,
            }
        }
        (oe, re) => {
            let err = oe
                .err()
                .or_else(|| re.err())
                .unwrap_or_else(|| "unknown capture error".to_string());
            placeholder_cell(&rival.name, scenario, fx, "ERROR", Some(err))
        }
    }
}

pub fn run_dropin(cfg: &DropinConfig) -> Result<DropinArtifact, String> {
    let cells_dir = cfg.out_dir.join("cells");
    fs::create_dir_all(&cells_dir).map_err(|e| format!("mkdir {}: {e}", cells_dir.display()))?;

    let ours_bin = resolve_ours_binary(&cfg.ours);
    let ours_sha = ours_bin
        .as_ref()
        .and_then(|p| crate::paired::sha256_of_file(p).ok());

    match read_meta(&cfg.out_dir) {
        Some(prev) => {
            if prev.ours_sha256.is_some() && ours_sha.is_some() && prev.ours_sha256 != ours_sha {
                return Err(format!(
                    "dropin: refused — {} was stamped ours_sha256={} but the current --ours \
                     resolves to sha256={}; resuming here would merge cells from two different \
                     gzippy binaries into one census. Use a fresh --out DIR.",
                    cfg.out_dir.display(),
                    prev.ours_sha256.as_deref().unwrap_or("?"),
                    ours_sha.as_deref().unwrap_or("?"),
                ));
            }
        }
        None => {
            write_meta(
                &cfg.out_dir,
                &SweepMeta {
                    ours_tmpl: cfg.ours.clone(),
                    ours_bin: ours_bin.as_ref().map(|p| p.display().to_string()),
                    ours_sha256: ours_sha.clone(),
                    created_unix: unix_now(),
                    attested: false,
                },
            )?;
        }
    }

    let oracle_gzip = resolve_ours_binary(&cfg.oracle_gzip).ok_or_else(|| {
        format!(
            "dropin: oracle gzip `{}` not found on PATH — cannot prepare/verify any fixture",
            cfg.oracle_gzip
        )
    })?;

    let rival_prov: Vec<RivalProvenance> = cfg.rivals.iter().map(rival_provenance).collect();
    let rival_available: BTreeMap<String, bool> = rival_prov
        .iter()
        .map(|r| (r.name.clone(), r.available))
        .collect();
    let rival_abs: BTreeMap<String, Option<PathBuf>> = cfg
        .rivals
        .iter()
        .map(|r| (r.name.clone(), resolve_ours_binary(&r.tmpl)))
        .collect();

    let ours_available = ours_bin.is_some();
    let ours_abs_string = ours_bin.as_ref().map(|p| p.display().to_string());

    let tmp_root = std::env::temp_dir().join(format!("fulcrum-dropin-run-{}", std::process::id()));
    fs::create_dir_all(&tmp_root).map_err(|e| format!("mkdir {}: {e}", tmp_root.display()))?;

    let mut fixture_prov = Vec::new();
    let mut fixtures = Vec::new();
    for path in &cfg.fixtures {
        if !path.exists() {
            return Err(format!("dropin: fixture {} does not exist", path.display()));
        }
        let fx = load_fixture(path)?;
        fixture_prov.push(CorpusProvenance {
            name: fx.name.clone(),
            sha256: fx.sha256.clone(),
            bytes: fx.bytes.len() as u64,
        });
        fixtures.push(fx);
    }
    // Fixture kinds 4 + 5 — fully TOOL-CONSTRUCTED, unconditional, no new CLI
    // flag: reuse the EXISTING scenarios() x fixtures cross-product to
    // exercise `shq()` for real (space + non-ASCII filename) and the
    // already-.gz-suffix divergence class, with zero new scenario code.
    for fx in [synth_spaces_unicode_fixture(), synth_already_gz_fixture()] {
        fixture_prov.push(CorpusProvenance {
            name: fx.name.clone(),
            sha256: fx.sha256.clone(),
            bytes: fx.bytes.len() as u64,
        });
        fixtures.push(fx);
    }

    let scenario_list = scenarios();
    let mut cells = Vec::new();
    for rival in &cfg.rivals {
        let avail = *rival_available.get(&rival.name).unwrap_or(&false);
        let r_abs = rival_abs
            .get(&rival.name)
            .and_then(|o| o.as_ref())
            .map(|p| p.display().to_string());
        for fx in &fixtures {
            for scenario in &scenario_list {
                let id = cell_id(&rival.name, scenario.name, &fx.name);
                let cell_path = cells_dir.join(format!("{id}.json"));
                if let Some(existing) = load_cell(&cell_path) {
                    if existing.status != "DIVERGENT" && existing.status != "ERROR" {
                        eprintln!("dropin: resume {id} (cached status={})", existing.status);
                        cells.push(existing);
                        continue;
                    }
                    eprintln!(
                        "dropin: resume {id} — cached status={}, RE-MEASURING (a DIVERGENT or \
                         ERROR is never trusted on resume)",
                        existing.status
                    );
                }
                let cell = measure_cell(
                    rival,
                    avail,
                    r_abs.as_deref(),
                    ours_available,
                    ours_abs_string.as_deref(),
                    scenario,
                    fx,
                    &tmp_root,
                    &oracle_gzip,
                    &cfg.declared,
                );
                eprintln!("dropin: {id} -> {}", cell.status);
                save_cell(&cell_path, &cell);
                cells.push(cell);
            }
        }
    }
    let _ = fs::remove_dir_all(&tmp_root);

    let ours_commit = git_commit_for_binary(ours_bin.as_deref());
    let provenance = DropinProvenance {
        fulcrum_commit: crate::selfver::stamp(),
        ours_cmd: cfg.ours.clone(),
        ours_bin: ours_bin.map(|p| p.display().to_string()),
        ours_sha256: ours_sha,
        ours_commit,
        host: host_string(),
        rivals: rival_prov,
        fixtures: fixture_prov,
        oracle_gzip: oracle_gzip.display().to_string(),
        created_unix: unix_now(),
    };
    if provenance.ours_commit.is_none() {
        eprintln!(
            "dropin: WARN ours_commit could not be determined — recorded as null, not guessed"
        );
    }

    Ok(DropinArtifact { provenance, cells })
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

pub fn write_tsv(cells: &[DropinCell], path: &Path) -> Result<(), String> {
    let mut s =
        String::from("rival\tscenario\tfixture\tkind\tstatus\tours_exit\trival_exit\tdeclared_reason\tdiffs\terror\n");
    for c in cells {
        s.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            c.rival,
            c.scenario,
            c.fixture,
            c.kind,
            c.status,
            c.ours_exit.map(|e| e.to_string()).unwrap_or_default(),
            c.rival_exit.map(|e| e.to_string()).unwrap_or_default(),
            c.declared_reason
                .clone()
                .unwrap_or_default()
                .replace('\t', " "),
            c.diffs.join("; ").replace('\t', " ").replace('\n', " "),
            c.error.clone().unwrap_or_default().replace('\t', " "),
        ));
    }
    fs::write(path, s).map_err(|e| format!("write {}: {e}", path.display()))
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct DropinSummary {
    pub declared_total: usize,
    pub matched: usize,
    pub divergent: usize,
    pub declared_exception: usize,
    pub error: usize,
    pub ours_unavailable: usize,
    pub rival_unavailable: usize,
}

pub fn summarize(cells: &[DropinCell]) -> DropinSummary {
    let mut s = DropinSummary {
        declared_total: cells.len(),
        ..Default::default()
    };
    for c in cells {
        match c.status.as_str() {
            "MATCH" => s.matched += 1,
            "DIVERGENT" => s.divergent += 1,
            "DECLARED" => s.declared_exception += 1,
            "ERROR" => s.error += 1,
            "OURS-UNAVAILABLE" => s.ours_unavailable += 1,
            "RIVAL-UNAVAILABLE" => s.rival_unavailable += 1,
            _ => {}
        }
    }
    s
}

/// Human summary: every DIVERGENT cell named with its fixture, scenario, and
/// exact diff list (module contract — "report every DIVERGENT with its
/// fixture and exact difference"), denominator always stated, ERROR cells
/// named separately from real findings.
pub fn render_summary(provenance: &DropinProvenance, cells: &[DropinCell]) -> String {
    let s = summarize(cells);
    let mut out = String::new();
    out.push_str(&format!(
        "DROPIN ours_sha256={} commit={} host={}\n",
        provenance
            .ours_sha256
            .as_deref()
            .map(|h| h.chars().take(12).collect::<String>())
            .unwrap_or_else(|| "UNPROVENANCED".to_string()),
        provenance.ours_commit.as_deref().unwrap_or("UNKNOWN"),
        provenance.host,
    ));
    for r in &provenance.rivals {
        out.push_str(&format!("  rival {:<12} {}\n", r.name, r.version));
    }
    out.push_str(&format!(
        "  oracle gzip: {}\n  fixtures: {} (shas stamped in the JSON artifact)\n\n",
        provenance.oracle_gzip,
        provenance.fixtures.len()
    ));

    out.push_str(&format!(
        "DIVERGENT CELLS: {} of {} measured (MATCH+DIVERGENT+DECLARED)\n\n",
        s.divergent,
        s.matched + s.divergent + s.declared_exception
    ));
    for c in cells.iter().filter(|c| c.status == "DIVERGENT") {
        out.push_str(&format!(
            "  [{}] rival={} scenario={} fixture={} ours_exit={:?} rival_exit={:?}\n",
            c.kind, c.rival, c.scenario, c.fixture, c.ours_exit, c.rival_exit
        ));
        for d in &c.diffs {
            out.push_str(&format!("      - {d}\n"));
        }
    }
    if s.divergent > 0 {
        out.push('\n');
    }

    if s.declared_exception > 0 {
        out.push_str(&format!(
            "DECLARED (reasoned, non-blocking) CELLS: {}\n",
            s.declared_exception
        ));
        for c in cells.iter().filter(|c| c.status == "DECLARED") {
            out.push_str(&format!(
                "  rival={} scenario={} fixture={} reason={}\n",
                c.rival,
                c.scenario,
                c.fixture,
                c.declared_reason.as_deref().unwrap_or("")
            ));
        }
        out.push('\n');
    }

    if s.error > 0 {
        out.push_str(&format!(
            "ERROR CELLS (instrument failure, never a product finding): {}\n",
            s.error
        ));
        for c in cells.iter().filter(|c| c.status == "ERROR") {
            out.push_str(&format!(
                "  rival={} scenario={} fixture={} error={}\n",
                c.rival,
                c.scenario,
                c.fixture,
                c.error.as_deref().unwrap_or("")
            ));
        }
        out.push('\n');
    }

    out.push_str(&format!(
        "DROPIN declared={} matched={} divergent={} declared_exception={} error={} \
         ours_unavailable={} rival_unavailable={}\n",
        s.declared_total,
        s.matched,
        s.divergent,
        s.declared_exception,
        s.error,
        s.ours_unavailable,
        s.rival_unavailable,
    ));
    out
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

fn cli_flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
}

fn cli_multi(args: &[String], name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == name {
            if let Some(v) = args.get(i + 1) {
                out.push(v.clone());
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    out
}

fn usage() -> ExitCode {
    eprintln!(
        "fulcrum dropin — the executable DROP-IN COMPATIBILITY census (the missing half of the\n\
         goal scoreboard: level x rival x corpus x threads can go 100%% green while a real\n\
         invocation like `gzip file` or `gzip -dk archive.gz` silently behaves differently).\n\
         \n\
         USAGE:\n\
         \x20 fulcrum dropin --ours PATH --rival name=CMD [--rival ...] \\\n\
         \x20     --fixture FILE [--fixture FILE2 ...] --out DIR \\\n\
         \x20     [--oracle-gzip CMD] [--declared FILE.json]\n\
         \x20 fulcrum dropin report --out DIR [--out DIR2 ...]   merge banked runs\n\
         \x20                                                    (refuses on sha mismatch)\n\
         \x20 fulcrum dropin selftest                            Gate-0\n\
         \n\
         For EVERY (rival, fixture, scenario) — a hardcoded minimum surface covering in-place\n\
         vs -c, -k, -f, error behaviour (missing input, refuse-without-force, corrupt input),\n\
         and -t/-l — runs ours and the rival in isolated sandboxes and diffs exit code, stdout,\n\
         stderr shape, created/removed/modified files, permission bits, and roundtrip\n\
         correctness. Statuses: MATCH / DIVERGENT (a real unreasoned difference) / DECLARED\n\
         (matches a --declared exception, reason required, min 20 chars) / ERROR (instrument\n\
         failure, never a product finding) / OURS-UNAVAILABLE / RIVAL-UNAVAILABLE.\n\
         \n\
         Emits DIR/dropin.json (provenance+cells), DIR/dropin.tsv, DIR/summary.txt, and prints\n\
         the human summary (every DIVERGENT cell named with its exact diff). Resumable per cell\n\
         via DIR/cells/*.json; a cached DIVERGENT or ERROR is ALWAYS re-measured on resume.\n\
         Exit code: nonzero iff any cell is DIVERGENT or ERROR."
    );
    ExitCode::from(2)
}

fn run_cmd(args: &[String]) -> ExitCode {
    let Some(ours) = cli_flag(args, "--ours") else {
        eprintln!("dropin: --ours PATH is required");
        return usage();
    };
    let rival_strs = cli_multi(args, "--rival");
    if rival_strs.is_empty() {
        eprintln!("dropin: need at least one --rival name=CMD");
        return usage();
    }
    let mut rivals = Vec::new();
    for s in &rival_strs {
        match crate::levelsweep::parse_rival(s) {
            Ok(r) => rivals.push(r),
            Err(e) => {
                eprintln!("dropin: {e}");
                return ExitCode::from(2);
            }
        }
    }
    let fixture_strs = cli_multi(args, "--fixture");
    if fixture_strs.is_empty() {
        eprintln!("dropin: need at least one --fixture FILE");
        return usage();
    }
    let fixtures: Vec<PathBuf> = fixture_strs.iter().map(PathBuf::from).collect();
    let Some(out) = cli_flag(args, "--out") else {
        eprintln!("dropin: --out DIR is required");
        return usage();
    };
    let oracle_gzip = cli_flag(args, "--oracle-gzip")
        .unwrap_or("gzip")
        .to_string();
    let declared = match load_declared(cli_flag(args, "--declared")) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("dropin: {e}");
            return ExitCode::FAILURE;
        }
    };

    let cfg = DropinConfig {
        ours: ours.to_string(),
        rivals,
        fixtures,
        out_dir: PathBuf::from(out),
        oracle_gzip,
        declared,
    };

    let artifact = match run_dropin(&cfg) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("dropin: FAIL {e}");
            return ExitCode::FAILURE;
        }
    };

    let json_path = cfg.out_dir.join("dropin.json");
    match serde_json::to_string_pretty(&artifact) {
        Ok(js) => {
            if let Err(e) = fs::write(&json_path, js) {
                eprintln!("dropin: WARN write {}: {e}", json_path.display());
            }
        }
        Err(e) => eprintln!("dropin: WARN serialize: {e}"),
    }
    let tsv_path = cfg.out_dir.join("dropin.tsv");
    if let Err(e) = write_tsv(&artifact.cells, &tsv_path) {
        eprintln!("dropin: WARN {e}");
    }
    let summary = render_summary(&artifact.provenance, &artifact.cells);
    let summary_path = cfg.out_dir.join("summary.txt");
    let _ = fs::write(&summary_path, &summary);

    print!("{summary}");
    println!(
        "dropin: wrote {} + {} + {}",
        json_path.display(),
        tsv_path.display(),
        summary_path.display()
    );

    if artifact
        .cells
        .iter()
        .any(|c| c.status == "DIVERGENT" || c.status == "ERROR")
    {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn report_cmd(args: &[String]) -> ExitCode {
    let dirs = cli_multi(args, "--out");
    if dirs.is_empty() {
        eprintln!("dropin report: need at least one --out DIR");
        return usage();
    }
    let mut shas: Vec<(String, Option<String>)> = Vec::new();
    let mut all_cells = Vec::new();
    let mut first_provenance: Option<DropinProvenance> = None;
    for d in &dirs {
        let dp = Path::new(d);
        let meta = read_meta(dp);
        let sha = meta.as_ref().and_then(|m| m.ours_sha256.clone());
        shas.push((d.clone(), sha));
        let path = dp.join("dropin.json");
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("dropin report: read {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
        };
        let artifact: DropinArtifact = match serde_json::from_str(&text) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("dropin report: parse {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
        };
        if first_provenance.is_none() {
            first_provenance = Some(artifact.provenance.clone());
        }
        all_cells.extend(artifact.cells);
    }

    let distinct: Vec<&Option<String>> = {
        let mut v: Vec<&Option<String>> = shas.iter().map(|(_, s)| s).collect();
        v.sort();
        v.dedup();
        v
    };
    if distinct.len() > 1 {
        eprintln!(
            "dropin report: REFUSED — {} dirs carry DIFFERENT ours shas, merging would stitch \
             cells from different binaries into one census:",
            dirs.len()
        );
        for (d, sha) in &shas {
            eprintln!(
                "  {d}: ours_sha256={}",
                sha.as_deref().unwrap_or("UNPROVENANCED")
            );
        }
        return ExitCode::FAILURE;
    }

    let Some(provenance) = first_provenance else {
        eprintln!("dropin report: no dirs produced a provenance block");
        return ExitCode::FAILURE;
    };
    let summary = render_summary(&provenance, &all_cells);
    print!("{summary}");

    if all_cells
        .iter()
        .any(|c| c.status == "DIVERGENT" || c.status == "ERROR")
    {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

pub fn cmd(args: &[String]) -> ExitCode {
    match args.first().map(|s| s.as_str()) {
        Some("selftest") => selftest(),
        Some("report") => report_cmd(&args[1..]),
        _ => run_cmd(args),
    }
}

// ---------------------------------------------------------------------------
// Gate-0 selftest
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

    // -- 1. classify_status truth table (pure, no I/O) -----------------------
    check(
        "classify: run_error -> ERROR regardless of anything else",
        classify_status(true, true, true, true, 0) == "ERROR",
    );
    check(
        "classify: rival unavailable -> RIVAL-UNAVAILABLE",
        classify_status(true, false, false, false, 0) == "RIVAL-UNAVAILABLE",
    );
    check(
        "classify: ours unavailable (rival available) -> OURS-UNAVAILABLE",
        classify_status(false, true, false, false, 0) == "OURS-UNAVAILABLE",
    );
    check(
        "classify: zero diffs -> MATCH",
        classify_status(true, true, false, false, 0) == "MATCH",
    );
    check(
        "classify: nonzero diffs, no declared match -> DIVERGENT",
        classify_status(true, true, false, false, 3) == "DIVERGENT",
    );
    check(
        "classify: nonzero diffs, WITH declared match -> DECLARED (visible, capped, never hidden)",
        classify_status(true, true, false, true, 3) == "DECLARED",
    );
    check(
        "classify precedence: RIVAL-UNAVAILABLE beats a would-be MATCH",
        classify_status(true, false, false, false, 0) == "RIVAL-UNAVAILABLE",
    );

    // -- 2. observation_diffs truth table (pure, synthetic Observations) -----
    let base = || Observation {
        exit_code: Some(0),
        success: true,
        stdout_len: 10,
        stdout_sha256: "abc".to_string(),
        stderr_empty: true,
        stderr_first_line: String::new(),
        created: vec!["f.gz".to_string()],
        removed: vec!["f".to_string()],
        modified: vec![],
        created_modes: BTreeMap::from([("f.gz".to_string(), 0o640)]),
        roundtrip_ok: Some(true),
        semantic_ok: None,
    };
    check(
        "diffs: identical observations -> zero diffs",
        observation_diffs(Kind::Compress, &base(), &base()).is_empty(),
    );
    {
        let mut r = base();
        r.success = false;
        r.exit_code = Some(1);
        let d = observation_diffs(Kind::Compress, &base(), &r);
        check(
            "diffs: exit-code class differs -> flagged",
            d.iter().any(|s| s.contains("exit-code class differs")),
        );
    }
    {
        let mut r = base();
        r.stderr_empty = false;
        r.stderr_first_line = "warning: something".to_string();
        let d = observation_diffs(Kind::Compress, &base(), &r);
        check(
            "diffs: stderr shape differs -> flagged",
            d.iter().any(|s| s.contains("stderr shape differs")),
        );
    }
    {
        let mut r = base();
        r.created = vec![];
        let d = observation_diffs(Kind::Compress, &base(), &r);
        check(
            "diffs: created-file set differs -> flagged",
            d.iter().any(|s| s.contains("created-file set differs")),
        );
    }
    {
        let mut r = base();
        r.created_modes = BTreeMap::from([("f.gz".to_string(), 0o644)]);
        let d = observation_diffs(Kind::Compress, &base(), &r);
        check(
            "diffs: created-file permission bits differ -> flagged",
            d.iter().any(|s| s.contains("permission bits differ")),
        );
    }
    {
        let mut r = base();
        r.roundtrip_ok = Some(false);
        let d = observation_diffs(Kind::Compress, &base(), &r);
        check(
            "diffs (Compress): roundtrip correctness differs -> flagged",
            d.iter()
                .any(|s| s.contains("roundtrip correctness differs")),
        );
        let d2 = observation_diffs(Kind::Decompress, &base(), &r);
        check(
            "diffs (Decompress): correctness differs -> flagged",
            d2.iter().any(|s| s.contains("correctness differs")),
        );
    }
    {
        let mut o = base();
        o.roundtrip_ok = Some(false);
        let mut r = base();
        r.roundtrip_ok = Some(false);
        let d = observation_diffs(Kind::Compress, &o, &r);
        check(
            "diffs: BOTH arms fail roundtrip (shared defect) -> still flagged, not hidden",
            d.iter().any(|s| s.contains("shared defect")),
        );
    }
    {
        let mut o = base();
        o.semantic_ok = Some(true);
        let mut r = base();
        r.semantic_ok = Some(false);
        let d = observation_diffs(Kind::Inspect, &o, &r);
        check(
            "diffs (Inspect): semantic check differs (e.g. -l wrong size) -> flagged",
            d.iter()
                .any(|s| s.contains("semantic content check differs")),
        );
    }
    {
        // Same success CLASS (both nonzero) but a DIFFERENT exact exit code —
        // e.g. real gzip's WARNING(2) on a directory input vs an ERROR(1)
        // class — must still be flagged even though the boolean-success
        // check above cannot see it.
        let mut o = base();
        o.success = false;
        o.exit_code = Some(2);
        let mut r = base();
        r.success = false;
        r.exit_code = Some(1);
        let d = observation_diffs(Kind::ErrorExpected, &o, &r);
        check(
            "diffs: same success class, DIFFERENT exact exit code -> flagged",
            d.iter()
                .any(|s| s.contains("exit code differs despite same success class")),
        );
        let mut r2 = base();
        r2.success = false;
        r2.exit_code = Some(2);
        let mut o2 = base();
        o2.success = false;
        o2.exit_code = Some(2);
        let d2 = observation_diffs(Kind::ErrorExpected, &o2, &r2);
        check(
            "diffs: same success class, SAME exact exit code -> not flagged by exit-code check",
            !d2.iter()
                .any(|s| s.contains("exit code differs despite same success class")),
        );
    }

    // -- 2b. New fixture-kind construction checks (real I/O, no process spawn) -
    {
        let sf = synth_spaces_unicode_fixture();
        check(
            "synth fixture (kind 4): name has a space",
            sf.name.contains(' '),
        );
        check(
            "synth fixture (kind 4): name has a non-ASCII character",
            !sf.name.is_ascii(),
        );
        let gf = synth_already_gz_fixture();
        check(
            "synth fixture (kind 5): name already ends in .gz",
            gf.name.ends_with(".gz"),
        );
        check(
            "synth fixture (kind 5): content is PLAIN (not a real gzip stream — no 1f8b magic)",
            !(gf.bytes.len() >= 2 && gf.bytes[0] == 0x1f && gf.bytes[1] == 0x8b),
        );
    }
    {
        let tmp = std::env::temp_dir().join(format!(
            "fulcrum-dropin-fixturekind-st-{}-{}",
            std::process::id(),
            SANDBOX_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&tmp);
        let _ = fs::create_dir_all(&tmp);
        let dummy = Fixture {
            name: "kindprobe".to_string(),
            bytes: b"hello dropin fixture kinds\n".to_vec(),
            sha256: String::new(),
        };
        let oracle = resolve_ours_binary("gzip");

        // kind 1: directory.
        let ok_dir = setup_directory(&tmp, &dummy, Path::new("gzip")).is_ok();
        check(
            "setup_directory: succeeds and creates an actual directory",
            ok_dir && tmp.join(&dummy.name).is_dir(),
        );
        let _ = fs::remove_dir_all(tmp.join(&dummy.name));

        // kind 2: broken symlink.
        let symfx = Fixture {
            name: "kindprobe-symlink".to_string(),
            ..dummy.clone()
        };
        let ok_sym = setup_broken_symlink(&tmp, &symfx, Path::new("gzip")).is_ok();
        let sym_path = tmp.join(&symfx.name);
        let is_symlink = fs::symlink_metadata(&sym_path)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);
        let target_resolves = fs::metadata(&sym_path).is_ok();
        check(
            "setup_broken_symlink: creates a real symlink whose target does NOT resolve",
            ok_sym && is_symlink && !target_resolves,
        );
        let _ = fs::remove_file(&sym_path);

        // kind 3: mode 000.
        let m0fx = Fixture {
            name: "kindprobe-mode000".to_string(),
            ..dummy.clone()
        };
        let ok_m0 = setup_mode000(&tmp, &m0fx, Path::new("gzip")).is_ok();
        let m0_path = tmp.join(&m0fx.name);
        let mode_is_zero = fs::metadata(&m0_path)
            .map(|m| m.permissions().mode() & 0o777 == 0)
            .unwrap_or(false);
        check(
            "setup_mode000: creates a file whose mode really is 0",
            ok_m0 && mode_is_zero,
        );
        // Mode-000 cleanup gate: harden-then-remove must succeed without
        // sudo/chmod from outside, on a sandbox actually containing a
        // mode-000 leaf file.
        harden_permissions_for_removal(&tmp);
        let removed_ok = fs::remove_dir_all(&tmp).is_ok();
        check(
            "mode-000 cleanup: harden_permissions_for_removal + remove_dir_all succeeds on a real mode-000 file",
            removed_ok,
        );
        let _ = fs::create_dir_all(&tmp); // recreate for the checks below

        match &oracle {
            None => println!(
                "  NOTE dropin: oracle-dependent fixture-kind checks skipped (no `gzip` on PATH)"
            ),
            Some(gzip_bin) => {
                // kind 9: hardlink.
                let hlfx = Fixture {
                    name: "kindprobe-hardlink".to_string(),
                    ..dummy.clone()
                };
                let ok_hl = setup_hardlink(&tmp, &hlfx, gzip_bin).is_ok();
                let hl_nlink = fs::metadata(tmp.join(&hlfx.name))
                    .map(|m| m.nlink())
                    .unwrap_or(0);
                check(
                    "setup_hardlink: the fixture file really has nlink() > 1",
                    ok_hl && hl_nlink > 1,
                );

                // kind 6: multi-member.
                let mmfx = Fixture {
                    name: "kindprobe-multimember".to_string(),
                    ..dummy.clone()
                };
                let ok_mm = setup_multi_member_gz(&tmp, &mmfx, gzip_bin).is_ok();
                let mm_bytes = fs::read(tmp.join(format!("{}.gz", mmfx.name))).unwrap_or_default();
                let magic_count = mm_bytes
                    .windows(2)
                    .filter(|w| w[0] == 0x1f && w[1] == 0x8b)
                    .count();
                let mm_decoded = oracle_decompress(gzip_bin, &mm_bytes).unwrap_or_default();
                let mut mm_expected = mmfx.bytes.clone();
                mm_expected.extend_from_slice(&mmfx.bytes);
                check(
                    "setup_multi_member_gz: really has (at least) two gzip magic headers",
                    ok_mm && magic_count >= 2,
                );
                check(
                    "setup_multi_member_gz: oracle decompresses to the DOUBLED (concatenated) plaintext",
                    mm_decoded == mm_expected,
                );

                // kind 7: truncated.
                let trfx = Fixture {
                    name: "kindprobe-truncated".to_string(),
                    ..dummy.clone()
                };
                let full_len = canonical_gz_bytes(gzip_bin, &trfx.bytes)
                    .map(|b| b.len())
                    .unwrap_or(0);
                let ok_tr = setup_truncated_gz(&tmp, &trfx, gzip_bin).is_ok();
                let tr_bytes = fs::read(tmp.join(format!("{}.gz", trfx.name))).unwrap_or_default();
                check(
                    "setup_truncated_gz: really shorter than a valid stream",
                    ok_tr && !tr_bytes.is_empty() && tr_bytes.len() < full_len,
                );
                let tr_test_ok = Command::new(gzip_bin)
                    .arg("-t")
                    .arg(tmp.join(format!("{}.gz", trfx.name)))
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(true);
                check(
                    "setup_truncated_gz: the real oracle gzip actually FAILS -t on it",
                    !tr_test_ok,
                );

                // kind 8: corrupted CRC only.
                let crcfx = Fixture {
                    name: "kindprobe-corruptcrc".to_string(),
                    ..dummy.clone()
                };
                let ok_crc = setup_corrupt_gz_crc_only(&tmp, &crcfx, gzip_bin).is_ok();
                let crc_path = tmp.join(format!("{}.gz", crcfx.name));
                let crc_bytes = fs::read(&crc_path).unwrap_or_default();
                let crc_decoded = oracle_decompress(gzip_bin, &crc_bytes).unwrap_or_default();
                let crc_test_ok = Command::new(gzip_bin)
                    .arg("-t")
                    .arg(&crc_path)
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(true);
                check(
                    "setup_corrupt_gz_crc_only: body-only decode still yields the RIGHT plaintext",
                    ok_crc && crc_decoded == crcfx.bytes,
                );
                check(
                    "setup_corrupt_gz_crc_only: the real oracle gzip's CRC check actually FAILS -t on it",
                    !crc_test_ok,
                );
            }
        }
        let _ = fs::remove_dir_all(&tmp);
    }

    // -- 3. Declared: wildcard matching + MIN_DECLARED_REASON gate -----------
    let long_reason = "known: pigz -l column format legitimately differs from gzippy's".to_string();
    check(
        "declared reason length: 20-char minimum is enforced",
        long_reason.len() >= MIN_DECLARED_REASON,
    );
    let d = Declared {
        rival: "*".to_string(),
        scenario: "list_mode".to_string(),
        fixture: "*".to_string(),
        reason: long_reason.clone(),
    };
    check(
        "Declared: wildcard rival + exact scenario matches any rival on that scenario",
        d.matches("gzip", "list_mode", "anything.bin") && d.matches("pigz", "list_mode", "x"),
    );
    check(
        "Declared: does not match a different scenario",
        !d.matches("gzip", "test_valid", "anything.bin"),
    );
    check(
        "validate_declared: accepts a reason >= MIN_DECLARED_REASON",
        validate_declared(&[d.clone()]).is_ok(),
    );
    check(
        "validate_declared: rejects a reason < MIN_DECLARED_REASON",
        validate_declared(&[Declared {
            rival: "*".to_string(),
            scenario: "*".to_string(),
            fixture: "*".to_string(),
            reason: "too short".to_string(),
        }])
        .is_err(),
    );

    // -- 3b. Declared PRECISION guard: an over-broad (wildcarded) entry is
    // DETECTABLY over-broad by a straightforward match-count assertion — the
    // technique `declared.json`'s own review must apply so a future edit that
    // accidentally widens a field (e.g. `fixture` narrowed to one name,
    // loosened back to "*") doesn't silently start absorbing real,
    // unrelated divergences it was never meant to cover ("a declared entry
    // that silently absorbs a future real divergence is worse than no gate
    // at all", per the task brief).
    {
        let all_fixtures = [
            "empty-0B",
            "one-1B",
            "page-4095B",
            "rand-8192B",
            "small-256B",
            "text-65536B",
            "dropin naive file 名前 with spaces.txt",
        ];
        let exact = Declared {
            rival: "pigz".to_string(),
            scenario: "refuse_overwrite_without_force".to_string(),
            fixture: "empty-0B".to_string(),
            reason: "pigz exits 1 \"skipping\"; gzip (primary drop-in target) exits 2".to_string(),
        };
        let exact_matches = all_fixtures
            .iter()
            .filter(|f| exact.matches("pigz", "refuse_overwrite_without_force", f))
            .count();
        check(
            "Declared precision: an EXACT (non-wildcard) fixture field matches only that ONE fixture",
            exact_matches == 1,
        );

        let mut broadened = exact.clone();
        broadened.fixture = star();
        let broad_matches = all_fixtures
            .iter()
            .filter(|f| broadened.matches("pigz", "refuse_overwrite_without_force", f))
            .count();
        check(
            "Declared precision: wildcarding `fixture` is DETECTABLY over-broad — matches ALL \
             fixtures, not just the intended one, and matches strictly more than the exact entry",
            broad_matches == all_fixtures.len() && broad_matches > exact_matches,
        );

        // Same guard on the `rival` axis: our real declared.json entries are
        // all pigz-specific (gzip's two divergences are FIXED, not declared)
        // — an entry accidentally wildcarding `rival` would also match gzip,
        // which must never happen for these scenarios.
        check(
            "Declared precision: an exact `rival` field does NOT also match a different rival",
            !exact.matches("gzip", "refuse_overwrite_without_force", "empty-0B"),
        );
        let mut rival_broadened = exact.clone();
        rival_broadened.rival = star();
        check(
            "Declared precision: wildcarding `rival` is DETECTABLY over-broad — now matches gzip too",
            rival_broadened.matches("gzip", "refuse_overwrite_without_force", "empty-0B"),
        );
    }

    // -- 4. shq(): real shell round-trip for a name with a space + a quote ----
    {
        let tricky = "a b'c.txt";
        let quoted = shq(tricky);
        let out = Command::new("sh")
            .arg("-c")
            .arg(format!("printf '%s' {quoted}"))
            .output();
        match out {
            Ok(o) => check(
                "shq: a filename with a space and a single quote survives sh -c as ONE token",
                String::from_utf8_lossy(&o.stdout) == tricky,
            ),
            Err(e) => println!("  NOTE dropin: shq real-shell check skipped (no /bin/sh?: {e})"),
        }
    }

    // -- 5. resume contract: DIVERGENT/ERROR always re-measured, MATCH reused
    {
        let would_reuse = |status: &str| status != "DIVERGENT" && status != "ERROR";
        check("resume contract: MATCH is reused", would_reuse("MATCH"));
        check(
            "resume contract: DECLARED is reused",
            would_reuse("DECLARED"),
        );
        check(
            "resume contract: DIVERGENT is NEVER reused (always re-measured)",
            !would_reuse("DIVERGENT"),
        );
        check(
            "resume contract: ERROR is NEVER reused (always re-measured)",
            !would_reuse("ERROR"),
        );
    }

    // -- 6. e2e: real gzip vs itself on a real scenario -> MATCH --------------
    let have_gzip = resolve_ours_binary("gzip");
    match have_gzip {
        None => println!("  NOTE dropin: e2e selftests skipped (no `gzip` on PATH)"),
        Some(gzip_bin) => {
            let gzip_abs = gzip_bin.display().to_string();
            let tmp_root = std::env::temp_dir()
                .join(format!("fulcrum-dropin-selftest-{}", std::process::id()));
            let _ = fs::remove_dir_all(&tmp_root);
            let _ = fs::create_dir_all(&tmp_root);
            let fx = Fixture {
                name: "st-fixture.txt".to_string(),
                bytes: b"the quick brown fox jumps over the lazy dog\n".repeat(50),
                sha256: String::new(),
            };
            let mut fx = fx;
            fx.sha256 = hex32(&sha256(&fx.bytes));

            let scenario_list = scenarios();
            let by_name = |n: &str| scenario_list.iter().find(|s| s.name == n).unwrap();

            // gzip vs itself, compress_inplace -> MATCH (A/A of the identical
            // binary must never show a diff).
            {
                let s = by_name("compress_inplace");
                let o = capture(&gzip_abs, s, &fx, &tmp_root, &gzip_bin).unwrap();
                let r = capture(&gzip_abs, s, &fx, &tmp_root, &gzip_bin).unwrap();
                let diffs = observation_diffs(s.kind, &o, &r);
                check(
                    "e2e: real gzip vs itself, compress_inplace -> zero diffs (A/A sanity)",
                    diffs.is_empty(),
                );
                check(
                    "e2e: compress_inplace actually removed the original and created the .gz",
                    o.removed == vec![fx.name.clone()]
                        && o.created == vec![format!("{}.gz", fx.name)],
                );
                check(
                    "e2e: compress_inplace output roundtrips to the original plaintext",
                    o.roundtrip_ok == Some(true),
                );
            }

            // gzip vs itself, refuse_overwrite_without_force -> both refuse,
            // stale .gz left untouched -> MATCH.
            {
                let s = by_name("refuse_overwrite_without_force");
                let o = capture(&gzip_abs, s, &fx, &tmp_root, &gzip_bin).unwrap();
                let r = capture(&gzip_abs, s, &fx, &tmp_root, &gzip_bin).unwrap();
                check(
                    "e2e: refuse-without-force — real gzip actually exits nonzero",
                    !o.success,
                );
                check(
                    "e2e: refuse-without-force — nothing created/removed/modified (stale .gz untouched)",
                    o.created.is_empty() && o.removed.is_empty() && o.modified.is_empty(),
                );
                let diffs = observation_diffs(s.kind, &o, &r);
                check(
                    "e2e: refuse_overwrite_without_force, gzip vs itself -> zero diffs",
                    diffs.is_empty(),
                );
            }

            // gzip vs itself, force_overwrite -> succeeds, stale .gz replaced.
            {
                let s = by_name("force_overwrite");
                let o = capture(&gzip_abs, s, &fx, &tmp_root, &gzip_bin).unwrap();
                check(
                    "e2e: force_overwrite — real gzip succeeds and replaces the stale .gz",
                    o.success && o.modified == vec![format!("{}.gz", fx.name)],
                );
                check(
                    "e2e: force_overwrite output roundtrips correctly",
                    o.roundtrip_ok == Some(true),
                );
            }

            // gzip vs itself, test_corrupt -> both fail loudly, identical.
            {
                let s = by_name("test_corrupt");
                let o = capture(&gzip_abs, s, &fx, &tmp_root, &gzip_bin).unwrap();
                let r = capture(&gzip_abs, s, &fx, &tmp_root, &gzip_bin).unwrap();
                check(
                    "e2e: test_corrupt — real gzip -t fails on a corrupted stream",
                    !o.success,
                );
                let diffs = observation_diffs(s.kind, &o, &r);
                check(
                    "e2e: test_corrupt, gzip vs itself -> zero diffs",
                    diffs.is_empty(),
                );
            }

            // -- DELIBERATE DIVERGENCE: a broken "rival" that just cats the
            // compressed bytes instead of decompressing them on
            // decompress_stdout. Confirms the instrument actually CATCHES a
            // real behavioural difference, and that a matching Declared entry
            // caps it to DECLARED rather than hiding or still failing it.
            {
                let broken_path = tmp_root.join("broken-decompressor.sh");
                fs::write(&broken_path, "#!/bin/sh\ncat \"$2\"\n").unwrap();
                let mut perm = fs::metadata(&broken_path).unwrap().permissions();
                perm.set_mode(0o755);
                fs::set_permissions(&broken_path, perm).unwrap();
                let broken_abs = broken_path.display().to_string();

                let s = by_name("decompress_stdout");
                let ours_obs = capture(&gzip_abs, s, &fx, &tmp_root, &gzip_bin).unwrap();
                let rival_obs = capture(&broken_abs, s, &fx, &tmp_root, &gzip_bin).unwrap();
                let diffs = observation_diffs(s.kind, &ours_obs, &rival_obs);
                check(
                    "e2e DIVERGENCE: a broken decompressor is CAUGHT (roundtrip mismatch flagged)",
                    !diffs.is_empty(),
                );
                let status_no_decl = classify_status(true, true, false, false, diffs.len());
                check(
                    "e2e DIVERGENCE: classify_status with no Declared entry -> DIVERGENT",
                    status_no_decl == "DIVERGENT",
                );
                let decl = Declared {
                    rival: "broken".to_string(),
                    scenario: "decompress_stdout".to_string(),
                    fixture: fx.name.clone(),
                    reason: "synthetic selftest fixture — deliberately broken decompressor"
                        .to_string(),
                };
                let matched = decl.matches("broken", s.name, &fx.name);
                let status_with_decl = classify_status(true, true, false, matched, diffs.len());
                check(
                    "e2e DIVERGENCE: a matching Declared entry caps it to DECLARED (visible, not hidden)",
                    matched && status_with_decl == "DECLARED",
                );
            }

            // -- New fixture kinds, e2e via real gzip vs itself: proves the
            // "shared incumbent failure is MATCH, not a bug" contract for
            // each new scenario, same pattern as `test_corrupt` above.
            {
                let s = by_name("directory_input");
                let o = capture(&gzip_abs, s, &fx, &tmp_root, &gzip_bin).unwrap();
                let r = capture(&gzip_abs, s, &fx, &tmp_root, &gzip_bin).unwrap();
                check(
                    "e2e: directory_input — real gzip actually fails on a bare directory arg",
                    !o.success,
                );
                check(
                    "e2e: directory_input — nothing created/removed/modified (gzip touches nothing)",
                    o.created.is_empty() && o.removed.is_empty() && o.modified.is_empty(),
                );
                let diffs = observation_diffs(s.kind, &o, &r);
                check(
                    "e2e: directory_input, gzip vs itself -> zero diffs (shared behavior is MATCH)",
                    diffs.is_empty(),
                );
            }
            {
                let s = by_name("hardlink_input");
                let o = capture(&gzip_abs, s, &fx, &tmp_root, &gzip_bin).unwrap();
                let r = capture(&gzip_abs, s, &fx, &tmp_root, &gzip_bin).unwrap();
                check(
                    "e2e: hardlink_input — real gzip actually refuses a file with nlink()>1",
                    !o.success,
                );
                let diffs = observation_diffs(s.kind, &o, &r);
                check(
                    "e2e: hardlink_input, gzip vs itself -> zero diffs (shared refuse-behavior is MATCH)",
                    diffs.is_empty(),
                );
            }
            {
                let s = by_name("multi_member_decompress");
                let o = capture(&gzip_abs, s, &fx, &tmp_root, &gzip_bin).unwrap();
                let r = capture(&gzip_abs, s, &fx, &tmp_root, &gzip_bin).unwrap();
                check(
                    "e2e: multi_member_decompress — real gzip succeeds and produces the DOUBLED plaintext",
                    o.success && o.roundtrip_ok == Some(true),
                );
                let diffs = observation_diffs(s.kind, &o, &r);
                check(
                    "e2e: multi_member_decompress, gzip vs itself -> zero diffs",
                    diffs.is_empty(),
                );
            }
            {
                // Both test_truncated AND test_corrupt_crc are real error
                // classes a real gzip ALSO hits — the "shared incumbent
                // failure is MATCH, not a bug" contract, exercised twice more.
                for scen_name in ["test_truncated", "test_corrupt_crc"] {
                    let s = by_name(scen_name);
                    let o = capture(&gzip_abs, s, &fx, &tmp_root, &gzip_bin).unwrap();
                    let r = capture(&gzip_abs, s, &fx, &tmp_root, &gzip_bin).unwrap();
                    check(
                        &format!("e2e: {scen_name} — real gzip actually fails -t on it"),
                        !o.success,
                    );
                    let diffs = observation_diffs(s.kind, &o, &r);
                    check(
                        &format!("e2e: {scen_name}, gzip vs itself -> zero diffs (shared failure is MATCH)"),
                        diffs.is_empty(),
                    );
                }
            }

            // -- Task-3 fix: "both arms correctly produce NO output" must be
            // MATCH, not a manufactured "fails to roundtrip" false positive
            // (dropin-coverage-gap census: fixture `already-named.gz` x
            // `compress_inplace`/`compress_inplace_keep`, BOTH gzip and pigz
            // rivals — established by direct execution that real gzip prints
            // "already has .gz suffix -- unchanged", exit 0, touches nothing).
            {
                let gz_fixture = synth_already_gz_fixture();
                for scen_name in ["compress_inplace", "compress_inplace_keep"] {
                    let s = by_name(scen_name);
                    let o = capture(&gzip_abs, s, &gz_fixture, &tmp_root, &gzip_bin).unwrap();
                    let r = capture(&gzip_abs, s, &gz_fixture, &tmp_root, &gzip_bin).unwrap();
                    check(
                        &format!(
                            "e2e: {scen_name} on an already-.gz fixture — real gzip declines \
                             (no-op, exit 0, touches nothing)"
                        ),
                        o.success
                            && o.created.is_empty()
                            && o.removed.is_empty()
                            && o.modified.is_empty(),
                    );
                    check(
                        &format!(
                            "e2e: {scen_name} no-op on already-.gz fixture — roundtrip_ok is \
                             N/A (None), NOT Some(false)"
                        ),
                        o.roundtrip_ok.is_none(),
                    );
                    let diffs = observation_diffs(s.kind, &o, &r);
                    check(
                        &format!(
                            "e2e: {scen_name}, gzip vs itself on already-.gz fixture -> zero \
                             diffs (both-decline is MATCH, not a harness false positive)"
                        ),
                        diffs.is_empty(),
                    );
                }
                // Same contract holds against pigz (which ALSO declines,
                // "skipping: X ends with .gz", confirmed by execution) — the
                // fix is rival-agnostic because it lives in the pure
                // classification core, not in any gzip-specific special case.
                if let Some(pigz_bin) = resolve_ours_binary("pigz") {
                    let pigz_abs = pigz_bin.display().to_string();
                    for scen_name in ["compress_inplace", "compress_inplace_keep"] {
                        let s = by_name(scen_name);
                        let o = capture(&pigz_abs, s, &gz_fixture, &tmp_root, &gzip_bin).unwrap();
                        let r = capture(&pigz_abs, s, &gz_fixture, &tmp_root, &gzip_bin).unwrap();
                        check(
                            &format!(
                                "e2e: {scen_name} on an already-.gz fixture — real pigz ALSO \
                                 declines (no-op, exit 0, touches nothing)"
                            ),
                            o.success
                                && o.created.is_empty()
                                && o.removed.is_empty()
                                && o.modified.is_empty(),
                        );
                        let diffs = observation_diffs(s.kind, &o, &r);
                        check(
                            &format!(
                                "e2e: {scen_name}, pigz vs itself on already-.gz fixture -> zero \
                                 diffs (both-decline is MATCH against pigz too)"
                            ),
                            diffs.is_empty(),
                        );
                    }
                } else {
                    println!("  NOTE dropin: pigz-side already-.gz no-op checks skipped (no `pigz` on PATH)");
                }
            }

            // compute_checks(Kind::Compress, ...) unit-level guard: a
            // SUCCESSFUL compress with truly empty output (no stdout, no
            // `<name>.gz` written) is a legitimate no-op -> (None, None).
            // This must NOT be over-corrected into masking a real defect:
            // a claimed failure, or a claimed SUCCESS with non-empty GARBAGE
            // output, must both still report Some(false).
            {
                let s = by_name("compress_inplace");
                let cc_tmp = std::env::temp_dir().join(format!(
                    "fulcrum-dropin-cc-st-{}-{}",
                    std::process::id(),
                    SANDBOX_SEQ.fetch_add(1, Ordering::Relaxed)
                ));
                let _ = fs::remove_dir_all(&cc_tmp);
                let _ = fs::create_dir_all(&cc_tmp);
                let (rt_noop, _) = compute_checks(s, &fx, &cc_tmp, b"", true, &gzip_bin).unwrap();
                check(
                    "compute_checks: success=true + truly empty output -> roundtrip_ok=None \
                     (no-op), not Some(false)",
                    rt_noop.is_none(),
                );
                let (rt_fail, _) = compute_checks(s, &fx, &cc_tmp, b"", false, &gzip_bin).unwrap();
                check(
                    "compute_checks: success=false -> still Some(false) (a real failure is \
                     never masked as N/A)",
                    rt_fail == Some(false),
                );
                let (rt_garbage, _) =
                    compute_checks(s, &fx, &cc_tmp, b"not a real gzip stream", true, &gzip_bin)
                        .unwrap();
                check(
                    "compute_checks: success=true + non-empty GARBAGE output -> still \
                     Some(false), never masked",
                    rt_garbage == Some(false),
                );
                let _ = fs::remove_dir_all(&cc_tmp);
            }

            let _ = fs::remove_dir_all(&tmp_root);
        }
    }

    // -- 7. run_dropin: resume-refusal on a different ours sha ----------------
    {
        let run_base =
            std::env::temp_dir().join(format!("fulcrum-dropin-run-st-{}", std::process::id()));
        let _ = fs::remove_dir_all(&run_base);
        let _ = fs::create_dir_all(&run_base);
        write_meta(
            &run_base,
            &SweepMeta {
                ours_tmpl: "true".to_string(),
                ours_bin: None,
                ours_sha256: Some("sha-OLD".to_string()),
                created_unix: unix_now(),
                attested: false,
            },
        )
        .unwrap();
        if let Some(true_bin) = resolve_ours_binary("true") {
            let _ = true_bin;
            let refuse_cfg = DropinConfig {
                ours: "true".to_string(),
                rivals: vec![crate::levelsweep::parse_rival("gzip=gzip -c {input}").unwrap()],
                fixtures: vec![],
                out_dir: run_base.clone(),
                oracle_gzip: "gzip".to_string(),
                declared: vec![],
            };
            check(
                "run_dropin: refuses to resume a DIR stamped with a different ours sha",
                run_dropin(&refuse_cfg).is_err(),
            );
        } else {
            println!("  SKIP run_dropin resume-refusal (could not resolve a `true` binary here)");
        }
        let _ = fs::remove_dir_all(&run_base);
    }

    // -- 8. report merge: refuses across different ours shas ------------------
    {
        let base_dir =
            std::env::temp_dir().join(format!("fulcrum-dropin-rpt-st-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base_dir);
        let mk_dir = |name: &str, sha: &str| -> PathBuf {
            let d = base_dir.join(name);
            let _ = fs::create_dir_all(&d);
            let _ = write_meta(
                &d,
                &SweepMeta {
                    ours_tmpl: "synth".to_string(),
                    ours_bin: None,
                    ours_sha256: Some(sha.to_string()),
                    created_unix: unix_now(),
                    attested: false,
                },
            );
            let artifact = DropinArtifact {
                provenance: DropinProvenance {
                    fulcrum_commit: String::new(),
                    ours_cmd: "synth".to_string(),
                    ours_bin: None,
                    ours_sha256: Some(sha.to_string()),
                    ours_commit: None,
                    host: "test".to_string(),
                    rivals: vec![],
                    fixtures: vec![],
                    oracle_gzip: "gzip".to_string(),
                    created_unix: 0,
                },
                cells: vec![],
            };
            let _ = fs::write(
                d.join("dropin.json"),
                serde_json::to_string_pretty(&artifact).unwrap(),
            );
            d
        };
        let dir_a1 = mk_dir("a1", "sha-AAAA");
        let dir_a2 = mk_dir("a2", "sha-AAAA");
        let dir_b = mk_dir("b", "sha-BBBB");

        check(
            "report: merging two dirs with the SAME ours sha succeeds",
            report_cmd(&[
                "--out".to_string(),
                dir_a1.display().to_string(),
                "--out".to_string(),
                dir_a2.display().to_string(),
            ]) == ExitCode::SUCCESS,
        );
        check(
            "report: merging two dirs with DIFFERENT ours shas is REFUSED",
            report_cmd(&[
                "--out".to_string(),
                dir_a1.display().to_string(),
                "--out".to_string(),
                dir_b.display().to_string(),
            ]) == ExitCode::FAILURE,
        );
        let _ = fs::remove_dir_all(&base_dir);
    }

    let p = pass.get();
    let f = fail.get();
    println!(
        "DROPIN_SELFTEST={} pass={p} fail={f}",
        if f == 0 { "PASS" } else { "FAIL" }
    );
    if f == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_status_exhaustive() {
        assert_eq!(classify_status(true, true, true, false, 5), "ERROR");
        assert_eq!(
            classify_status(true, false, false, false, 0),
            "RIVAL-UNAVAILABLE"
        );
        assert_eq!(
            classify_status(false, true, false, false, 0),
            "OURS-UNAVAILABLE"
        );
        assert_eq!(classify_status(true, true, false, false, 0), "MATCH");
        assert_eq!(classify_status(true, true, false, false, 1), "DIVERGENT");
        assert_eq!(classify_status(true, true, false, true, 1), "DECLARED");
    }

    #[test]
    fn shq_roundtrips_via_real_shell() {
        let tricky = "weird name's.txt";
        let out = Command::new("sh")
            .arg("-c")
            .arg(format!("printf '%s' {}", shq(tricky)))
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout), tricky);
    }

    #[test]
    fn declared_wildcard_matching() {
        let d = Declared {
            rival: "*".to_string(),
            scenario: "list_mode".to_string(),
            fixture: "*".to_string(),
            reason: "column format legitimately differs across tools".to_string(),
        };
        assert!(d.matches("gzip", "list_mode", "x"));
        assert!(d.matches("pigz", "list_mode", "y"));
        assert!(!d.matches("gzip", "test_valid", "x"));
    }

    #[test]
    fn validate_declared_min_reason_length() {
        assert!(validate_declared(&[Declared {
            rival: "*".to_string(),
            scenario: "*".to_string(),
            fixture: "*".to_string(),
            reason: "short".to_string(),
        }])
        .is_err());
        assert!(validate_declared(&[Declared {
            rival: "*".to_string(),
            scenario: "*".to_string(),
            fixture: "*".to_string(),
            reason: "a sufficiently long, argued reason".to_string(),
        }])
        .is_ok());
    }

    #[test]
    fn dropin_cell_json_roundtrip() {
        let cell = DropinCell {
            rival: "gzip".to_string(),
            scenario: "compress_inplace".to_string(),
            fixture: "x".to_string(),
            kind: "Compress".to_string(),
            status: "DIVERGENT".to_string(),
            diffs: vec!["exit-code class differs: ours=Some(1) rival=Some(0)".to_string()],
            declared_reason: None,
            ours_exit: Some(1),
            rival_exit: Some(0),
            error: None,
        };
        let js = serde_json::to_string(&cell).unwrap();
        let back: DropinCell = serde_json::from_str(&js).unwrap();
        assert_eq!(back.status, "DIVERGENT");
        assert_eq!(back.diffs.len(), 1);
    }
}
