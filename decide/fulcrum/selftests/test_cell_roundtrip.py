"""CELL round-trip — the unified contract crosses the Rust↔Python boundary.

The whole pipeline rests on one claim: a measurement that LEAVES one gate can
ENTER the next, even across languages, because both speak the SAME cell. This
suite proves it three ways:

  1. IN-PROCESS: Python mint → to_json → from_json re-derives the SAME id, and
     re-wording the prose `claim` does NOT fork the id (fingerprint excludes it).
  2. RUST-WRITES / PYTHON-READS: `fulcrum finding add` writes a JSONL row;
     Python `Cell.from_json` parses it and re-derives the IDENTICAL cell_id.
  3. PYTHON-WRITES / RUST-READS: Python `Cell.to_json` writes a findings.jsonl;
     `fulcrum finding cite` (Rust) loads it and GRANTS the citation — i.e. Rust
     parsed the Python-written row and agreed on the id.

(2)+(3) are gated on the built `fulcrum` binary; absent, they print [SKIP]
(the combined `make`/`cargo` flow builds it).
"""

import json
import os
import subprocess
import tempfile

from ..core import cell as cell_mod
from ..core.cell import Cell, Threads, mint
from ..core.pipeline import find_fulcrum_bin, repo_root
from . import Checker


def _good_cell(commit="abc1234", tier="oracle", value=247.0):
    return mint(region="ParallelSM/per-chunk-serialization",
                claim="247ms per-chunk serialization tax dominates T1",
                commit_sha=commit, corpus="silesia", arch="amd",
                threads_T=Threads.fixed(4), sink="regular-file", n=9,
                inter_run_spread=0.012, evidence_tier=tier, verdict="located",
                value=value, dimension="ms", method="removal-oracle DIS-15",
                created_utc="2026-06-13")


def run():
    check = Checker()
    print("=== fulcrum selftest: CELL round-trip (unified Rust↔Python "
          "contract) ===")

    # 1. IN-PROCESS round trip ------------------------------------------------
    c = _good_cell()
    ok, why = c.is_citable()
    check(ok, f"minted cell is citable (derived id {c.cell_id}); {why}")
    back = Cell.from_json(c.to_json())
    check(back.cell_id == c.cell_id,
          "to_json → from_json preserves the cell_id (round-trip stable)")
    check(back.to_json() == c.to_json(),
          "JSON is idempotent across a round trip (byte-stable wire form)")
    # re-wording prose must not fork the cell.
    c2 = _good_cell()
    c2.claim = "completely different wording of the same finding"
    check(c2.derive_id() == c.cell_id,
          "re-wording `claim` does NOT fork the cell_id (prose excluded from "
          "the fingerprint)")
    # tier honesty mirrors finding.rs strength().
    check(cell_mod.tier_strength("perturbation") == "STRONG"
          and cell_mod.tier_strength("source-read") == "HYPOTHESIS"
          and cell_mod.tier_strength("whole-program-attribution") == "WEAK",
          "tier→strength map mirrors finding.rs (perturbation STRONG, "
          "source-read HYPOTHESIS, whole-program WEAK)")

    bin_path = find_fulcrum_bin()
    if not bin_path:
        print("  [SKIP] fulcrum binary not built — cross-language round-trip "
              "checks skipped (run `cargo build --release`)")
        return check.finish("CELL round-trip selftest")

    repo = repo_root()
    tmp = tempfile.mkdtemp(prefix="fulcrum_cell_rt_")

    # 2. RUST WRITES, PYTHON READS -------------------------------------------
    store_a = os.path.join(tmp, "rust_written.jsonl")
    add = subprocess.run([
        bin_path, "finding", "add",
        "--region", "ParallelSM/per-chunk-serialization",
        "--claim", "247ms per-chunk serialization tax dominates T1",
        "--commit", "abc1234", "--tier", "oracle", "--corpus", "silesia",
        "--arch", "amd", "--threads", "4", "--sink", "regular-file",
        "--n", "9", "--spread", "0.012", "--verdict", "located",
        "--value", "247", "--dim", "ms", "--method", "removal-oracle DIS-15",
        "--date", "2026-06-13", "--store", store_a, "--repo", repo],
        capture_output=True, text=True, timeout=60)
    check(add.returncode == 0 and "ADDED" in add.stdout,
          f"`fulcrum finding add` (Rust) wrote a cell: {add.stdout.strip()}")
    rust_line = open(store_a).read().strip()
    rust_cell = Cell.from_json(rust_line)
    py_id = _good_cell().cell_id
    rust_id = json.loads(rust_line)["cell_id"]
    check(rust_cell.cell_id == rust_id == py_id,
          f"Rust-written row parses in Python and the cell_id MATCHES the "
          f"Python-derived id ({py_id}) — same hash in both languages")
    ok, why = rust_cell.is_citable()
    check(ok, f"Rust-written cell passes the Python citability check; {why}")

    # 3. PYTHON WRITES, RUST READS -------------------------------------------
    store_b = os.path.join(tmp, "py_written.jsonl")
    # use HEAD so the Rust git-oracle reads the cell as FRESH (citable now).
    head = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip()
    pc = mint(region="ParallelSM/per-chunk-serialization",
              claim="python-authored cell", commit_sha=head, corpus="silesia",
              arch="amd", threads_T=Threads.fixed(4), sink="regular-file", n=9,
              inter_run_spread=0.012, evidence_tier="perturbation",
              verdict="located", value=247.0, dimension="ms",
              method="pipeline", created_utc="2026-06-13")
    with open(store_b, "w") as f:
        f.write(pc.to_json() + "\n")
    cite = subprocess.run([
        bin_path, "finding", "cite", pc.cell_id, "--as", "strong",
        "--for-corpus", "silesia", "--for-arch", "amd", "--for-threads", "4",
        "--store", store_b, "--repo", repo], capture_output=True, text=True,
        timeout=60)
    check(cite.returncode == 0 and "GRANTED" in cite.stdout,
          f"`fulcrum finding cite` (Rust) loaded the PYTHON-written row and "
          f"GRANTED it — Rust agrees on the id: {cite.stdout.strip()[:80]}")

    return check.finish("CELL round-trip selftest")
