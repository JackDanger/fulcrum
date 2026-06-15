"""Locate the built `fulcrum` ELF (the dev oracle's bridge to the Rust gates).

Extracted from the now-removed `core/pipeline.py` (the subprocess-seam pipeline,
superseded by the all-Rust in-process `src/pipeline.rs`). These two helpers are
still used by the remaining Python *oracle* selftests to find the Rust binary for
cross-language fingerprint/citation checks.
"""

import os


def repo_root():
    # decide/fulcrum/core/binloc.py -> repo root is four dirs up.
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(os.path.join(here, "..", "..", ".."))


def find_fulcrum_bin():
    """$FULCRUM_BIN wins; else target/release then target/debug under the repo."""
    env = os.environ.get("FULCRUM_BIN")
    if env and os.path.exists(env):
        return env
    repo = repo_root()
    for cand in (os.path.join(repo, "target", "release", "fulcrum"),
                 os.path.join(repo, "target", "debug", "fulcrum")):
        if os.path.exists(cand):
            return cand
    return None
