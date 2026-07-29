# Deployment — every box runs main, verifiably

## The incident this exists for

On 2026-07-28 the authority box (**solvency**, `root@10.0.2.240`,
`/root/fulcrum`) was found running a fulcrum binary built **2026-07-13** that
LACKED `sizecensus`, `counterdiff`, `chainlat`, `ablate`, `verify` and
`wallcensus` — the instrument set had been growing for two weeks while the
box measured with the old one. Nobody could tell, because the binary carried
no provenance. The operator, not finding the tools, hand-rolled weaker bash
substitutes — one of which (a byte-count size comparison with **no roundtrip
gate**) would have scored a corrupt-but-smaller output as a WIN.

Two failure classes, two fixes, both now in the tool:

1. **You cannot detect staleness without provenance.** `build.rs` bakes the
   source commit, dirty flag, build time and origin URL into every binary.
   `fulcrum version` prints them; `fulcrum version --expect <sha>` exits
   non-zero on mismatch; every measurement artifact carries
   `fulcrum_commit`/`fulcrum_dirty` so a banked number can be audited after
   the fact.
2. **Staleness must not depend on a human remembering.** Every command
   compares its baked commit against `origin/main` at startup (cached 60 s,
   network capped at ~2.5 s, degrades to a warning offline). Measurement
   commands **REFUSE to run stale**; analysis commands self-update (pull →
   rebuild → re-exec, loudly) when no freeze is held. `--no-self-update`
   pins a reproduction against a banked commit.

## The runnable deploy (this, not prose)

From a fulcrum checkout:

```sh
# Push origin/main to a box, rebuild there, verify provenance, run Gate-0s:
make deploy BOX=root@10.0.2.240 DIR=/root/fulcrum        # solvency (authority, AMD Zen2)
make deploy BOX=root@10.0.2.199 DIR=/root/fulcrum        # trainer  (Intel LXC — valgrind box)

# Just check (no changes) — CI-able, exit code is the verdict:
make deploy-check BOX=root@10.0.2.240 DIR=/root/fulcrum
```

`make deploy` is four verifiable steps, and it is not done until all four pass:

1. clone-or-fetch the repo on the box and hard-reset to `origin/main`;
2. `cargo build --release` **on the box** (native arch, no cross-compile);
3. `fulcrum version --expect $(git ls-remote origin main)` **on the box** —
   the deployed binary itself attests the commit it was built from; a stale
   or dirty binary fails loudly here;
4. `fulcrum selftest` **on the box** — the full Gate-0 suite. An instrument
   whose refusal paths do not fire on the measuring box is not deployed,
   whatever sha it reports.

## Keeping it current without a human

The self-check makes drift self-limiting: the first fulcrum command anyone
(or any script) runs on a stale box either updates it (analysis, safe
context) or refuses with `deployed binary is N commits behind origin/main;
update before measuring` (measurement, or freeze held). A wrong number is
worse than a stale one, so the unsafe path never auto-swaps the binary —
rebuilding between the two arms of a paired A/B would silently break the
both-arms-same-binary invariant.

For belt-and-braces, put the check in the box's crontab:

```cron
17 * * * * cd /root/fulcrum && ./target/release/fulcrum version --json >> /root/fulcrum-version.log 2>&1
```

and gate any measurement session on `make deploy-check` from your laptop.

## Scope

This machinery is fulcrum-only. gzippy is the shipped product; its rules
forbid environment-driven behaviour changes and nothing here goes near it —
gzippy binaries under test are still built explicitly per arm (`ab ablate`,
`try`) and identified by sha in every artifact.
