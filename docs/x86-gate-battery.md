# x86 Gate Battery — the `fulcrum scaling` reconnect runbook

**Goal question this battery answers:** *Does gzippy decode silesia FASTER than
rapidgzip at ALL thread counts on both Intel and AMD?* — a full-T competitive
matrix, per cell WIN / TIE / LOSS with a Δ-vs-spread significance gate.

The tool is `fulcrum scaling --box …` (the COMPETITIVE THREAD-SCALING MATRIX;
`src/scaling_matrix.rs`). It is dispatched from the `scaling` verb: `--box`
selects this matrix, `--at T:trace.json` selects the older scaling-deficit
decomposition. Both share the verb by design.

> The boxes are network-unreachable at authoring time (NO ssh). The tool's PURE
> logic (arg-parse, median/spread math, the Gate-0 predicates, WIN/TIE/LOSS +
> goal classification) is unit-tested locally (`cargo test --lib scaling_matrix`,
> 27 tests). The MEASUREMENT ORCHESTRATION (`run`) needs the real binaries + a
> box and is **reconnect-validated** — running this runbook IS its validation.

`fulcrum` runs ON the box (like `abmeasure`: it shells `perf`/decodes locally).
So the flow is: ssh onto the box, get the binaries + corpus + `fulcrum` there,
then run the invocations below. `--box <host>` is the provenance label stamped
into the artifact; it does not itself ssh.

---

## 0. Gate-0 is BAKED (refuse-to-run, LOUD, non-zero exit)

`fulcrum scaling --box …` refuses to emit any wall number unless every one of
these passes — they are the exact violations that manufactured phantom findings
all campaign:

| Gate | Check | Failure exit |
|------|-------|--------------|
| (a) comparator self-1.0 | rg-vs-rg (A/A) interleave at every T reads ≈1.0 ± spread | 2 (verdict REFUSED) |
| (b) sha == oracle | BOTH gz and rg decode the corpus to `--oracle-sha` | 2 |
| (c) sink-law | BOTH arms decode to `/dev/null` (asserted) | 2 |
| (d) path assertion | gz under `GZIPPY_DEBUG=1` prints `path=ParallelSM` | 2 |
| (e) binary fingerprint | gz + rg sha256 recorded and printed | (informational) |

Per-cell verdict: `Δ = |1 − gz/rg|`; **WIN** iff `gz/rg<1 ∧ Δ>spread`, **LOSS**
iff `gz/rg>1 ∧ Δ>spread`, else **TIE** (Δ<spread ⇒ TIE, full stop). `spread` is
the combined relative inter-run spread (IQR/median) of the two tools.
Overall: **goal met** = no LOSS cell; **strict goal** = every cell a WIN.

Exit code: `0` goal met · `1` a LOSS (goal not met) · `2` usage / refused
instrument / Gate-0 failure.

---

## 1. The pinned optimal rapidgzip build (ISA-L + LTO + native)

Build rapidgzip once per arch, on the box (its `-march=native` bakes in the
box's ISA). This is the comparator the whole matrix is scored against.

```bash
# on the box (Intel trainer / AMD solvency):
git clone https://github.com/mxmlnkn/rapidgzip && cd rapidgzip
# ISA-L backend + LTO + native tuning:
python3 -m pip install --user .          # or the cmake path below
# cmake path (explicit flags):
cmake -B build -DCMAKE_BUILD_TYPE=Release \
  -DWITH_ISAL=ON -DWITH_RPMALLOC=ON \
  -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
  -DCMAKE_CXX_FLAGS="-march=native -O3"
cmake --build build -j
RG=$PWD/build/src/tools/rapidgzip           # the pinned comparator binary
```

Record `sha256sum "$RG"` — Gate-0(e) prints it too; they must agree.

---

## 2. The gzippy builds to gate (ship + each parked lever)

Build each on the box with native tuning; the matrix is re-run per build.
`--no-default-features --features pure-rust-inflate` = the SOLE production decode
path (Gate-4). Verify `GZIPPY_DEBUG=1 … 2>&1 | grep path=ParallelSM` first.

```bash
# ship baseline
git -C gzippy checkout dc6d5b18
RUSTFLAGS="-C target-cpu=native" cargo build --release \
  --no-default-features --features pure-rust-inflate --manifest-path gzippy/Cargo.toml
GZ_SHIP=gzippy/target/release/gzippy

# parked lever: resident-pool
git -C gzippy checkout 5d707fdb   # + rebuild → GZ_RESPOOL

# parked lever: ratio-cap + min-work
git -C gzippy checkout 44f21899   # + rebuild → GZ_RATIOCAP

# parked lever: stored-writev  (apply the stash, then rebuild → GZ_STOREDWRITEV)
git -C gzippy stash list         # find the stored-writev stash; git stash apply <n>
```

---

## 3. The oracle sha (what both tools must reproduce)

```bash
CORPUS=/data/silesia-large.gz
ORACLE_SHA=$(gzip -dc "$CORPUS" | shasum -a 256 | cut -d' ' -f1)   # 64-hex; tool lowercases + compares
```

(`fulcrum scaling` records + compares the *decode-output* sha of each arm against
`--oracle-sha`. Use the trusted `gzip -dc` as the reference decoder.)

---

## 4. The invocations — silesia, all-T, BOTH arches

### Intel — `trainer` (10.30.0.199, via `-J neurotic`), freezable

```bash
ssh -J neurotic root@10.30.0.199         # get onto the Intel box
# (copy fulcrum + gz builds + rapidgzip + corpus over, or build in place)
fulcrum scaling \
  --box trainer-intel \
  --gz "$GZ_SHIP" --rg "$RG" \
  --corpus "$CORPUS" --oracle-sha "$ORACLE_SHA" \
  --threads 1,2,3,4,5,6,7,8,12,16 --n 15 \
  --out /dev/shm/scaling-trainer-silesia-ship.json
# repeat with --gz "$GZ_RESPOOL" / "$GZ_RATIOCAP" / "$GZ_STOREDWRITEV",
# each with its own --out.
```

### AMD — `solvency` (10.0.2.240), EPYC Zen2, runs the user's llama — LLAMA-SAFE

⛔ Do NOT pause/freeze `llama-server`. `fulcrum scaling` never SIGSTOPs/kills any
process, never touches the governor — it is load-tolerant by construction (the
interleaved [gz, rg, rgAA] triplet sees the same contention each rep, so the
ratio cancels it; Gate-0(a) VOIDs any T where the rg self-1.0 strayed past
spread). Still, prefer a QUIET WINDOW (low llama traffic) and rely on the
self-1.0 refusal to reject an unquiet T.

```bash
ssh root@10.0.2.240                      # AMD box (llama lives here — do not disturb it)
fulcrum scaling \
  --box solvency-amd \
  --gz "$GZ_SHIP" --rg "$RG" \
  --corpus "$CORPUS" --oracle-sha "$ORACLE_SHA" \
  --threads 1,2,3,4,5,6,7,8,12,16 --n 15 \
  --out /dev/shm/scaling-solvency-silesia-ship.json
# repeat per parked-lever build.
```

If any T prints `[self-1.0 FAIL]` / the run exits 2 with
"comparator not self-consistent at T=…", the box was too noisy at that T —
re-run in a quieter window (do NOT lower the bar).

---

## 5. Held-out re-gate (nasa / squishy)

After silesia, re-run the SAME invocations with a held-out corpus so a
silesia-specific tuning cannot masquerade as a general win (Gate-3 cross-corpus):

```bash
for C in /data/nasa.gz /data/squishy.gz; do
  ORACLE=$(gzip -dc "$C" | shasum -a 256 | cut -d' ' -f1)
  fulcrum scaling --box <host> --gz "$GZ_SHIP" --rg "$RG" \
    --corpus "$C" --oracle-sha "$ORACLE" \
    --threads 1,2,3,4,5,6,7,8,12,16 --n 15 \
    --out /dev/shm/scaling-<host>-$(basename "$C").json
done
```

---

## 6. Reading the result

- Human table: per-T `gz ms | rg ms | gz/rg | Δ | spread | cell`, then
  `GOAL on <box>: MET/NOT MET` + `STRICT`.
- JSON artifact at `--out`: `cells[]` (each carries `verdict`, `ratio`,
  `spread`, `self_ratio`, `self_consistent`), `goal_met`, `strict_goal_met`,
  `gz_sha256`, `rg_sha256` — the pinned provenance of exactly what was measured.

**The campaign goal is met** when, on BOTH trainer-intel and solvency-amd, the
ship build's silesia matrix reads `goal_met = true` (every T WIN-or-TIE, none
LOSS) — and holds on the nasa/squishy re-gate. A LOSS at any T (the known
T8/T16 parallel-scaling deficit) is the open front the parked levers target.

---

## Reconnect checklist

1. `git -C ~/www/fulcrum-mac checkout feat/scaling-subcommand`
2. Build `fulcrum` for the box's OS/arch; copy it + the gz/rg builds + corpus over.
3. Build the pinned rapidgzip (§1) and the gz builds (§2) on each box.
4. Compute `$ORACLE_SHA` (§3).
5. Run §4 (silesia, both arches, per build), then §5 (held-out).
6. Collect the JSON artifacts; the `goal_met` flags are the verdict.
