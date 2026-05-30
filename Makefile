BIN   := ./target/release/fulcrum
TOY   := ./target/release/examples/toy_pipeline
TRACE := /tmp/fulcrum_toy.json

.DEFAULT_GOAL := test

.PHONY: test check-unit check-pipeline check-robustness demo build release clean help

# ── run everything ────────────────────────────────────────────────────────────

test: check-unit check-pipeline

# ── unit + integration (cargo) ────────────────────────────────────────────────

check-unit:
	@printf '\n\033[1;34m══ unit tests ══════════════════════════════════════════════════════\033[0m\n\n'
	cargo test

# ── end-to-end: real pipeline, real data, real assertions ─────────────────────
#
# 1200 items keeps the measurement above the noise floor so the ground truth
# checks pass reliably. At 240 items the toy finishes in ~30ms and scheduling
# jitter swamps the signal.

check-pipeline: build
	@printf '\n\033[1;34m══ pipeline integration (1200 items, 4 workers) ═════════════════════\033[0m\n\n'
	@FULCRUM_TRACE=$(TRACE) $(TOY) --items 1200 --workers 4 2>&1
	@printf '\n'
	@$(BIN) critpath $(TRACE) --heavy-ms 5 > /tmp/fulcrum_critpath.txt
	@grep -q 'transform' /tmp/fulcrum_critpath.txt \
		&& printf '\033[1;32m  ✓ critpath: transform attributed on critical path\033[0m\n' \
		|| { printf '\033[1;31m  ✗ critpath: transform should dominate the critical path\033[0m\n'; \
		     cat /tmp/fulcrum_critpath.txt; exit 1; }
	@grep -q 'consumer wait' /tmp/fulcrum_critpath.txt \
		&& printf '\033[1;32m  ✓ critpath: consumer wait detected (in-order consumer found)\033[0m\n' \
		|| { printf '\033[1;31m  ✗ critpath: expected consumer wait spans\033[0m\n'; exit 1; }
	@printf '\n'
	@$(BIN) validate $(TRACE) \
		&& printf '\033[1;32m  ✓ validate: ground truth reproduced\033[0m\n' \
		|| { printf '\033[1;31m  ✗ validate: ground truth diverged — check above\033[0m\n'; exit 1; }
	@printf '\n'
	@$(BIN) rank $(TRACE) > /tmp/fulcrum_rank.txt
	@grep -q '> transform' /tmp/fulcrum_rank.txt \
		&& printf '\033[1;32m  ✓ rank: transform is the #1 lever\033[0m\n' \
		|| { printf '\033[1;31m  ✗ rank: expected transform as #1 lever\033[0m\n'; \
		     cat /tmp/fulcrum_rank.txt; exit 1; }
	@grep -q 'NEXT LEVER -> transform' /tmp/fulcrum_rank.txt \
		&& printf '\033[1;32m  ✓ rank: NEXT LEVER points at transform\033[0m\n' \
		|| { printf '\033[1;31m  ✗ rank: NEXT LEVER should point at transform\033[0m\n'; exit 1; }
	@printf '\n\033[1;32m══ all pipeline assertions passed ══════════════════════════════════\033[0m\n'

# ── robustness: same ranking under different parallelism ──────────────────────
#
# The ranking should not flip just because you ran with 2 workers instead of 4.
# These catch regressions in consumer-detection and attribution logic.
#
# Note: the cp_offpath ground truth check only holds reliably at 4 workers —
# at higher parallelism every stage accumulates more critical-path blame. So
# these check ranking only, not validate.

check-robustness: build
	@printf '\n\033[1;34m══ robustness: 2 workers (600 items) ════════════════════════════════\033[0m\n\n'
	@FULCRUM_TRACE=/tmp/fulcrum_toy_2w.json $(TOY) --items 600 --workers 2 2>&1
	@$(BIN) rank /tmp/fulcrum_toy_2w.json | grep -q '> transform' \
		&& printf '\033[1;32m  ✓ transform still #1 at 2 workers\033[0m\n' \
		|| { printf '\033[1;31m  ✗ transform should be #1 at 2 workers\033[0m\n'; exit 1; }
	@printf '\n\033[1;34m══ robustness: 8 workers (2400 items) ═══════════════════════════════\033[0m\n\n'
	@FULCRUM_TRACE=/tmp/fulcrum_toy_8w.json $(TOY) --items 2400 --workers 8 2>&1
	@$(BIN) rank /tmp/fulcrum_toy_8w.json | grep -q '> transform' \
		&& printf '\033[1;32m  ✓ transform still #1 at 8 workers\033[0m\n' \
		|| { printf '\033[1;31m  ✗ transform should be #1 at 8 workers\033[0m\n'; exit 1; }
	@printf '\n\033[1;32m══ robustness: all assertions passed ═══════════════════════════════\033[0m\n'

# ── show it off ───────────────────────────────────────────────────────────────

demo: build
	@printf '\n\033[1;34m══ fulcrum demo ════════════════════════════════════════════════════\033[0m\n\n'
	FULCRUM_TRACE=$(TRACE) $(TOY) --items 240 --workers 4
	@printf '\n'
	$(BIN) critpath $(TRACE) --heavy-ms 5
	@printf '\n'
	$(BIN) rank $(TRACE)
	@printf '\n'
	$(BIN) validate $(TRACE)

# ── release: VERSION → Cargo.toml → commit → tag → push ──────────────────────
#
# Edit VERSION, then run `make release`. It syncs the version into Cargo.toml,
# runs the full test suite, commits, tags, and pushes. GHA picks up the tag
# and publishes to crates.io.

release: test
	@git diff --quiet && git diff --staged --quiet \
	    || { printf '\033[1;31m  working tree is dirty — commit or stash first\033[0m\n'; exit 1; }
	@version=$$(cat VERSION | tr -d '[:space:]') && \
	git tag | grep -q "^v$$version$$" \
	    && { printf '\033[1;31m  v%s is already tagged\033[0m\n' "$$version"; exit 1; } \
	    || true
	@version=$$(cat VERSION | tr -d '[:space:]') && \
	printf '\n\033[1;34m══ releasing v%s ═══════════════════════════════════════════════\033[0m\n\n' "$$version" && \
	perl -i -pe "s/^version = \"[^\"]*\"/version = \"$$version\"/" Cargo.toml && \
	cargo metadata --no-deps --format-version 1 > /dev/null && \
	git add VERSION Cargo.toml Cargo.lock && \
	git diff --cached --quiet || git commit -m "Release v$$version" && \
	git tag "v$$version" && \
	git push && git push --tags && \
	printf '\n\033[1;32m  v%s tagged and pushed — GHA will publish to crates.io\033[0m\n\n' "$$version"

# ── plumbing ──────────────────────────────────────────────────────────────────

build:
	cargo build --release --examples

clean:
	@rm -f $(TRACE) /tmp/fulcrum_toy_2w.json /tmp/fulcrum_toy_8w.json \
	        /tmp/fulcrum_rank.txt /tmp/fulcrum_critpath.txt
	cargo clean

help:
	@printf '\nTargets:\n'
	@printf '  make test               unit tests + pipeline integration\n'
	@printf '  make check-unit         cargo test only (no binary needed)\n'
	@printf '  make check-pipeline     build, run toy, assert the ranking\n'
	@printf '  make check-robustness   same assertions at 2 and 8 workers\n'
	@printf '  make demo               full analysis output, pretty-printed\n'
	@printf '  make build              cargo build --release --examples\n'
	@printf '  make release            sync VERSION → Cargo.toml, tag, push\n'
	@printf '  make clean              remove traces and build artifacts\n'
	@printf '\nTo release: edit VERSION, then run make release\n\n'
