BIN   := ./target/release/fulcrum
TOY   := ./target/release/examples/toy_pipeline
TRACE := /tmp/fulcrum_toy.json

.DEFAULT_GOAL := test

.PHONY: test check-unit check-pipeline check-robustness demo build release clean help deploy deploy-check

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
	@$(BIN) trace critpath $(TRACE) --heavy-ms 5 --no-self-update > /tmp/fulcrum_critpath.txt
	@grep -q 'transform' /tmp/fulcrum_critpath.txt \
		&& printf '\033[1;32m  ✓ trace critpath: transform attributed on critical path\033[0m\n' \
		|| { printf '\033[1;31m  ✗ trace critpath: transform should dominate the critical path\033[0m\n'; \
		     cat /tmp/fulcrum_critpath.txt; exit 1; }
	@grep -q 'consumer wait' /tmp/fulcrum_critpath.txt \
		&& printf '\033[1;32m  ✓ trace critpath: consumer wait detected (in-order consumer found)\033[0m\n' \
		|| { printf '\033[1;31m  ✗ trace critpath: expected consumer wait spans\033[0m\n'; exit 1; }
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
	@$(BIN) trace critpath /tmp/fulcrum_toy_2w.json --no-self-update | grep -q 'transform' \
		&& printf '\033[1;32m  ✓ transform still #1 at 2 workers\033[0m\n' \
		|| { printf '\033[1;31m  ✗ transform should be #1 at 2 workers\033[0m\n'; exit 1; }
	@printf '\n\033[1;34m══ robustness: 8 workers (2400 items) ═══════════════════════════════\033[0m\n\n'
	@FULCRUM_TRACE=/tmp/fulcrum_toy_8w.json $(TOY) --items 2400 --workers 8 2>&1
	@$(BIN) trace critpath /tmp/fulcrum_toy_8w.json --no-self-update | grep -q 'transform' \
		&& printf '\033[1;32m  ✓ transform still #1 at 8 workers\033[0m\n' \
		|| { printf '\033[1;31m  ✗ transform should be #1 at 8 workers\033[0m\n'; exit 1; }
	@printf '\n\033[1;32m══ robustness: all assertions passed ═══════════════════════════════\033[0m\n'

# ── show it off ───────────────────────────────────────────────────────────────

demo: build
	@printf '\n\033[1;34m══ fulcrum demo ════════════════════════════════════════════════════\033[0m\n\n'
	FULCRUM_TRACE=$(TRACE) $(TOY) --items 240 --workers 4
	@printf '\n'
	$(BIN) trace critpath $(TRACE) --heavy-ms 5 --no-self-update
	@printf '\n'
	$(BIN) trace consumer $(TRACE) --config demo --no-self-update

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

# ── deployment: get main onto every box we measure on, verifiably ─────────────
#
# THE SCAR: the authority box ran a fulcrum binary built 2026-07-13 that lacked
# half the instrument set; two weeks of measurements used a stale instrument
# and a hand-rolled byte-count size check nearly scored a corrupt output as a
# WIN. Deployment is not done until `fulcrum version --expect <sha>` passes ON
# THE BOX and the Gate-0 suite is green there.
#
#   make deploy       BOX=root@10.0.2.240 DIR=/root/fulcrum
#   make deploy-check BOX=root@10.0.2.240 DIR=/root/fulcrum

BOX ?= root@10.0.2.240
DIR ?= /root/fulcrum

deploy:
	@printf '\n\033[1;34m══ deploy main → %s:%s ══\033[0m\n\n' "$(BOX)" "$(DIR)"
	ssh $(BOX) 'test -d $(DIR)/.git || git clone $(shell git remote get-url origin) $(DIR)'
	ssh $(BOX) 'cd $(DIR) && git fetch origin main && git checkout -q main && git reset --hard -q origin/main && cargo build --release'
	@$(MAKE) --no-print-directory deploy-check BOX=$(BOX) DIR=$(DIR)
	ssh $(BOX) '$(DIR)/target/release/fulcrum selftest --no-self-update' \
		&& printf '\033[1;32m  ✓ Gate-0 suite green on %s\033[0m\n' "$(BOX)" \
		|| { printf '\033[1;31m  ✗ Gate-0 suite FAILED on %s — the deploy does not count\033[0m\n' "$(BOX)"; exit 1; }

deploy-check:
	@want=$$(git ls-remote $(shell git remote get-url origin) refs/heads/main | cut -f1) && \
	ssh $(BOX) '$(DIR)/target/release/fulcrum version --expect '"$$want"' --no-self-update' \
		&& printf '\033[1;32m  ✓ %s runs origin/main (%s)\033[0m\n' "$(BOX)" "$$want" \
		|| { printf '\033[1;31m  ✗ %s is NOT running origin/main — do not measure there\033[0m\n' "$(BOX)"; exit 1; }

# ── plumbing ──────────────────────────────────────────────────────────────────

build:
	cargo build --release --bin fulcrum --examples

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
	@printf '  make deploy BOX=… DIR=… push main to a box, rebuild, verify provenance + Gate-0s\n'
	@printf '  make deploy-check …     verify a box runs origin/main (fulcrum version --expect)\n'
	@printf '  make clean              remove traces and build artifacts\n'
	@printf '\nTo release: edit VERSION, then run make release\n\n'
