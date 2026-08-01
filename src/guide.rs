//! `fulcrum guide` / `fulcrum commands` — THE TASK INDEX.
//!
//! THE SCAR (2026-07-31, recorded by the agent it happened to): an agent working
//! the gzippy encoder campaign spent HOURS hand-rolling measurements this binary
//! already performs — a by-hand vendor diff (position counts, match/literal
//! ratios, per-line Ir/Dr from callgrind, a declared-parameter table) that
//! `fulcrum why` does in ONE command and in four layers; a python script that
//! re-parsed census JSON to count failing cells by rival and thread count, which
//! is exactly `fulcrum board`; and it never once ran `fulcrum dropin`, so an
//! entire axis of the stated goal ("drop-in replacement, same observable
//! behaviour") went unmeasured for the whole campaign. When `dropin` was finally
//! run it found 19 divergences in 208 scenarios.
//!
//! The tools were all present. `--help` listed all of them. THAT WAS THE
//! DEFECT: the help is indexed by COMMAND, and an agent arrives holding a
//! QUESTION. "Why does this cell fail?" does not look like the word `why` until
//! you already know the answer.
//!
//! So this module is an index in the other direction:
//!
//!   * [`INTENTS`] — questions an agent actually arrives with, each mapped to
//!     literal copy-pasteable command lines, in the order they should be run.
//!   * [`COMMANDS`] — every dispatchable command path with the question it
//!     answers, its required arguments, a runnable example, its staleness
//!     class, whether it carries a Gate-0, and the next action after it.
//!     `fulcrum commands --json` emits it whole, so an agent can discover the
//!     capability surface without parsing prose.
//!
//! Both registries are load-bearing, not documentation: `main.rs` derives its
//! dispatch-name list from [`COMMANDS`], `--help` is answered from it, and the
//! Gate-0 below EXECUTES every advertised path to prove it resolves. A command
//! that is advertised here and does not exist fails the selftest.

use std::process::ExitCode;

// ---------------------------------------------------------------------------
// The registries
// ---------------------------------------------------------------------------

/// How a command relates to measurement — mirrors `selfver::CmdClass`, which is
/// what actually enforces the staleness gate. Stated here so an agent can see,
/// before running anything, which commands REFUSE to run from a stale binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Emits a number that may be quoted. Refuses to run stale.
    Measurement,
    /// Reads or adjudicates banked artifacts. Self-updates when safe.
    Analysis,
    /// Always runs (help, version, selftest, freeze release).
    Exempt,
}

impl Class {
    pub fn as_str(self) -> &'static str {
        match self {
            Class::Measurement => "measurement",
            Class::Analysis => "analysis",
            Class::Exempt => "exempt",
        }
    }
}

/// One dispatchable command path.
#[derive(Debug, Clone, Copy)]
pub struct Cmd {
    /// The argv path, space-separated: `"board size"`, `"why"`, `"trace flow"`.
    pub path: &'static str,
    /// The QUESTION this answers, phrased the way someone would ask it.
    pub question: &'static str,
    /// Required arguments (what the command REFUSES to run without).
    pub required: &'static str,
    /// A literal runnable line. Gate-0 asserts it starts with `fulcrum <path>`.
    pub example: &'static str,
    pub class: Class,
    /// The name of this command's Gate-0, exactly as `fulcrum selftest <name>`
    /// takes it. Gate-0 asserts the name resolves in the selftest registry, so
    /// the guide cannot advertise a self-test that does not exist.
    pub gate0: Option<&'static str>,
    /// What to run next. `None` = the command emits its own contextual NEXT
    /// ACTION (a generic one would contradict it), so nothing is added.
    pub next: Option<&'static str>,
    /// True when passing `--help` to this path would DO the thing instead of
    /// describing it. `--help` is answered from the registry and never
    /// delegated for these. Receipt: `fulcrum freeze acquire --help` used to
    /// stop processes and pin the governor.
    pub help_acts: bool,
}

/// Terse constructor so the registry below reads as a table. `gated`, `then`
/// and `acts_on_help` decorate it.
#[allow(non_snake_case)]
const fn C(
    path: &'static str,
    question: &'static str,
    required: &'static str,
    example: &'static str,
    class: Class,
) -> Cmd {
    Cmd {
        path,
        question,
        required,
        example,
        class,
        gate0: None,
        next: None,
        help_acts: false,
    }
}

const fn gated(name: &'static str, mut c: Cmd) -> Cmd {
    c.gate0 = Some(name);
    c
}

const fn then(mut c: Cmd, next: &'static str) -> Cmd {
    c.next = Some(next);
    c
}

const fn acts_on_help(mut c: Cmd) -> Cmd {
    c.help_acts = true;
    c
}

/// EVERY dispatchable command path. `main.rs` derives its known-subcommand list
/// from this, and the Gate-0 executes each path's `--help` to prove it resolves.
pub const COMMANDS: &[Cmd] = &[
    // ---- the four campaign verbs -----------------------------------------
    gated("board", C(
        "board",
        "Where do we stand? Which per-label cells are failing, ranked by gap?",
        "--size DIR and/or --wall DIR (banked census dirs)",
        "fulcrum board --size ~/www/gzippy-bench/campaign/board-size/latest --wall ~/www/gzippy-bench/campaign/board-wall/latest",
        Class::Analysis,
    )),
    then(
        gated("board size (sizecensus)", C(
            "board size",
            "Derive the SIZE axis: is our output bigger than the rival's, per cell?",
            "--ours CMD, --rival name=CMD, --corpus FILE, --out DIR",
            "fulcrum board size --ours '~/www/gzippy/target/release/gzippy -{level} -p {threads} -c {input}' --rival libdeflate='libdeflate-gzip -{level} -c {input}' --levels 1-9 --threads 1,4 --corpus ~/www/gzippy-bench/corpus/silesia.tar --out /tmp/board-size",
            Class::Measurement,
        )),
        "fulcrum board --size <that --out DIR>   (rank the failing cells)",
    ),
    then(
        gated("board wall (wallcensus)", C(
            "board wall",
            "Derive the WALL axis: are we slower than the rival, per cell, paired?",
            "--ours CMD, --rival name=CMD, --corpus FILE, --out DIR (and a held freeze)",
            "fulcrum board wall --ours '~/www/gzippy/target/release/gzippy -{level} -p {threads} -c {input}' --rival libdeflate='libdeflate-gzip -{level} -c {input}' --levels 1-9 --threads 1,4 --corpus ~/www/gzippy-bench/corpus/silesia.tar --out /tmp/board-wall",
            Class::Measurement,
        )),
        "fulcrum board --wall <that --out DIR>   (rank the failing cells)",
    ),
    then(
        gated("goal", C(
            "board goal",
            "Does the WHOLE goal surface pass, or was the scope narrowed?",
            "--spec goal.json --ours-bin PATH",
            "fulcrum board goal join --size-census /tmp/board-size --wall-census /tmp/board-wall --spec goal.json --ours-bin ~/www/gzippy/target/release/gzippy",
            Class::Analysis,
        )),
        "fulcrum board --size DIR --wall DIR   (a narrowed scope is INCOMPLETE, never a pass — widen the grid and re-run)",
    ),
    gated("why", C(
        "why",
        "Why does this cell fail? What is the MECHANISM, vendor-diffed?",
        "<cell> --repo PATH (derives the arms from the cell id), or --ours/--rival-cmd/--corpus",
        "fulcrum why libdeflate:sil40:L6:T1:wall --repo ~/www/gzippy",
        Class::Measurement,
    )),
    gated("candidates", C(
        "candidates",
        "What could I do about it? Which vendor techniques are un-tried and un-falsified?",
        "<cell> (--repo defaults to ~/www/gzippy)",
        "fulcrum candidates libdeflate:silesia.tar:L6:T1:wall --repo ~/www/gzippy",
        Class::Analysis,
    )),
    gated("try", C(
        "try",
        "Is this change good? Does it clear the promotion rule, clause by clause?",
        "<after-ref> --repo PATH --rival name=CMD --corpus FILE",
        "fulcrum try my-branch --base origin/main --repo ~/www/gzippy --rival libdeflate='libdeflate-gzip -{level} -c {input}' --corpus ~/www/gzippy-bench/corpus/silesia.tar --levels 2,6,9",
        Class::Measurement,
    )),
    // ---- correctness / goal axes ------------------------------------------
    then(
        gated("verify", C(
            "verify",
            "Is the encoder correct? Does every output roundtrip at every thread count?",
            "--ours CMD, --decoder CMD, --corpus FILE",
            "fulcrum verify --ours '~/www/gzippy/target/release/gzippy -{level} -p {threads} -c {input}' --decoder '~/www/gzippy/target/release/ungzippy -d -p {threads} -c {input}' --corpus ~/www/gzippy-bench/corpus/silesia.tar --cross 'gzip -dc'",
            Class::Measurement,
        )),
        "fulcrum dropin …   (correct BYTES is only half the goal; dropin measures observable BEHAVIOUR)",
    ),
    then(
        gated("dropin", C(
            "dropin",
            "Did I break drop-in CLI compatibility — in-place vs -c, -k, -f, -t, error behaviour?",
            "--ours PATH, --rival name=CMD, --fixture FILE, --out DIR",
            "fulcrum dropin --ours ~/www/gzippy/target/release/gzippy --rival gzip=gzip --rival pigz=pigz --fixture ~/www/gzippy-bench/corpus/silesia.tar --out /tmp/dropin",
            Class::Measurement,
        )),
        "every DIVERGENT cell is either a bug to fix or an exception to declare in --declared FILE.json (reason required)",
    ),
    then(
        gated("structcensus", C(
            "structcensus",
            "Where do the allocations and bytes go, ours vs every rival? (the cheapest falsifier)",
            "--ours CMD, --rival name=CMD, --corpus FILE",
            "fulcrum structcensus --ours '~/www/gzippy/target/release/gzippy -{level} -p {threads} -c {input}' --rival libdeflate='libdeflate-gzip -{level} -c {input}' --corpus ~/www/gzippy-bench/corpus/silesia.tar --level 6 --threads 1",
            Class::Measurement,
        )),
        "pass two sizes of the same data to get the SCALING verdict (allocations that grow with input = per-block allocation)",
    ),
    // ---- the box -----------------------------------------------------------
    then(
        gated("freeze", C(
            "freeze",
            "How do I make this box quiet enough to trust a wall number?",
            "a verb: acquire|release|run|status|selftest",
            "fulcrum freeze run --ttl-s 600 -- fulcrum board wall --ours '…' --out /tmp/board-wall",
            Class::Exempt,
        )),
        "fulcrum freeze run --ttl-s 600 -- <the measurement>   (the only form that cannot orphan a stopped process)",
    ),
    then(
        acts_on_help(C(
            "freeze acquire",
            "Pin the governor and stop the noisy processes (prefer `freeze run`, which cannot orphan).",
            "nothing (--ttl-s recommended)",
            "fulcrum freeze acquire --ttl-s 600",
            Class::Exempt,
        )),
        "fulcrum freeze release   (or use `fulcrum freeze run --`, which releases on every exit path)",
    ),
    then(
        acts_on_help(C(
            "freeze release",
            "Undo a freeze — SIGCONT everything, restore boost/governor.",
            "nothing",
            "fulcrum freeze release",
            Class::Exempt,
        )),
        "fulcrum freeze status   (verify nothing is left stopped — an orphaned SIGSTOP is the worse failure)",
    ),
    acts_on_help(C(
        "freeze run",
        "Run one command under a freeze that is released on EVERY exit path.",
        "-- COMMAND …",
        "fulcrum freeze run --ttl-s 900 -- fulcrum ab paired --a-cmd '…' --b-cmd '…'",
        Class::Exempt,
    )),
    then(
        C(
            "freeze status",
            "Is a freeze held right now, and by what, and for how long?",
            "nothing",
            "fulcrum freeze status",
            Class::Exempt,
        ),
        "fulcrum freeze release   (if one is held and you are done)",
    ),
    // ---- A/B ---------------------------------------------------------------
    C(
        "ab",
        "A/B two builds with provenance — which family member do I want?",
        "a subcommand: paired|matrix|ablate|bisect|selftest",
        "fulcrum ab paired --a-cmd '…' --b-cmd '…' --n 15",
        Class::Measurement,
    ),
    then(
        gated("ab paired", C(
            "ab paired",
            "Is A really faster than B? (interleaved paired-Δ with an A/A certificate)",
            "--a-cmd, --b-cmd",
            "fulcrum ab paired --a-cmd 'A -6 -c in > /dev/null' --b-cmd 'B -6 -c in > /dev/null' --n 15",
            Class::Measurement,
        )),
        "fulcrum try <ref> --repo ~/www/gzippy …   (a paired win is not a ship decision; the promotion rule has more clauses)",
    ),
    then(
        gated("ab matrix", C(
            "ab matrix",
            "Does the A/B verdict hold across the corpus x thread-count grid?",
            "--a-cmd, --b-cmd",
            "fulcrum ab matrix --a-cmd '…' --b-cmd '…' --corpus ~/www/gzippy-bench/corpus/silesia.tar --threads 1,4",
            Class::Measurement,
        )),
        "fulcrum try <ref> --repo ~/www/gzippy --levels 2,6,9   (a verdict at one level generalises to none)",
    ),
    then(
        gated("ab ablate", C(
            "ab ablate",
            "Which PART of my change paid? (builds both arms from refs; refuses a NO-OP control)",
            "--repo, --base REF, --after REF, --class name=FILE",
            "fulcrum ab ablate --repo ~/www/gzippy --base origin/main --after my-branch --class matchfinder=src/compress/hc.rs",
            Class::Measurement,
        )),
        "fulcrum try <ref> --repo ~/www/gzippy …   (turn the surviving class into SHIP / NO-SHIP)",
    ),
    then(
        gated("ab bisect", C(
            "ab bisect",
            "Which commit in this chain introduced the regression?",
            "--run '<tmpl with {bin} {threads} {corpus}>'",
            "fulcrum ab bisect --repo ~/www/gzippy --run '{bin} -6 -p {threads} -c {corpus} > /dev/null' --refs a,b,c",
            Class::Measurement,
        )),
        "fulcrum why <cell> --repo ~/www/gzippy   (the named transition still needs a mechanism)",
    ),
    // ---- profile -----------------------------------------------------------
    C(
        "profile",
        "Where do time, instructions and loads go? (these LOCATE; they never predict the wall)",
        "a subcommand: counters|insn|insn-cat|topdown|excess|uarch|chainlat|classhist|rss|phases",
        "fulcrum profile counters --a-cmd '…' --b-cmd '…'",
        Class::Measurement,
    ),
    then(
        C(
            "profile counters",
            "Where does the hardware time go vs the rival, with threads MATCHED?",
            "--a-cmd, --b-cmd",
            "fulcrum profile counters --a-cmd '…' --b-cmd '…'",
            Class::Measurement,
        ),
        "fulcrum freeze run -- fulcrum ab paired --a-cmd '…' --b-cmd '…'   (counters LOCATE; only the paired wall decides)",
    ),
    then(
        C(
            "profile insn",
            "Where do the instructions go? (closed accounting ledger from perf stat+report)",
            "--a-stat FILE, --a-report FILE",
            "fulcrum profile insn --a-stat a.stat --a-report a.report",
            Class::Measurement,
        ),
        "fulcrum freeze run -- fulcrum ab paired --a-cmd '…' --b-cmd '…'   (Ir has been cut 1.77% while the wall got 9.9% WORSE)",
    ),
    then(
        C(
            "profile insn-cat",
            "Which instruction CATEGORIES carry the excess?",
            "a perf report capture",
            "fulcrum profile insn-cat --a-report a.report",
            Class::Measurement,
        ),
        "fulcrum freeze run -- fulcrum ab paired --a-cmd '…' --b-cmd '…'   (confirm on the wall before quoting it)",
    ),
    then(
        C(
            "profile topdown",
            "Is the gap frontend, backend, bad speculation or retiring? (TMA)",
            "--a-stat FILE",
            "fulcrum profile topdown --a-stat a.stat --b-stat b.stat",
            Class::Measurement,
        ),
        "fulcrum freeze run -- fulcrum ab paired --a-cmd '…' --b-cmd '…'   (confirm on the wall before quoting it)",
    ),
    then(
        C(
            "profile excess",
            "Which region is EXCESS over intrinsic work, per region?",
            "<artifact.json>",
            "fulcrum profile excess artifact.json",
            Class::Measurement,
        ),
        "fulcrum why <cell> --repo ~/www/gzippy   (excess is located; the mechanism still needs the vendor diff)",
    ),
    then(
        gated("profile uarch", C(
            "profile uarch",
            "What do the raw microarch counters say, and how do two boxes differ?",
            "a subcommand: run|cross|selftest",
            "fulcrum profile uarch run -- ~/www/gzippy/target/release/gzippy -6 -c in",
            Class::Measurement,
        )),
        "fulcrum freeze run -- fulcrum ab paired --a-cmd '…' --b-cmd '…'   (confirm on the wall before quoting it)",
    ),
    then(
        C(
            "profile chainlat",
            "Is this loop latency-bound on a recurrence? (llvm-mca chain analysis)",
            "an object/asm input",
            "fulcrum profile chainlat --obj target/release/gzippy --symbol hc_find",
            Class::Measurement,
        ),
        "fulcrum freeze run -- fulcrum ab paired --a-cmd '…' --b-cmd '…'   (a latency model predicts nothing until the wall agrees)",
    ),
    then(
        C(
            "profile classhist",
            "Which instruction CLASSES execute most, ours vs theirs? (x86-64)",
            "a perf capture",
            "fulcrum profile classhist --a-report a.report --b-report b.report",
            Class::Measurement,
        ),
        "fulcrum freeze run -- fulcrum ab paired --a-cmd '…' --b-cmd '…'   (confirm on the wall before quoting it)",
    ),
    then(
        gated("profile rss (memprofile)", C(
            "profile rss",
            "How much memory does it hold, and how does that move with threads?",
            "-- ARGV…",
            "fulcrum profile rss -- ~/www/gzippy/target/release/gzippy -6 -p 16 -c in",
            Class::Measurement,
        )),
        "fulcrum structcensus --ours '…' --rival name=CMD --corpus FILE   (RSS is its own scoreboard; allocation COUNT and its scaling are the falsifier)",
    ),
    then(
        C(
            "profile phases",
            "How does the wall split across the phases of a phase-timing build?",
            "a phase-timing gzippy build",
            "fulcrum profile phases --runs 5 -- ~/www/gzippy/target/release/gzippy -6 -c in",
            Class::Measurement,
        ),
        "fulcrum freeze run -- fulcrum ab paired --a-cmd '…' --b-cmd '…'   (confirm on the wall before quoting it)",
    ),
    // ---- trace (T>1) --------------------------------------------------------
    C(
        "trace",
        "Span-trace views over a Chrome-trace timeline — the T>1 starvation/causation tooling.",
        "a subcommand + a trace.json",
        "fulcrum trace occupancy trace.json",
        Class::Analysis,
    ),
    then(
        C(
            "trace critpath",
            "Which span is on the critical path of this parallel run?",
            "<trace.json>",
            "fulcrum trace critpath trace.json --config gzippy",
            Class::Analysis,
        ),
        "fulcrum trace causal trace.json   (being ON the critical path is not the same as MOVING the wall)",
    ),
    then(
        C(
            "trace flow",
            "How does work FLOW between the threads over time?",
            "<trace.json>",
            "fulcrum trace flow trace.json --config gzippy",
            Class::Analysis,
        ),
        "fulcrum trace occupancy trace.json   (name the starved thread, not the busy one)",
    ),
    then(
        C(
            "trace causal",
            "If I sped up this region, how much wall would actually move? (virtual speedup)",
            "<trace.json>",
            "fulcrum trace causal trace.json --config gzippy",
            Class::Analysis,
        ),
        "fulcrum freeze run -- fulcrum ab paired --a-cmd '…' --b-cmd '…'   (a virtual speedup is a prediction; the wall is the verdict)",
    ),
    then(
        C(
            "trace consumer",
            "Is the consumer thread the bottleneck?",
            "<trace.json>",
            "fulcrum trace consumer trace.json",
            Class::Analysis,
        ),
        "fulcrum trace occupancy trace.json",
    ),
    then(
        C(
            "trace occupancy",
            "Is any thread ever STARVED, and for how long?",
            "<trace.json>",
            "fulcrum trace occupancy trace.json",
            Class::Analysis,
        ),
        "fulcrum trace dispatchgap events.jsonl   (attribute the starvation to a dispatcher, not a guess)",
    ),
    then(
        C(
            "trace spans",
            "What are the heaviest spans in this trace?",
            "<trace.json>",
            "fulcrum trace spans trace.json --config gzippy --top 20",
            Class::Analysis,
        ),
        "fulcrum trace critpath trace.json --config gzippy   (the heaviest span is often not the blocking one)",
    ),
    then(
        C(
            "trace schedule",
            "Were the reads and writes scheduled in the right order?",
            "<trace.json>",
            "fulcrum trace schedule trace.json",
            Class::Analysis,
        ),
        "fulcrum trace occupancy trace.json",
    ),
    then(
        C(
            "trace scaling",
            "Why does it stop scaling at T threads?",
            "--at T:trace.json",
            "fulcrum trace scaling --at 4:t4.json --at 16:t16.json --config gzippy",
            Class::Analysis,
        ),
        "fulcrum board --wall DIR   (measure at the coordinate where the cells FAIL, not where the trace is convenient)",
    ),
    then(
        C(
            "trace decompose",
            "What fraction of the wall is serial, parallel, and overhead?",
            "<trace.json>",
            "fulcrum trace decompose trace.json",
            Class::Analysis,
        ),
        "fulcrum trace causal trace.json",
    ),
    then(
        C(
            "trace locate",
            "Which region holds enough wall to be worth optimising at all?",
            "<trace.json> [--wall-ms N]",
            "fulcrum trace locate trace.json --wall-ms 350",
            Class::Analysis,
        ),
        "fulcrum why <cell> --repo ~/www/gzippy   (a region with wall in it is not yet a mechanism)",
    ),
    then(
        C(
            "trace model",
            "What does the analytic model predict for this thread count?",
            "<trace.json>",
            "fulcrum trace model trace.json --workers 8",
            Class::Analysis,
        ),
        "fulcrum freeze run -- fulcrum ab paired --a-cmd '…' --b-cmd '…'",
    ),
    then(
        C(
            "trace vs",
            "Where do these two traces spend their time differently?",
            "<A-trace.json> <B-trace.json>",
            "fulcrum trace vs a.json b.json --labels ours,rival",
            Class::Analysis,
        ),
        "fulcrum trace scaling --at T:a.json --at T:b.json",
    ),
    then(
        C(
            "trace vs-sweep",
            "Where does the two-trace gap open up as threads rise?",
            "--at T:a.json:b.json",
            "fulcrum trace vs-sweep --at 4:a4.json:b4.json --at 16:a16.json:b16.json",
            Class::Analysis,
        ),
        "fulcrum board --wall DIR   (a trace gap only matters where a cell fails)",
    ),
    then(
        gated("trace dispatchgap", C(
            "trace dispatchgap",
            "Which worker waited on dispatch, and for how long?",
            "<event-log.jsonl>",
            "fulcrum trace dispatchgap events.jsonl --workers 8",
            Class::Analysis,
        )),
        "fulcrum trace occupancy trace.json",
    ),
    // ---- anatomy ------------------------------------------------------------
    then(
        C(
            "anatomy",
            "What is the STRUCTURE of our deflate output vs theirs — tokens, matches, literals, header bits?",
            "two .gz files or a compare spec",
            "fulcrum anatomy --ours ours.gz --rival rival.gz --input ~/www/gzippy-bench/corpus/silesia.tar",
            Class::Measurement,
        ),
        "fulcrum why <cell> --repo ~/www/gzippy   (this diff plus three more layers, run for you)",
    ),
    then(
        gated("anatomy ratio", C(
            "anatomy ratio",
            "How much ratio is left on the table vs the optimal parse frontier?",
            "an input file",
            "fulcrum anatomy ratio --input ~/www/gzippy-bench/corpus/silesia.tar --level 9",
            Class::Measurement,
        )),
        "fulcrum candidates <cell> --repo ~/www/gzippy   (a ratio gap is an algorithmic question)",
    ),
    then(
        gated("anatomy explain", C(
            "anatomy explain",
            "Do the level knobs we DECLARE match what the binary actually does?",
            "--ours CMD, --corpus FILE (gzippy built --features anatomy-counters)",
            "fulcrum anatomy explain --ours '~/www/gzippy/target/release/gzippy -{level} -p1 -c {input}' --corpus ~/www/gzippy-bench/corpus/silesia.tar --levels 0-9",
            Class::Measurement,
        )),
        "a declared knob that does not move observed behaviour is a defect, not a tuning opportunity",
    ),
    // ---- banked artifacts ----------------------------------------------------
    C(
        "bank",
        "Read the banked artifact stores (prior runs stay readable forever).",
        "a subcommand: finding|ledger|scoreboard",
        "fulcrum bank finding consult",
        Class::Analysis,
    ),
    then(
        C(
            "bank finding",
            "What has already been established, with a citation I can quote?",
            "an action: add|cite|consult|list",
            "fulcrum bank finding consult",
            Class::Analysis,
        ),
        "fulcrum candidates <cell> --repo ~/www/gzippy   (a prior falsification is BINDING until a NEW mechanism is named)",
    ),
    C(
        "bank ledger",
        "What results have been appended, in order, tamper-evidently?",
        "a verb + a ledger path",
        "fulcrum bank ledger list",
        Class::Analysis,
    ),
    C(
        "bank scoreboard",
        "Render/diff a banked legacy scoreboard artifact.",
        "<artifact.json>",
        "fulcrum bank scoreboard render artifact.json",
        Class::Analysis,
    ),
    // ---- the instrument itself ------------------------------------------------
    then(
        C(
            "selftest",
            "Is this instrument trustworthy on THIS box? (runs every Gate-0)",
            "nothing; [name|invariants|--list]",
            "fulcrum selftest",
            Class::Exempt,
        ),
        "fulcrum selftest invariants   (the rules this binary ENFORCES, not the ones we remember)",
    ),
    then(
        gated("version", C(
            "version",
            "Which binary is this, is it the one that ships, and is another one shadowing it on PATH?",
            "nothing; [--json] [--expect SHA]",
            "fulcrum version --expect $(git -C ~/www/fulcrum rev-parse origin/main)",
            Class::Exempt,
        )),
        "run this on EVERY box before quoting a number from it — version skew is invisible until something fails",
    ),
    then(
        gated("guide", C(
            "guide",
            "I have a question — which command answers it?",
            "nothing; or words to search",
            "fulcrum guide why does this cell fail",
            Class::Exempt,
        )),
        "fulcrum commands --json   (the same surface, machine-readable)",
    ),
    then(
        C(
            "commands",
            "What is the whole capability surface, machine-readably?",
            "nothing; [--json]",
            "fulcrum commands --json",
            Class::Exempt,
        ),
        "fulcrum guide <words>   (search by the question instead of the name)",
    ),
];

/// One QUESTION an agent arrives with, mapped to the exact lines to run.
#[derive(Debug, Clone, Copy)]
pub struct Intent {
    pub id: &'static str,
    /// The question in the words someone would actually use.
    pub question: &'static str,
    /// Extra search terms (the question's own words are searched too).
    pub keywords: &'static [&'static str],
    /// Literal command lines, in the order they should be run.
    pub run: &'static [&'static str],
    /// Why you can trust it / what it refuses / the scar behind it.
    pub note: &'static str,
}

/// THE TASK INDEX. Ordered by how often the campaign needs it.
pub const INTENTS: &[Intent] = &[
    Intent {
        id: "stand",
        question: "Where do we stand? What is failing and what should I work on?",
        keywords: &["board", "failing", "cells", "status", "worst", "priority", "scoreboard", "stand"],
        run: &[
            "fulcrum board --size <banked size-census DIR> --wall <banked wall-census DIR>",
            "cd ~/www/gzippy && make board-size     # derives the size axis with the corpus/rival guards on",
        ],
        note: "Ranks failing cells by gap, flags cells measured against a different subject commit as \
               STALE, and always prints the denominator. Name the CLASS (rival x thread count), not the \
               cell: libdeflate-at-T4 was 48 of 68 failures while libdeflate-at-T1 was ZERO.",
    },
    Intent {
        id: "why",
        question: "Why does this cell fail? What is the mechanism?",
        keywords: &["why", "mechanism", "vendor", "diff", "cause", "gap", "slower", "bigger", "callgrind"],
        run: &["fulcrum why <cell> --repo ~/www/gzippy"],
        note: "FOUR layers automatically: [1] anatomy position-count structure verdict (same algorithm vs \
               different work), [2] callgrind per-line Ir+Dr for BOTH arms (refuses a rival built without \
               -g — one opaque symbol is not an attribution), [3] paired counters with threads MATCHED, \
               [4] declared-parameter diff. It states its own denominator: skipped layers are NOT covered \
               by any claim. The cell id already names the rival and the corpus, so --repo derives both \
               from the repo's own declared tables and REFUSES an undeclared one by name. \
               Do not hand-build this — 3 of 3 wins came from a vendor diff, 3 of 3 failures \
               from reading our own profile's top line.",
    },
    Intent {
        id: "what-next",
        question: "What should I try? Has this idea already been falsified?",
        keywords: &["candidates", "try", "idea", "technique", "falsify", "falsified", "next", "lever", "options"],
        run: &["fulcrum candidates <cell> --repo ~/www/gzippy"],
        note: "Lists vendor-precedented techniques we do NOT already do, with citations, and surfaces \
               FALSIFY records LOUDLY. A FALSIFY note is binding: run this BEFORE building anything, or \
               you will rebuild something already refuted (it happened twice in one session).",
    },
    Intent {
        id: "is-it-good",
        question: "Is my change good? Can I ship it?",
        keywords: &["ship", "promote", "promotion", "good", "gate", "merge", "verdict", "regression", "faster", "smaller"],
        run: &[
            "fulcrum try <after-ref> --base origin/main --repo ~/www/gzippy --rival name=CMD --corpus FILE --levels 2,6,9",
            "cd ~/www/gzippy && make lever REF=<ref>          # the same thing with the campaign's declared corpus and rivals",
        ],
        note: "Builds BOTH arms from git refs (a stale control is impossible, a NO-OP is refused), verifies \
               roundtrip, runs size+wall censuses at a shallow AND a deep level (single-level verdicts are \
               REFUSED — measuring L2 alone once shipped a 6.2% L6 and 9.9% L9 regression), then applies \
               the promotion rule clause by clause.",
    },
    Intent {
        id: "correct",
        question: "Is the output still correct? Did I break anything?",
        keywords: &["correct", "correctness", "roundtrip", "valid", "sha", "broken", "oracle", "decompress"],
        run: &["fulcrum verify --ours 'CMD -{level} -p {threads} -c {input}' --decoder 'CMD -d -p {threads} -c {input}' --corpus FILE --cross 'gzip -dc'"],
        note: "Compress, decompress with OUR decoder at every thread count, sha256 against the original, \
               plus every independent decoder present. Deterministic — no rig, no timing, no statistics. \
               Byte-identity with a vendor is NOT the oracle and never was.",
    },
    Intent {
        id: "dropin",
        question: "Did I break drop-in CLI compatibility? Does it still behave like gzip?",
        keywords: &["dropin", "drop-in", "cli", "compatible", "compatibility", "behaviour", "behavior", "flags", "in-place", "observable"],
        run: &["fulcrum dropin --ours PATH --rival gzip=gzip --rival pigz=pigz --fixture FILE --out DIR"],
        note: "THE AXIS THAT WENT UNMEASURED FOR A WHOLE CAMPAIGN. size x wall can be 100% green while \
               `gzip file` or `gzip -dk archive.gz` silently behaves differently. Diffs exit code, stdout, \
               stderr shape, created/removed/modified files, permission bits and roundtrip across a fixed \
               scenario surface. A difference is DIVERGENT until you declare it with a reason.",
    },
    Intent {
        id: "structure",
        question: "Where do the allocations and the memory go?",
        keywords: &["alloc", "allocation", "memory", "rss", "bytes", "structure", "copies", "malloc"],
        run: &[
            "fulcrum structcensus --ours 'CMD -{level} -p {threads} -c {input}' --rival name=CMD --corpus FILE",
            "fulcrum profile rss -- CMD ARGS…",
        ],
        note: "Deterministic: no frozen box, no paired CI, no noise floor — the CHEAPEST falsifier, so run \
               it before any wall work. Pass two sizes of the same data for the SCALING verdict. Receipt: \
               731 allocations / 83.9 MB to compress 6 MB, against libdeflate's 3 / 6.7 MB, unnoticed for \
               months because every census we owned measured OUTCOMES.",
    },
    Intent {
        id: "time",
        question: "Where does the time go?",
        keywords: &["time", "profile", "hot", "slow", "cycles", "instructions", "counters", "perf", "stall", "ipc"],
        run: &[
            "fulcrum why <cell> --repo ~/www/gzippy      # start here: the vendor-diffed version of this question",
            "fulcrum profile counters --a-cmd '…' --b-cmd '…'",
            "fulcrum profile topdown --a-stat a.stat --b-stat b.stat",
        ],
        note: "Instruction and read counts LOCATE; they NEVER predict the wall. Receipts: a change that cut \
               Ir 1.77% and Dr 3.87% was 9.9% SLOWER at L9; deleting 25.6M loads made the wall 1.77% WORSE. \
               Always confirm on the wall, paired, under a freeze.",
    },
    Intent {
        id: "threads",
        question: "Why doesn't it scale with threads? Is a thread starved?",
        keywords: &["thread", "threads", "parallel", "scaling", "starved", "starvation", "t4", "t16", "consumer", "trace"],
        run: &[
            "fulcrum trace occupancy trace.json",
            "fulcrum trace scaling --at 4:t4.json --at 16:t16.json --config gzippy",
            "fulcrum trace dispatchgap events.jsonl",
        ],
        note: "The starvation/causation tooling that won parallel decode. Measure at the coordinate where \
               the cells FAIL: the parse-config space was closed as unaffordable against T1 slack of 0-8% \
               when the failing cells were T4 with 249-330% slack — a 40x budget error.",
    },
    Intent {
        id: "ab",
        question: "Is A actually faster than B?",
        keywords: &["ab", "a/b", "paired", "faster", "compare", "benchmark", "wall", "significance", "noise"],
        run: &[
            "fulcrum freeze run --ttl-s 900 -- fulcrum ab paired --a-cmd '…' --b-cmd '…' --n 15",
            "fulcrum ab ablate --repo ~/www/gzippy --base origin/main --after <ref> --class name=FILE",
        ],
        note: "Interleaved paired-Δ with a MANDATORY A/A certificate; SINK LAW on both arms; VOID on A/A \
               bias. Report the paired-difference CI, never marginal spread. Never hand-roll this.",
    },
    Intent {
        id: "freeze",
        question: "How do I make the box quiet before measuring?",
        keywords: &["freeze", "quiet", "box", "governor", "boost", "noise", "pin", "llama"],
        run: &[
            "fulcrum freeze run --ttl-s 600 -- <the measurement command>",
            "fulcrum freeze status",
            "fulcrum freeze release",
        ],
        note: "`freeze run` is the only form that cannot orphan a stopped process — SIGCONT on every exit \
               path plus a TTL watchdog. Prefer it over acquire/release.",
    },
    Intent {
        id: "knobs",
        question: "What do our level knobs actually do?",
        keywords: &["knob", "knobs", "level", "levels", "parameters", "config", "declared", "strategy", "depth"],
        run: &["fulcrum anatomy explain --ours 'CMD -{level} -p1 -c {input}' --corpus FILE --levels 0-9"],
        note: "Puts each level's DECLARED knobs beside the OBSERVED behaviour and refuses loudly when they \
               disagree. A mismatch between declared knobs and observed behaviour is a DEFECT. It found \
               the ladder to be mostly decorative.",
    },
    Intent {
        id: "regression",
        question: "Which commit made it worse?",
        keywords: &["regress", "regression", "bisect", "worse", "broke", "when", "commit"],
        run: &["fulcrum ab bisect --repo ~/www/gzippy --run '{bin} -6 -p {threads} -c {corpus} > /dev/null' --refs a,b,c"],
        note: "Names the regressing TRANSITION in a build chain, with both arms built from refs.",
    },
    Intent {
        id: "trust",
        question: "Can I trust this instrument / this box / this binary?",
        keywords: &["trust", "selftest", "gate", "gate-0", "version", "stale", "skew", "provenance", "deploy", "which binary"],
        run: &[
            "fulcrum version --json",
            "fulcrum version --expect $(git -C ~/www/fulcrum rev-parse origin/main)",
            "fulcrum selftest",
            "fulcrum selftest invariants",
        ],
        note: "A measurement from an unidentified binary is not a measurement. Run `version --expect` on \
               EVERY box before quoting a number from it: a stale /usr/local/bin/fulcrum on a remote box \
               once lacked whole commands, and two weeks of measurements were taken with an instrument \
               that was missing half the tool set.",
    },
    Intent {
        id: "prior",
        question: "What do we already know? Has this been measured before?",
        keywords: &["known", "prior", "already", "finding", "findings", "banked", "ledger", "history", "record"],
        run: &[
            "fulcrum bank finding consult",
            "fulcrum candidates <cell> --repo ~/www/gzippy    # surfaces the binding FALSIFY records",
        ],
        note: "A prior falsification is BINDING until a NEW mechanism is named. Check before building, not \
               after measuring.",
    },
];

// ---------------------------------------------------------------------------
// Lookup
// ---------------------------------------------------------------------------

/// The distinct first tokens of every registered path — `main.rs`'s known-
/// subcommand list is derived from this so the registry cannot advertise a
/// command the dispatcher does not know.
pub fn top_level_names() -> Vec<&'static str> {
    let mut v: Vec<&'static str> = COMMANDS
        .iter()
        .filter_map(|c| c.path.split_whitespace().next())
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// The registry entry for an argv, by LONGEST matching path (so `board size …`
/// resolves to `board size`, not `board`).
pub fn lookup(args: &[String]) -> Option<&'static Cmd> {
    let mut best: Option<&'static Cmd> = None;
    for c in COMMANDS {
        let toks: Vec<&str> = c.path.split_whitespace().collect();
        if args.len() >= toks.len() && toks.iter().enumerate().all(|(i, t)| args[i] == *t) {
            let better = best.map(|b| b.path.len() < c.path.len()).unwrap_or(true);
            if better {
                best = Some(c);
            }
        }
    }
    best
}

/// True when this argv is asking for help (a bare `--help`/`-h`/`help` token).
pub fn is_help_request(args: &[String]) -> bool {
    args.iter().any(|a| a == "--help" || a == "-h" || a == "help")
}

/// Render one registry entry the way `--help` shows it.
pub fn render_cmd(c: &Cmd) -> String {
    let mut s = String::new();
    s.push_str(&format!("fulcrum {}\n", c.path));
    s.push_str(&format!("  ANSWERS   {}\n", c.question));
    s.push_str(&format!("  REQUIRES  {}\n", c.required));
    s.push_str(&format!("  EXAMPLE   {}\n", c.example));
    s.push_str(&format!(
        "  CLASS     {}{}\n",
        c.class.as_str(),
        match c.class {
            Class::Measurement => " (REFUSES to run from a stale binary)",
            Class::Analysis => " (self-updates when safe)",
            Class::Exempt => "",
        }
    ));
    if let Some(g) = c.gate0 {
        s.push_str(&format!("  GATE-0    fulcrum selftest \"{g}\"\n"));
    }
    if let Some(n) = c.next {
        s.push_str(&format!("  NEXT      {n}\n"));
    }
    s
}

fn render_intent(it: &Intent, detail: bool) -> String {
    let mut s = String::new();
    s.push_str(&format!("Q: {}\n", it.question));
    for line in it.run {
        s.push_str(&format!("   $ {line}\n"));
    }
    if detail {
        for line in wrap(it.note, 88) {
            s.push_str(&format!("   {line}\n"));
        }
    }
    s
}

fn wrap(s: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for w in s.split_whitespace() {
        if !cur.is_empty() && cur.len() + 1 + w.len() > width {
            out.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(w);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Score an intent against free-text words. Question text and keywords both
/// count; a keyword hit is worth more than an incidental word.
pub fn score(it: &Intent, words: &[String]) -> u32 {
    let q = it.question.to_lowercase();
    let id = it.id.to_lowercase();
    let mut n = 0;
    for raw in words {
        let w = raw.to_lowercase();
        if w.len() < 2 {
            continue;
        }
        if id == w {
            n += 5;
        }
        if it.keywords.iter().any(|k| *k == w) {
            n += 3;
        } else if it.keywords.iter().any(|k| k.contains(&w) || w.contains(*k)) {
            n += 1;
        }
        if q.contains(&w) {
            n += 1;
        }
    }
    n
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

fn cmd_json(c: &Cmd) -> serde_json::Value {
    serde_json::json!({
        "path": c.path,
        "answers": c.question,
        "requires": c.required,
        "example": c.example,
        "class": c.class.as_str(),
        "gate0": c.gate0,
        "gate0_cmd": c.gate0.map(|g| format!("fulcrum selftest \"{g}\"")),
        "next": c.next,
    })
}

fn intent_json(it: &Intent) -> serde_json::Value {
    serde_json::json!({
        "id": it.id,
        "question": it.question,
        "keywords": it.keywords,
        "run": it.run,
        "note": it.note,
    })
}

pub fn registry_json() -> serde_json::Value {
    serde_json::json!({
        "fulcrum_commit": crate::selfver::COMMIT,
        "commands": COMMANDS.iter().map(cmd_json).collect::<Vec<_>>(),
        "intents": INTENTS.iter().map(intent_json).collect::<Vec<_>>(),
    })
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn banner() -> String {
    "FULCRUM GUIDE — indexed by the QUESTION you arrived with, not by command name.\n\
     Every line below is literally runnable; replace only the <angle-bracket> parts.\n"
        .to_string()
}

/// `fulcrum guide [words…] [--json]`
pub fn cmd_guide(args: &[String]) -> ExitCode {
    if args.first().map(|s| s.as_str()) == Some("selftest") {
        return selftest();
    }
    if args.iter().any(|a| a == "--json") {
        println!("{}", serde_json::to_string_pretty(&registry_json()).unwrap_or_default());
        return ExitCode::SUCCESS;
    }
    let words: Vec<String> = args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .filter(|a| *a != "help")
        .cloned()
        .collect();

    if words.is_empty() {
        print!("{}", banner());
        println!();
        for it in INTENTS {
            print!("{}", render_intent(it, false));
            println!();
        }
        println!("For the full rationale on one of these:  fulcrum guide <words from the question>");
        println!("For the whole surface, machine-readable:  fulcrum commands --json");
        println!("For the rules this binary ENFORCES:       fulcrum selftest invariants");
        return ExitCode::SUCCESS;
    }

    let mut scored: Vec<(u32, &Intent)> = INTENTS
        .iter()
        .map(|it| (score(it, &words), it))
        .filter(|(n, _)| *n > 0)
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0));

    if scored.is_empty() {
        println!(
            "No intent matched {:?}. The whole index follows — if your question is genuinely not\n\
             here, that is a gap in this registry, not in the tool set: say so in the commit that\n\
             adds it.\n",
            words.join(" ")
        );
        for it in INTENTS {
            print!("{}", render_intent(it, false));
            println!();
        }
        return ExitCode::SUCCESS;
    }

    println!("{} matching intent(s) for {:?}:\n", scored.len(), words.join(" "));
    for (i, (_, it)) in scored.iter().take(3).enumerate() {
        if i > 0 {
            println!();
        }
        print!("{}", render_intent(it, true));
    }
    if scored.len() > 3 {
        println!();
        println!("also: {}", scored[3..].iter().map(|(_, it)| it.id).collect::<Vec<_>>().join(", "));
    }
    ExitCode::SUCCESS
}

/// `fulcrum commands [--json]`
pub fn cmd_commands(args: &[String]) -> ExitCode {
    if args.first().map(|s| s.as_str()) == Some("selftest") {
        return selftest();
    }
    if args.iter().any(|a| a == "--json") {
        println!("{}", serde_json::to_string_pretty(&registry_json()).unwrap_or_default());
        return ExitCode::SUCCESS;
    }
    println!(
        "{} commands. Each line: the path, then the QUESTION it answers.\n\
         `fulcrum commands --json` emits paths, required args, examples, classes and Gate-0s.\n",
        COMMANDS.len()
    );
    let w = COMMANDS.iter().map(|c| c.path.len()).max().unwrap_or(10);
    for c in COMMANDS {
        println!("  {:w$}  {}", c.path, c.question, w = w);
    }
    println!("\nStart from the question instead:  fulcrum guide");
    ExitCode::SUCCESS
}

// ---------------------------------------------------------------------------
// Gate-0
// ---------------------------------------------------------------------------

/// Gate-0: the registry is EXECUTABLE truth, not documentation.
///
/// 1. Every advertised path resolves in the real dispatcher (run in a
///    subprocess, asserting the binary does not answer "unknown subcommand").
/// 2. Every example starts with `fulcrum <path>` — an example that drifts off
///    its own command is how a copy-pasteable line stops being runnable.
/// 3. Every intent's command line names a REGISTERED path (no intent can point
///    at a command that does not exist).
/// 4. `lookup` prefers the longest path, so `board size` never resolves to
///    `board`.
pub fn selftest() -> ExitCode {
    let pass = std::cell::Cell::new(0u32);
    let fail = std::cell::Cell::new(0u32);
    let check = |name: String, ok: bool| {
        if ok {
            pass.set(pass.get() + 1);
            println!("  PASS {name}");
        } else {
            fail.set(fail.get() + 1);
            println!("  FAIL {name}");
        }
    };

    // --- structural checks -------------------------------------------------
    for c in COMMANDS {
        check(
            format!("registry: `{}` example starts with its own path", c.path),
            c.example.starts_with(&format!("fulcrum {}", c.path)),
        );
        check(
            format!("registry: `{}` states a question and required args", c.path),
            !c.question.is_empty() && !c.required.is_empty(),
        );
        if let Some(n) = c.next {
            // A next action that names a command that does not exist is worse
            // than none: it is a dead end presented as the way forward.
            if let Some(rest) = n.strip_prefix("fulcrum ") {
                let argv: Vec<String> = rest
                    .split_whitespace()
                    .take_while(|t| !t.starts_with('-') && !t.starts_with('<'))
                    .map(|s| s.to_string())
                    .collect();
                check(
                    format!("registry: `{}` NEXT ACTION names a real command", c.path),
                    !argv.is_empty() && lookup(&argv).is_some(),
                );
            }
        }
        if let Some(g) = c.gate0 {
            check(
                format!("registry: `{}` advertises a Gate-0 that EXISTS (`{g}`)", c.path),
                crate::selftest::gate_names().contains(&g),
            );
        }
    }
    {
        let mut seen: Vec<&str> = COMMANDS.iter().map(|c| c.path).collect();
        let n = seen.len();
        seen.sort_unstable();
        seen.dedup();
        check("registry: no duplicate paths".to_string(), seen.len() == n);
    }
    for it in INTENTS {
        check(
            format!("intent `{}`: has at least one runnable line", it.id),
            !it.run.is_empty(),
        );
        for line in it.run {
            let head = line.split('#').next().unwrap_or(line).trim();
            if !head.starts_with("fulcrum ") {
                // Non-fulcrum lines (e.g. `cd … && make board-size`) are allowed
                // but must still mention a real entry point.
                check(
                    format!("intent `{}`: non-fulcrum line names a real target: {head}", it.id),
                    head.contains("make ") || head.contains("fulcrum"),
                );
                continue;
            }
            let argv: Vec<String> = head
                .split_whitespace()
                .skip(1)
                .map(|s| s.to_string())
                .collect();
            check(
                format!("intent `{}`: `fulcrum {}` is a registered path", it.id, argv.first().cloned().unwrap_or_default()),
                lookup(&argv).is_some(),
            );
        }
    }
    // longest-path preference
    {
        let argv: Vec<String> = vec!["board".into(), "size".into(), "--out".into(), "x".into()];
        check(
            "lookup: `board size …` resolves to `board size`, not `board`".to_string(),
            lookup(&argv).map(|c| c.path) == Some("board size"),
        );
        let argv: Vec<String> = vec!["board".into(), "--size".into(), "x".into()];
        check(
            "lookup: `board --size …` resolves to `board`".to_string(),
            lookup(&argv).map(|c| c.path) == Some("board"),
        );
        check(
            "is_help_request: bare --help/-h/help only".to_string(),
            is_help_request(&["--help".to_string()])
                && is_help_request(&["x".to_string(), "-h".to_string()])
                && !is_help_request(&["--helpful".to_string()]),
        );
    }

    // --- executable check: every advertised path really dispatches ---------
    match std::env::current_exe() {
        Err(e) => {
            println!("  FAIL exec: cannot find own binary ({e}) — the resolve check did not run");
            fail.set(fail.get() + 1);
        }
        Ok(exe) => {
            for c in COMMANDS {
                let mut cmd = std::process::Command::new(&exe);
                for t in c.path.split_whitespace() {
                    cmd.arg(t);
                }
                cmd.arg("--help");
                // Never let a child self-update or rebuild during a selftest.
                cmd.env("FULCRUM_SELFUPDATED", "1");
                let out = cmd.output();
                match out {
                    Err(e) => {
                        println!("  FAIL exec `{}`: {e}", c.path);
                        fail.set(fail.get() + 1);
                    }
                    Ok(o) => {
                        let text = format!(
                            "{}{}",
                            String::from_utf8_lossy(&o.stdout),
                            String::from_utf8_lossy(&o.stderr)
                        );
                        let unknown = text.contains("unknown subcommand")
                            || text.contains("unknown arg")
                            || text.contains("unknown action")
                            || text.contains("unknown option")
                            || text.contains("unknown flag")
                            || text.contains("unknown/unexpected argument");
                        check(
                            format!("exec: `fulcrum {} --help` resolves", c.path),
                            !unknown,
                        );
                        check(
                            format!("exec: `fulcrum {} --help` exits 0", c.path),
                            o.status.success(),
                        );
                        check(
                            format!("exec: `fulcrum {} --help` prints something", c.path),
                            text.lines().filter(|l| !l.trim().is_empty()).count() >= 2,
                        );
                    }
                }
            }
        }
    }

    println!(
        "GUIDE_SELFTEST={} pass={} fail={}",
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
