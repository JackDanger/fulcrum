/*
 * cpld_markers.h — critpath region markers for instrumented libdeflate.
 *
 * SEMANTIC TWIN of gzippy's `src/critpath_rt.rs` (feat/critpath-markers).
 * The whole point of this crate is a DIFFERENTIAL kernel localizer: run the
 * EXACT same `fulcrum critpath` protocol (CNTVCT active-time tick-sum
 * bracketing + injected-delay criticality slope) against libdeflate's gzip
 * decode loop, with the markers ALIGNED to the same six operations gzippy
 * brackets, so the per-region active-time can be compared apples-to-apples.
 *
 * BALANCE (the footgun gate). Each region fire is bracketed by EXACTLY TWO
 * CNTVCT reads (begin + end) and an armed-injection check — identical to the
 * Rust markers (`region_begin`/`region_end`). The empty-bracket per-fire tax
 * is calibrated (`cpld_calib_empty`) and subtracted by the tool, on BOTH
 * decoders. The injection kernel is the same independent MAC chain.
 *
 * Region ids are index-aligned with gzippy::critpath_rt::region.
 */
#ifndef CPLD_MARKERS_H
#define CPLD_MARKERS_H

#include <stdint.h>
#include <stddef.h>

#define CPLD_REFILL      0
#define CPLD_TABLE_LOAD  1
#define CPLD_CONSUME     2
#define CPLD_STORE       3
#define CPLD_MATCH_COPY  4
#define CPLD_DIST_LOOKUP 5
#define CPLD_CRC         6
#define CPLD_CALIB_SERIAL     7
#define CPLD_CALIB_OVERLAPPED 8
#define CPLD_EMPTY_TAX        9
#define CPLD_N_REGIONS   10

#define CPLD_NONE ((size_t)-1)

/* Shared control + accumulator state (defined once in cpld_markers.c, prefixed
 * so it never collides with the `libdeflater` crate's libdeflate). */
extern int      cpld_enabled;
extern size_t   cpld_selected;     /* CPLD_NONE => perturb nothing */
extern uint64_t cpld_dose;
extern uint64_t cpld_active_ticks[CPLD_N_REGIONS];
extern uint64_t cpld_fires[CPLD_N_REGIONS];
extern uint64_t cpld_injected_ticks;

/* Read the 24 MHz architectural timer. Mirrors critpath_rt::cntvct (no memory
 * clobber, so the per-read overhead matches the Rust `options(nomem,nostack)`
 * marker). Compiles to 0 off aarch64 so the crate still builds. */
static inline uint64_t cpld_cntvct(void)
{
#if defined(__aarch64__)
	uint64_t v;
	__asm__ volatile("mrs %0, cntvct_el0" : "=r"(v));
	return v;
#else
	return 0;
#endif
}

static inline uint64_t cpld_cntfrq(void)
{
#if defined(__aarch64__)
	uint64_t v;
	__asm__ volatile("mrs %0, cntfrq_el0" : "=r"(v));
	return v;
#else
	return 24000000ULL;
#endif
}

/* Independent-ALU delay kernel — twin of critpath_rt::inject. noinline + an
 * empty volatile asm per iteration so the optimizer cannot delete or hoist it,
 * and its result is independent of the decode dataflow (the OoO core MAY hide
 * it — that is exactly what the criticality slope measures). */
uint64_t cpld_inject(uint64_t n);

/* The ONE injection primitive (twin of critpath_rt::maybe_inject). If r is the
 * armed target with a nonzero dose, run the delay kernel, accumulate its
 * MEASURED ticks, and return its result; else return 0. */
static inline uint64_t cpld_maybe_inject(size_t r)
{
	uint64_t dose = cpld_dose;
	if (dose != 0 && cpld_selected == r) {
		uint64_t s = cpld_cntvct();
		uint64_t v = cpld_inject(dose);
		uint64_t e = cpld_cntvct();
		cpld_injected_ticks += e - s;
		return v;
	}
	return 0;
}

#ifdef CPLD_COARSE_ONLY
/* COARSE-ONLY build (kpcphase): the per-symbol CNTVCT region markers are
 * stripped to no-ops so the decode is a clean, faithful-cost libdeflate whose
 * retired-instruction count matches the uninstrumented library (~1472.6M on M1
 * silesia) — the ONLY per-block instrumentation left is the coarse `CPLD_PHASE`
 * switch. The macro bodies still execute their REAL work (refill / table load /
 * consume / store / copy); only the timestamp reads vanish. */
static inline uint64_t cpld_region_begin(size_t r) { (void)r; return 0; }
static inline void cpld_region_end(size_t r, uint64_t t0) { (void)r; (void)t0; }
#else
/* Enter region r: run the (independent) injection if armed, then return the
 * begin timestamp. Twin of critpath_rt::region_begin. */
static inline uint64_t cpld_region_begin(size_t r)
{
	uint64_t inj = cpld_maybe_inject(r);
	/* keep the injected value live but independent (black_box twin) */
	__asm__ volatile("" : : "r"(inj));
	return cpld_cntvct();
}

/* Close region r: accumulate elapsed ticks and bump the fire count. Twin of
 * critpath_rt::region_end. */
static inline void cpld_region_end(size_t r, uint64_t t0)
{
	uint64_t d = cpld_cntvct() - t0;
	cpld_active_ticks[r] += d;
	cpld_fires[r] += 1;
}
#endif

/* Bracket macros used in the instrumented decompress_template.h. */
#define CPLD_BEGIN(R)     cpld_region_begin((R))
#define CPLD_END(R, T0)   cpld_region_end((R), (T0))

/* ── COARSE PER-PHASE RETIRED-INSTRUCTION HOOK (kpcphase) ──
 * A single symbol both decoders call at coarse deflate-block phase boundaries.
 * Resolves to fulcrum's `fx_phase_switch` (fulcrum::macmeasure::phase) at final
 * link; a weak no-op default in cpld_markers.c lets this crate's own example
 * binaries link standalone. Phase ids are index-aligned with the Rust side. */
extern void fx_phase_switch(unsigned p);
#define CPLD_PH_OTHER    0u
#define CPLD_PH_HEADER   1u
#define CPLD_PH_BUILD    2u
#define CPLD_PH_FASTLOOP 3u
#define CPLD_PHASE(P)    fx_phase_switch((P))

/* ── Control surface (driven in-process by fulcrum critpath via FFI) ── */
void     cpld_set_enabled(int on);
void     cpld_select(long r);          /* <0 => none */
void     cpld_set_dose(uint64_t d);
void     cpld_reset_counters(void);
/* Snapshot: active_out[CPLD_N_REGIONS], fires_out[CPLD_N_REGIONS], *injected. */
void     cpld_snapshot(uint64_t *active_out, uint64_t *fires_out,
		       uint64_t *injected_out);
int      cpld_n_regions(void);
uint64_t cpld_cntvct_ffi(void);
uint64_t cpld_cntfrq_ffi(void);
uint64_t cpld_inject_ffi(uint64_t n);

/* ── Calibration kernels (ground truth for the criticality self-tests) ──
 * Twins of critpath_rt::{calib_serial,calib_overlapped,calib_empty}. They use
 * the SAME region_begin/region_end/inject primitive as the real markers so the
 * Gate-0 self-test validates the exact mechanism used on the decode. */
uint64_t cpld_calib_serial(uint64_t iters);
uint64_t cpld_calib_overlapped(uint64_t iters, const uint64_t *buf, size_t len);
uint64_t cpld_calib_empty(uint64_t iters);

/* ── Decode entry — gzip single-shot via the instrumented libdeflate ──
 * Returns bytes written; *ok=1 on LIBDEFLATE_SUCCESS else 0. */
size_t   cpld_gzip_decode(const uint8_t *in, size_t in_len,
			  uint8_t *out, size_t out_cap, int *ok);

#endif /* CPLD_MARKERS_H */
