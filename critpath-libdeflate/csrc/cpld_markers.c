/*
 * cpld_markers.c — definitions for the instrumented-libdeflate critpath markers.
 *
 * Defines the shared control/accumulator state, the injection + calibration
 * kernels, the FFI control surface, and the gzip decode entry. All twins of
 * gzippy::critpath_rt so `fulcrum critpath` drives both decoders identically.
 *
 * cpld_prefix.h is force-included by the build, so the `libdeflate_*` calls
 * below resolve to this crate's prefixed copy (never the `libdeflater` crate's).
 */
#include "libdeflate.h"
#include "cpld_markers.h"

/* Weak no-op default for the coarse per-phase hook so this crate's example
 * binaries link standalone. When linked into the fulcrum binary, fulcrum's
 * strong `#[no_mangle] fx_phase_switch` overrides this. */
__attribute__((weak)) void fx_phase_switch(unsigned p) { (void)p; }

/* Shared state (prefixed; never collides with libdeflater). */
int      cpld_enabled = 0;
size_t   cpld_selected = CPLD_NONE;
uint64_t cpld_dose = 0;
uint64_t cpld_active_ticks[CPLD_N_REGIONS] = {0};
uint64_t cpld_fires[CPLD_N_REGIONS] = {0};
uint64_t cpld_injected_ticks = 0;

/* Twin of critpath_rt::inject: 0x9E37.. seed, MAC chain with a per-iter
 * black_box, noinline. */
__attribute__((noinline))
uint64_t cpld_inject(uint64_t n)
{
	uint64_t a = 0x9E3779B97F4A7C15ULL;
	__asm__ volatile("" : "+r"(a));
	for (uint64_t i = 0; i < n; i++) {
		a = a * 6364136223846793005ULL + (1442695040888963407ULL ^ i);
		__asm__ volatile("" : "+r"(a));
	}
	return a;
}

void cpld_set_enabled(int on)        { cpld_enabled = on; }
void cpld_select(long r)             { cpld_selected = (r < 0) ? CPLD_NONE : (size_t)r; }
void cpld_set_dose(uint64_t d)       { cpld_dose = d; }
int  cpld_n_regions(void)            { return CPLD_N_REGIONS; }
uint64_t cpld_cntvct_ffi(void)       { return cpld_cntvct(); }
uint64_t cpld_cntfrq_ffi(void)       { return cpld_cntfrq(); }
uint64_t cpld_inject_ffi(uint64_t n) { return cpld_inject(n); }

void cpld_reset_counters(void)
{
	for (int r = 0; r < CPLD_N_REGIONS; r++) {
		cpld_active_ticks[r] = 0;
		cpld_fires[r] = 0;
	}
	cpld_injected_ticks = 0;
}

void cpld_snapshot(uint64_t *active_out, uint64_t *fires_out,
		   uint64_t *injected_out)
{
	for (int r = 0; r < CPLD_N_REGIONS; r++) {
		active_out[r] = cpld_active_ticks[r];
		fires_out[r] = cpld_fires[r];
	}
	*injected_out = cpld_injected_ticks;
}

/* KNOWN-SERIAL: dependent accumulator chain; the injected work is FOLDED into
 * the chain so any injected time adds 1:1 to the wall ⇒ criticality ≈ 1.
 * Twin of critpath_rt::calib_serial. */
uint64_t cpld_calib_serial(uint64_t iters)
{
	const size_t r = CPLD_CALIB_SERIAL;
	uint64_t acc = 1;
	__asm__ volatile("" : "+r"(acc));
	for (uint64_t i = 0; i < iters; i++) {
		uint64_t inj = cpld_maybe_inject(r);
		uint64_t t0 = cpld_cntvct();
		acc ^= inj;
		acc = acc * 6364136223846793005ULL + 1442695040888963407ULL;
		acc ^= acc >> 31;
		cpld_region_end(r, t0);
		__asm__ volatile("" : "+r"(acc));
	}
	return acc;
}

/* KNOWN-OVERLAPPED: loop bottlenecked on a long dependent pointer-chase; the
 * instrumented region wraps a SHORT burst of INDEPENDENT work that hides in the
 * load's shadow ⇒ criticality clearly below serial.
 * Twin of critpath_rt::calib_overlapped. */
uint64_t cpld_calib_overlapped(uint64_t iters, const uint64_t *buf, size_t len)
{
	const size_t r = CPLD_CALIB_OVERLAPPED;
	uint64_t mask = (uint64_t)len - 1;
	uint64_t idx = 0;
	uint64_t side = 0;
	__asm__ volatile("" : "+r"(side));
	for (uint64_t i = 0; i < iters; i++) {
		idx = buf[idx & mask] & mask;       /* long-latency dependent load */
		uint64_t t0 = cpld_region_begin(r);
		side = side + 0x9E3779B97F4A7C15ULL; /* independent ALU in the shadow */
		side = (side << 7) | (side >> 57);   /* rotate_left(7) */
		cpld_region_end(r, t0);
	}
	__asm__ volatile("" : "+r"(side));
	return side + idx;
}

/* EMPTY-region marker-tax calibration: bare begin/end bracket, no body, so
 * active_ticks[EMPTY_TAX]/fires[EMPTY_TAX] is the per-fire instrument tax to
 * subtract. Twin of critpath_rt::calib_empty. */
uint64_t cpld_calib_empty(uint64_t iters)
{
	const size_t r = CPLD_EMPTY_TAX;
	uint64_t x = 0;
	for (uint64_t i = 0; i < iters; i++) {
		uint64_t t0 = cpld_region_begin(r);
		cpld_region_end(r, t0);
		x += 1;
	}
	__asm__ volatile("" : "+r"(x));
	return x;
}

size_t cpld_gzip_decode(const uint8_t *in, size_t in_len,
			uint8_t *out, size_t out_cap, int *ok)
{
	struct libdeflate_decompressor *d = libdeflate_alloc_decompressor();
	if (!d) { *ok = 0; return 0; }
	size_t actual = 0;
	enum libdeflate_result res =
		libdeflate_gzip_decompress(d, in, in_len, out, out_cap, &actual);
	libdeflate_free_decompressor(d);
	*ok = (res == LIBDEFLATE_SUCCESS) ? 1 : 0;
	return actual;
}
