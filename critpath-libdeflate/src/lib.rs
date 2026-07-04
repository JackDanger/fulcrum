//! Rust bindings to the INSTRUMENTED libdeflate 1.25 gzip decoder.
//!
//! This crate exposes the SAME control/measurement surface as
//! `gzippy::critpath_rt` (region markers, CNTVCT reads, injection, calibration
//! kernels), but backed by libdeflate's C decode loop instead of gzippy's
//! pure-Rust one. `fulcrum critpath --target libdeflate` drives it through the
//! identical protocol so the two decoders' per-region active-time can be
//! compared apples-to-apples (the differential kernel localizer).
//!
//! All FFI symbols are `cpld_`-prefixed; the underlying libdeflate public
//! symbols are renamed at build time (see build.rs / cpld_prefix.h) so this
//! never collides with the `libdeflater` crate that fulcrum also links.

use std::os::raw::{c_int, c_long};

/// Region ids — index-aligned with `gzippy::critpath_rt::region`.
pub mod region {
    pub const REFILL: usize = 0;
    pub const TABLE_LOAD: usize = 1;
    pub const CONSUME: usize = 2;
    pub const STORE: usize = 3;
    pub const MATCH_COPY: usize = 4;
    pub const DIST_LOOKUP: usize = 5;
    pub const CRC: usize = 6;
    pub const CALIB_SERIAL: usize = 7;
    pub const CALIB_OVERLAPPED: usize = 8;
    pub const EMPTY_TAX: usize = 9;
}

pub const N_REGIONS: usize = 10;

pub const REGION_NAMES: [&str; N_REGIONS] = [
    "refill",
    "table_load",
    "consume",
    "store",
    "match_copy",
    "dist_lookup",
    "crc",
    "calib_serial",
    "calib_overlapped",
    "empty_tax",
];

extern "C" {
    fn cpld_set_enabled(on: c_int);
    fn cpld_select(r: c_long);
    fn cpld_set_dose(d: u64);
    fn cpld_reset_counters();
    fn cpld_snapshot(active_out: *mut u64, fires_out: *mut u64, injected_out: *mut u64);
    fn cpld_n_regions() -> c_int;
    fn cpld_cntvct_ffi() -> u64;
    fn cpld_cntfrq_ffi() -> u64;
    fn cpld_inject_ffi(n: u64) -> u64;
    fn cpld_calib_serial(iters: u64) -> u64;
    fn cpld_calib_overlapped(iters: u64, buf: *const u64, len: usize) -> u64;
    fn cpld_calib_empty(iters: u64) -> u64;
    fn cpld_gzip_decode(
        input: *const u8,
        in_len: usize,
        out: *mut u8,
        out_cap: usize,
        ok: *mut c_int,
    ) -> usize;
}

#[inline]
pub fn set_enabled(on: bool) {
    unsafe { cpld_set_enabled(on as c_int) }
}

#[inline]
pub fn select(r: Option<usize>) {
    unsafe { cpld_select(r.map(|x| x as c_long).unwrap_or(-1)) }
}

#[inline]
pub fn set_dose(d: u64) {
    unsafe { cpld_set_dose(d) }
}

#[inline]
pub fn reset_counters() {
    unsafe { cpld_reset_counters() }
}

/// `(active_ticks, fires, injected_ticks)` — same shape as critpath_rt::snapshot.
pub fn snapshot() -> (Vec<u64>, Vec<u64>, u64) {
    let mut active = vec![0u64; N_REGIONS];
    let mut fires = vec![0u64; N_REGIONS];
    let mut injected = 0u64;
    unsafe { cpld_snapshot(active.as_mut_ptr(), fires.as_mut_ptr(), &mut injected) }
    (active, fires, injected)
}

#[inline]
pub fn n_regions() -> usize {
    unsafe { cpld_n_regions() as usize }
}

#[inline]
pub fn cntvct() -> u64 {
    unsafe { cpld_cntvct_ffi() }
}

#[inline]
pub fn cntfrq() -> u64 {
    unsafe { cpld_cntfrq_ffi() }
}

#[inline]
pub fn inject(n: u64) -> u64 {
    unsafe { cpld_inject_ffi(n) }
}

#[inline]
pub fn calib_serial(iters: u64) -> u64 {
    unsafe { cpld_calib_serial(iters) }
}

#[inline]
pub fn calib_overlapped(iters: u64, buf: &[u64]) -> u64 {
    unsafe { cpld_calib_overlapped(iters, buf.as_ptr(), buf.len()) }
}

#[inline]
pub fn calib_empty(iters: u64) -> u64 {
    unsafe { cpld_calib_empty(iters) }
}

/// Pointer-chase buffer — byte-identical fill to critpath_rt::make_chase_buf so
/// the overlapped-calibration ground truth is the same on both subjects.
pub fn make_chase_buf(n: usize) -> Vec<u64> {
    assert!(n.is_power_of_two());
    let mut v = vec![0u64; n];
    let mut s: u64 = 0x243F6A8885A308D3;
    for slot in v.iter_mut() {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
        *slot = (s >> 11) % (n as u64);
    }
    v
}

/// Decode a gzip stream via the instrumented libdeflate. Returns bytes written.
/// Panics on decode failure (the harness's oracle gate catches wrong bytes).
pub fn gzip_decode(input: &[u8], out: &mut [u8]) -> usize {
    let mut ok: c_int = 0;
    let n = unsafe {
        cpld_gzip_decode(
            input.as_ptr(),
            input.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut ok,
        )
    };
    assert!(ok != 0, "instrumented libdeflate gzip_decode failed");
    n
}
