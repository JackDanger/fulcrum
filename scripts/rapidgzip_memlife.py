#!/usr/bin/env python3
"""Build a rapidgzip memlife dataset (the `fulcrum memlife` schema) from
rapidgzip's own `-v` profiling statistics + the vendor SOURCE structure.

WHY this mix (not allocator-interposition): rapidgzip routes its hot buffers
through its OWN internal rpmalloc (vendor RpmallocAllocator), so an LD_PRELOAD
on system malloc misses exactly the buffers we care about — the same reason
gzippy's allocator tap only sees its rpmalloc. So we take the AUTHORITATIVE,
tool-emitted byte counts from `rapidgzip -v` (Total decompressed bytes,
Non-marker symbols, Replaced marker symbol buffers) — which are byte-IDENTICAL
to gzippy's data-read / narrowed counts on the same workload, the strongest
cross-tool fairness check available — and combine them with the per-component
traffic SHAPE read directly from the vendor source:

  DecodedData::applyWindow (DecodedData.hpp:306-391):
    - marker resolve is IN PLACE: reads markerCount u16 (×2 bytes), writes
      markerCount u8 back into the SAME `dataWithMarkers` buffer.
    - NO separate `narrowed` buffer is allocated (line 385: the output data
      view reinterpret_casts the in-place buffer; the comment at 375 notes the
      upper half of the over-wide buffer is deliberately left unused, NOT
      shrunk/copied).
    - dataWithMarkers is std::vector<MarkerVector=FasterVector<uint16_t>> in
      128 KiB granules (DecodedData.hpp:23) — same 2× width as gzippy.

CONFIDENCE per field is annotated in the output `confidence` map:
  - written/read of data + marker resolve: HIGH (tool-emitted byte counts +
    source-exact loop shape).
  - alloc_bytes: MEDIUM — source-derived (chunk buffers sized to decoded
    output; marker buffer = markerCount×2 over-wide, kept). rapidgzip's
    internal rpmalloc is not tapped, so this is a structural estimate, not a
    measured allocator total. allocator_total_bytes is left 0 (no tap) so the
    fulcrum closure check correctly reports it as not-anchored for rapidgzip.
  - rusage_* : HIGH if --rusage given (measured via /usr/bin/time -v wrapper).

Usage:
  rapidgzip_memlife.py --verbose-log rg-v.txt [--workers 8] \
      [--minflt N --majflt N --maxrss-kb N] > rapidgzip-memlife-T8.json
"""
import argparse
import json
import re
import sys


def parse_int(s: str) -> int:
    return int(s.replace("'", "").replace(",", "").strip())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose-log", required=True,
                    help="captured stderr of `rapidgzip -v -d -c ...`")
    ap.add_argument("--workers", type=int, default=0)
    ap.add_argument("--minflt", type=int, default=0)
    ap.add_argument("--majflt", type=int, default=0)
    ap.add_argument("--maxrss-kb", type=int, default=0)
    args = ap.parse_args()

    text = open(args.verbose_log).read()

    def grab(pat):
        m = re.search(pat, text)
        return parse_int(m.group(1)) if m else None

    decoded = grab(r"Total decompressed bytes\s*:\s*([\d',]+)")
    non_marker = grab(r"Non-marker symbols\s*:\s*([\d',]+)")
    marker = grab(r"Replaced marker symbol buffers\s*:\s*([\d',]+)")
    par = grab(r"Parallelization\s*:\s*([\d',]+)")
    workers = args.workers or par or 0

    if decoded is None or non_marker is None or marker is None:
        print("ERROR: could not find the byte-count lines in the -v log",
              file=sys.stderr)
        return 1

    # ── source-derived per-component traffic ────────────────────────────────
    # data: the clean (non-marker) bytes. rapidgzip appends them to chunk
    # buffers (DecodedData::append / data VectorViews). Written once, read once
    # at output (toIoVec gather, no copy).
    data = {
        "component": "data",
        "site": "DecodedData.hpp data (VectorView); ChunkData append",
        "alloc_bytes": decoded,           # chunk buffers sized to decoded out
        "alloc_count": 0,
        "written_bytes": non_marker,      # clean bytes stored
        "read_bytes": non_marker,         # output gather read
        "copied_bytes": 0,                # toIoVec is a gather, no copy
        "freed_bytes": 0,
        "alloc_paths": {},
    }
    # data_with_markers: the marker buffer (u16, 2× width, 128 KiB granules).
    # Written by the window-absent decode (markerCount u16), then applyWindow
    # READS markerCount u16 and WRITES markerCount u8 IN PLACE (no narrowed).
    dwm = {
        "component": "data_with_markers",
        "site": "DecodedData.hpp:23 MarkerVector; applyWindow:306 IN-PLACE",
        "alloc_bytes": marker * 2,        # over-wide u16, kept (line 375)
        "alloc_count": 0,
        "written_bytes": marker * 2 + marker,  # decode write (×2) + in-place u8 write
        "read_bytes": marker * 2,         # applyWindow reads u16
        "copied_bytes": 0,
        "freed_bytes": 0,
        "alloc_paths": {},
    }
    # narrowed: rapidgzip has NONE (in-place resolve). Emit a zero row so the
    # cross-tool table shows the +delta against gzippy explicitly.
    narrowed = {
        "component": "narrowed",
        "site": "ABSENT in rapidgzip — applyWindow resolves in place (no buffer)",
        "alloc_bytes": 0, "alloc_count": 0,
        "written_bytes": 0, "read_bytes": 0, "copied_bytes": 0, "freed_bytes": 0,
        "alloc_paths": {},
    }
    # window: rapidgzip stores SPARSE/compressed windows in WindowMap. The raw
    # window touched per chunk is 32 KiB; storage is compressed (smaller).
    window = {
        "component": "window",
        "site": "WindowMap (sparse/compressed); applyWindow window arg",
        "alloc_bytes": 0,   # compressed; not separately measured here
        "alloc_count": 0,
        "written_bytes": 0,
        "read_bytes": 0,
        "copied_bytes": 0, "freed_bytes": 0,
        "alloc_paths": {},
    }
    # output_write: the writev gather to the sink.
    output = {
        "component": "output_write",
        "site": "toIoVec writev gather (no copy)",
        "alloc_bytes": 0, "alloc_count": 0,
        "written_bytes": decoded, "read_bytes": 0,
        "copied_bytes": 0, "freed_bytes": 0,
        "alloc_paths": {},
    }

    run = {
        "tool": "rapidgzip",
        "decoded_bytes": decoded,
        "workers": workers,
        # No allocator tap for rapidgzip's internal rpmalloc → 0 (the fulcrum
        # closure check then reports rapidgzip's alloc as not-anchored, honest).
        "allocator_total_bytes": 0,
        "allocator_total_count": 0,
        "rusage_minflt": args.minflt,
        "rusage_majflt": args.majflt,
        "rusage_maxrss_kb": args.maxrss_kb,
        "components": [dwm, data, narrowed, window, output],
        "confidence": {
            "data.written/read": "HIGH (tool -v Non-marker symbols)",
            "data_with_markers.*": "HIGH (tool -v marker count + applyWindow source)",
            "*.alloc_bytes": "MEDIUM (source-derived; rapidgzip rpmalloc not tapped)",
            "rusage_*": "HIGH if --minflt/--maxrss-kb measured via time -v",
        },
    }
    json.dump(run, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
