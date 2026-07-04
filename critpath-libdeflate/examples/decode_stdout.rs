// Decode /tmp/silesia.gz via the INSTRUMENTED libdeflate and write raw bytes to
// stdout, so an external sha oracle can verify byte-correctness.
use std::io::Write;
fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| "/tmp/silesia.gz".into());
    let data = std::fs::read(&path).expect("read corpus");
    // canonical silesia decoded length
    let mut out = vec![0u8; 211968000 + 4096];
    let n = critpath_libdeflate::gzip_decode(&data, &mut out);
    let mut so = std::io::stdout().lock();
    so.write_all(&out[..n]).unwrap();
}
