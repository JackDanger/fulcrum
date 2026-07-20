//! DEFLATE inflater + gzip wrapper parsing (pure std, no deps beyond `sha2`).
//!
//! `extract_gz` recovers the exact LZ77 token factorization of a single-member
//! gzip file (per-token exact bit cost, per-block Huffman code lengths, verbatim
//! header spans), enabling byte-exact conservation re-encoding (see encode.rs).
//! `inflate_gz` is an independent plain re-inflater for round-trip checks.
//!
//! Correctness is measured, not assumed: the block/token accounting satisfies
//! `TokenStream::attributed_bits() == deflate_bits` exactly (conservation LHS),
//! and CRC32 + ISIZE are verified against the gzip trailer.

use super::{
    len_code_index, Block, BlockKind, Tok, Token, TokenStream, DIST_BASE, DIST_EXTRA, LEN_BASE,
    LEN_EXTRA,
};
use sha2::{Digest, Sha256};

// ───────────────────────────── CRC-32 (IEEE, table-based) ───────────────────

const fn crc32_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut n = 0usize;
    while n < 256 {
        let mut c = n as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        t[n] = c;
        n += 1;
    }
    t
}

static CRC32_TABLE: [u32; 256] = crc32_table();

/// CRC-32 (IEEE 802.3, the gzip/zlib polynomial) of `data`.
pub(super) fn crc32(data: &[u8]) -> u32 {
    let mut c: u32 = 0xFFFF_FFFF;
    for &b in data {
        c = CRC32_TABLE[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
    }
    c ^ 0xFFFF_FFFF
}

// ───────────────────────────── LSB-first bit reader ─────────────────────────

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,  // index of next byte to load into the accumulator
    bitbuf: u64, // buffered bits, LSB = next bit to consume
    bitcnt: u32, // number of valid bits in `bitbuf`
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        BitReader {
            data,
            pos: 0,
            bitbuf: 0,
            bitcnt: 0,
        }
    }

    /// Read `n` (0..=32) bits LSB-first.
    #[inline]
    fn getbits(&mut self, n: u32) -> Result<u32, String> {
        if n == 0 {
            return Ok(0);
        }
        while self.bitcnt < n {
            if self.pos >= self.data.len() {
                return Err("unexpected end of deflate stream".to_string());
            }
            self.bitbuf |= (self.data[self.pos] as u64) << self.bitcnt;
            self.pos += 1;
            self.bitcnt += 8;
        }
        let v = (self.bitbuf & ((1u64 << n) - 1)) as u32;
        self.bitbuf >>= n;
        self.bitcnt -= n;
        Ok(v)
    }

    #[inline]
    fn getbit(&mut self) -> Result<u32, String> {
        self.getbits(1)
    }

    /// Absolute bit position (bits consumed since stream start).
    #[inline]
    fn bitpos(&self) -> u64 {
        self.pos as u64 * 8 - self.bitcnt as u64
    }

    /// Discard buffered bits up to the next byte boundary.
    fn align_to_byte(&mut self) {
        let drop = self.bitcnt & 7;
        self.bitbuf >>= drop;
        self.bitcnt -= drop;
    }

    /// Byte offset of the next unconsumed byte (valid only when byte-aligned).
    fn current_byte(&self) -> usize {
        self.pos - (self.bitcnt as usize) / 8
    }

    /// Reset the accumulator so the next read starts at byte offset `byte`.
    fn resync_to(&mut self, byte: usize) {
        self.pos = byte;
        self.bitbuf = 0;
        self.bitcnt = 0;
    }
}

/// Extract bits `[start, end)` from an LSB-first packed byte slice into a fresh
/// LSB-first packed `Vec<u8>` (bit 0 of output = bit `start` of input).
fn extract_bits(data: &[u8], start: u64, end: u64) -> Vec<u8> {
    let nbits = (end - start) as usize;
    let mut out = vec![0u8; nbits.div_ceil(8)];
    for i in 0..nbits {
        let src = start as usize + i;
        let bit = (data[src / 8] >> (src % 8)) & 1;
        if bit != 0 {
            out[i / 8] |= 1 << (i % 8);
        }
    }
    out
}

// ───────────────────────────── canonical Huffman decode ─────────────────────

/// Canonical Huffman decoder built from a code-length array (RFC 1951 §3.2.2).
/// Uses the `puff.c` bit-serial decode: O(code length) per symbol.
struct Huff {
    /// count[l] = number of codes of length l (l in 1..=15).
    count: [u16; 16],
    /// symbols, ordered by (length, symbol value).
    symbol: Vec<u16>,
}

impl Huff {
    /// Build from `lens` (index = symbol, value = code length, 0 = unused).
    /// Errors only on an over-subscribed code; incomplete codes are permitted
    /// (they occur legitimately for the degenerate single/zero distance code)
    /// and instead surface as a decode error if an undefined code is ever read.
    fn build(lens: &[u8]) -> Result<Huff, String> {
        let mut count = [0u16; 16];
        for &l in lens {
            if l as usize > 15 {
                return Err("code length exceeds 15".to_string());
            }
            count[l as usize] += 1;
        }
        // Over-subscription check.
        let mut left: i32 = 1;
        for len in 1..=15usize {
            left <<= 1;
            left -= count[len] as i32;
            if left < 0 {
                return Err("over-subscribed Huffman code".to_string());
            }
        }
        // Offsets for each length into the sorted symbol table.
        let mut offs = [0u16; 16];
        for len in 1..15usize {
            offs[len + 1] = offs[len] + count[len];
        }
        let nsym = lens.iter().filter(|&&l| l != 0).count();
        let mut symbol = vec![0u16; nsym];
        for (s, &l) in lens.iter().enumerate() {
            if l != 0 {
                symbol[offs[l as usize] as usize] = s as u16;
                offs[l as usize] += 1;
            }
        }
        Ok(Huff { count, symbol })
    }

    #[inline]
    fn decode(&self, br: &mut BitReader) -> Result<u16, String> {
        let mut code: i32 = 0;
        let mut first: i32 = 0;
        let mut index: i32 = 0;
        for len in 1..=15usize {
            code |= br.getbit()? as i32;
            let cnt = self.count[len] as i32;
            if code - first < cnt {
                return Ok(self.symbol[(index + (code - first)) as usize]);
            }
            index += cnt;
            first += cnt;
            first <<= 1;
            code <<= 1;
        }
        Err("invalid Huffman code (ran past 15 bits)".to_string())
    }
}

// ───────────────────────────── fixed tables (RFC 1951 §3.2.6) ────────────────

/// Fixed-Huffman literal/length code lengths (288 entries).
pub(super) fn fixed_litlen_lens() -> [u8; 288] {
    let mut l = [0u8; 288];
    for (i, v) in l.iter_mut().enumerate() {
        *v = match i {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    l
}

/// Fixed-Huffman distance code lengths (all 5 bits; 32 entries).
pub(super) fn fixed_dist_lens() -> [u8; 32] {
    [5u8; 32]
}

// ───────────────────────────── gzip wrapper ─────────────────────────────────

/// Parse the gzip header, returning the byte offset at which the deflate stream
/// begins. Handles FEXTRA / FNAME / FCOMMENT / FHCRC.
fn parse_gzip_header(gz: &[u8]) -> Result<usize, String> {
    if gz.len() < 18 {
        return Err("file too short to be a gzip member".to_string());
    }
    if gz[0] != 0x1f || gz[1] != 0x8b {
        return Err("bad gzip magic".to_string());
    }
    if gz[2] != 8 {
        return Err(format!(
            "unsupported compression method {} (expected 8)",
            gz[2]
        ));
    }
    let flg = gz[3];
    let mut off = 10usize; // fixed header: ID1 ID2 CM FLG MTIME(4) XFL OS
                           // FEXTRA
    if flg & 0x04 != 0 {
        if off + 2 > gz.len() {
            return Err("truncated FEXTRA length".to_string());
        }
        let xlen = gz[off] as usize | (gz[off + 1] as usize) << 8;
        off += 2 + xlen;
    }
    // FNAME (zero-terminated)
    if flg & 0x08 != 0 {
        while off < gz.len() && gz[off] != 0 {
            off += 1;
        }
        off += 1; // consume the terminator
    }
    // FCOMMENT (zero-terminated)
    if flg & 0x10 != 0 {
        while off < gz.len() && gz[off] != 0 {
            off += 1;
        }
        off += 1;
    }
    // FHCRC (2 bytes)
    if flg & 0x02 != 0 {
        off += 2;
    }
    if off + 8 > gz.len() {
        return Err("gzip header overruns file".to_string());
    }
    Ok(off)
}

// ───────────────────────────── dynamic header parse ─────────────────────────

const CL_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// Parse a dynamic-block header, returning (litlen_lens[288], dist_lens[32]).
fn parse_dynamic(br: &mut BitReader) -> Result<([u8; 288], [u8; 32]), String> {
    let hlit = br.getbits(5)? as usize + 257;
    let hdist = br.getbits(5)? as usize + 1;
    let hclen = br.getbits(4)? as usize + 4;
    if hlit > 288 || hdist > 32 {
        return Err("dynamic header HLIT/HDIST out of range".to_string());
    }
    let mut cl = [0u8; 19];
    for i in 0..hclen {
        cl[CL_ORDER[i]] = br.getbits(3)? as u8;
    }
    let clhuff = Huff::build(&cl)?;
    let total = hlit + hdist;
    let mut lens = vec![0u8; total];
    let mut i = 0usize;
    while i < total {
        let sym = clhuff.decode(br)?;
        match sym {
            0..=15 => {
                lens[i] = sym as u8;
                i += 1;
            }
            16 => {
                if i == 0 {
                    return Err("repeat code 16 with no previous length".to_string());
                }
                let n = 3 + br.getbits(2)? as usize;
                let prev = lens[i - 1];
                for _ in 0..n {
                    if i >= total {
                        return Err("repeat code 16 overruns length list".to_string());
                    }
                    lens[i] = prev;
                    i += 1;
                }
            }
            17 => {
                let n = 3 + br.getbits(3)? as usize;
                for _ in 0..n {
                    if i >= total {
                        return Err("repeat code 17 overruns length list".to_string());
                    }
                    lens[i] = 0;
                    i += 1;
                }
            }
            18 => {
                let n = 11 + br.getbits(7)? as usize;
                for _ in 0..n {
                    if i >= total {
                        return Err("repeat code 18 overruns length list".to_string());
                    }
                    lens[i] = 0;
                    i += 1;
                }
            }
            _ => return Err(format!("invalid code-length symbol {sym}")),
        }
    }
    let mut litlen_lens = [0u8; 288];
    let mut dist_lens = [0u8; 32];
    litlen_lens[..hlit].copy_from_slice(&lens[..hlit]);
    dist_lens[..hdist].copy_from_slice(&lens[hlit..hlit + hdist]);
    Ok((litlen_lens, dist_lens))
}

// ───────────────────────────── decode one match ─────────────────────────────

/// Decode a length/distance pair given an already-read litlen symbol in
/// 257..=285. Returns (len, dist, len_extra_bits, dist_extra_bits, dist_code).
fn decode_match(
    br: &mut BitReader,
    sym: u16,
    disthuff: &Huff,
) -> Result<(u16, u32, u8, u8, usize), String> {
    if sym > 285 {
        return Err(format!("invalid literal/length symbol {sym}"));
    }
    let lc = (sym - 257) as usize;
    let len = LEN_BASE[lc] + br.getbits(LEN_EXTRA[lc] as u32)? as u16;
    let dsym = disthuff.decode(br)? as usize;
    if dsym >= 30 {
        return Err(format!("invalid distance symbol {dsym}"));
    }
    let dist = DIST_BASE[dsym] + br.getbits(DIST_EXTRA[dsym] as u32)?;
    Ok((len, dist, LEN_EXTRA[lc], DIST_EXTRA[dsym], dsym))
}

// ───────────────────────────── extract_gz ───────────────────────────────────

/// Parse a single-member gzip file into its exact token factorization plus the
/// decompressed bytes. Verifies CRC32 and ISIZE; rejects multi-member/trailing.
pub fn extract_gz(gz: &[u8]) -> Result<(TokenStream, Vec<u8>), String> {
    let header_len = parse_gzip_header(gz)?;
    let data = &gz[header_len..];

    let mut br = BitReader::new(data);
    let mut out: Vec<u8> = Vec::new();
    let mut tokens: Vec<Token> = Vec::new();
    let mut blocks: Vec<Block> = Vec::new();

    loop {
        let start_bit = br.bitpos();
        let bfinal = br.getbits(1)? == 1;
        let btype = br.getbits(2)?;
        match btype {
            0 => {
                // Stored block: align, read LEN/NLEN, copy raw bytes.
                br.align_to_byte();
                let bp = br.current_byte();
                if bp + 4 > data.len() {
                    return Err("stored block header overruns stream".to_string());
                }
                let len = data[bp] as usize | (data[bp + 1] as usize) << 8;
                let nlen = data[bp + 2] as usize | (data[bp + 3] as usize) << 8;
                if nlen != (!len & 0xFFFF) {
                    return Err("stored block LEN/NLEN mismatch".to_string());
                }
                if bp + 4 + len > data.len() {
                    return Err("stored block data overruns stream".to_string());
                }
                let header_end_bit = (bp + 4) as u64 * 8;
                let raw_header = extract_bits(data, start_bit, header_end_bit);
                let tok_start = tokens.len();
                let uncomp_start = out.len() as u64;
                for k in 0..len {
                    let b = data[bp + 4 + k];
                    tokens.push(Token {
                        pos: out.len() as u64,
                        tok: Tok::Lit(b),
                        bits: 8,
                    });
                    out.push(b);
                }
                br.resync_to(bp + 4 + len);
                blocks.push(Block {
                    kind: BlockKind::Stored,
                    final_block: bfinal,
                    start_bit,
                    header_bits: header_end_bit - start_bit,
                    raw_header,
                    litlen_lens: [0u8; 288],
                    dist_lens: [0u8; 32],
                    token_range: (tok_start, tokens.len()),
                    uncomp_range: (uncomp_start, out.len() as u64),
                });
            }
            1 | 2 => {
                let (kind, litlen_lens, dist_lens) = if btype == 1 {
                    (BlockKind::Fixed, fixed_litlen_lens(), fixed_dist_lens())
                } else {
                    let (ll, dl) = parse_dynamic(&mut br)?;
                    (BlockKind::Dynamic, ll, dl)
                };
                let header_end_bit = br.bitpos();
                let raw_header = extract_bits(data, start_bit, header_end_bit);
                let lithuff = Huff::build(&litlen_lens)?;
                let disthuff = Huff::build(&dist_lens)?;
                let eob_len = litlen_lens[256];
                if eob_len == 0 {
                    return Err("block has no end-of-block code".to_string());
                }
                let tok_start = tokens.len();
                let uncomp_start = out.len() as u64;
                loop {
                    let sym = lithuff.decode(&mut br)?;
                    if sym == 256 {
                        break;
                    } else if sym < 256 {
                        let b = sym as u8;
                        tokens.push(Token {
                            pos: out.len() as u64,
                            tok: Tok::Lit(b),
                            bits: litlen_lens[sym as usize] as u32,
                        });
                        out.push(b);
                    } else {
                        let (len, dist, len_x, dist_x, dsym) =
                            decode_match(&mut br, sym, &disthuff)?;
                        if dist as usize > out.len() {
                            return Err("distance points before start of output".to_string());
                        }
                        let bits = litlen_lens[sym as usize] as u32
                            + len_x as u32
                            + dist_lens[dsym] as u32
                            + dist_x as u32;
                        tokens.push(Token {
                            pos: out.len() as u64,
                            tok: Tok::Match {
                                len,
                                dist: dist as u16,
                            },
                            bits,
                        });
                        let src = out.len() - dist as usize;
                        for k in 0..len as usize {
                            let byte = out[src + k];
                            out.push(byte);
                        }
                    }
                }
                blocks.push(Block {
                    kind,
                    final_block: bfinal,
                    start_bit,
                    header_bits: (header_end_bit - start_bit) + eob_len as u64,
                    raw_header,
                    litlen_lens,
                    dist_lens,
                    token_range: (tok_start, tokens.len()),
                    uncomp_range: (uncomp_start, out.len() as u64),
                });
            }
            _ => return Err("reserved block type (BTYPE=3)".to_string()),
        }
        if bfinal {
            break;
        }
    }

    let deflate_bits = br.bitpos();
    let deflate_bytes = deflate_bits.div_ceil(8);

    // Trailer: CRC32 (LE) + ISIZE (LE), immediately after the padded deflate.
    let trailer_off = header_len + deflate_bytes as usize;
    if trailer_off + 8 > gz.len() {
        return Err("file truncated before gzip trailer".to_string());
    }
    if trailer_off + 8 != gz.len() {
        return Err(
            "trailing bytes after gzip trailer (multi-member files are out of scope)".to_string(),
        );
    }
    let want_crc = u32::from_le_bytes([
        gz[trailer_off],
        gz[trailer_off + 1],
        gz[trailer_off + 2],
        gz[trailer_off + 3],
    ]);
    let want_isize = u32::from_le_bytes([
        gz[trailer_off + 4],
        gz[trailer_off + 5],
        gz[trailer_off + 6],
        gz[trailer_off + 7],
    ]);
    let got_crc = crc32(&out);
    if got_crc != want_crc {
        return Err(format!(
            "CRC32 mismatch: computed {got_crc:#010x}, trailer {want_crc:#010x}"
        ));
    }
    if want_isize != (out.len() as u32) {
        return Err(format!(
            "ISIZE mismatch: output {} bytes, trailer {}",
            out.len() as u32,
            want_isize
        ));
    }

    let mut hasher = Sha256::new();
    hasher.update(&out);
    let raw_sha: [u8; 32] = hasher.finalize().into();

    let ts = TokenStream {
        tokens,
        blocks,
        raw_len: out.len() as u64,
        raw_sha,
        gzip_header_bytes: header_len as u64 + 8,
        deflate_bytes,
        deflate_bits,
        file_bytes: gz.len() as u64,
    };
    Ok((ts, out))
}

// ───────────────────────────── inflate_gz (independent) ─────────────────────

/// Plain re-inflater: gzip → decompressed bytes. Independent of the extract
/// path (shares only the low-level bit reader / Huffman primitives). Verifies
/// CRC32 and ISIZE.
pub fn inflate_gz(gz: &[u8]) -> Result<Vec<u8>, String> {
    let header_len = parse_gzip_header(gz)?;
    let data = &gz[header_len..];
    let mut br = BitReader::new(data);
    let mut out: Vec<u8> = Vec::new();

    loop {
        let bfinal = br.getbits(1)? == 1;
        let btype = br.getbits(2)?;
        match btype {
            0 => {
                br.align_to_byte();
                let bp = br.current_byte();
                if bp + 4 > data.len() {
                    return Err("stored block header overruns stream".to_string());
                }
                let len = data[bp] as usize | (data[bp + 1] as usize) << 8;
                let nlen = data[bp + 2] as usize | (data[bp + 3] as usize) << 8;
                if nlen != (!len & 0xFFFF) {
                    return Err("stored block LEN/NLEN mismatch".to_string());
                }
                if bp + 4 + len > data.len() {
                    return Err("stored block data overruns stream".to_string());
                }
                out.extend_from_slice(&data[bp + 4..bp + 4 + len]);
                br.resync_to(bp + 4 + len);
            }
            1 | 2 => {
                let (litlen_lens, dist_lens) = if btype == 1 {
                    (fixed_litlen_lens(), fixed_dist_lens())
                } else {
                    parse_dynamic(&mut br)?
                };
                let lithuff = Huff::build(&litlen_lens)?;
                let disthuff = Huff::build(&dist_lens)?;
                loop {
                    let sym = lithuff.decode(&mut br)?;
                    if sym == 256 {
                        break;
                    } else if sym < 256 {
                        out.push(sym as u8);
                    } else {
                        let (len, dist, _, _, _) = decode_match(&mut br, sym, &disthuff)?;
                        if dist as usize > out.len() {
                            return Err("distance points before start of output".to_string());
                        }
                        let src = out.len() - dist as usize;
                        for k in 0..len as usize {
                            let byte = out[src + k];
                            out.push(byte);
                        }
                    }
                }
            }
            _ => return Err("reserved block type (BTYPE=3)".to_string()),
        }
        if bfinal {
            break;
        }
    }

    let deflate_bytes = br.bitpos().div_ceil(8) as usize;
    let trailer_off = header_len + deflate_bytes;
    if trailer_off + 8 > gz.len() {
        return Err("file truncated before gzip trailer".to_string());
    }
    let want_crc = u32::from_le_bytes([
        gz[trailer_off],
        gz[trailer_off + 1],
        gz[trailer_off + 2],
        gz[trailer_off + 3],
    ]);
    let want_isize = u32::from_le_bytes([
        gz[trailer_off + 4],
        gz[trailer_off + 5],
        gz[trailer_off + 6],
        gz[trailer_off + 7],
    ]);
    if crc32(&out) != want_crc {
        return Err("CRC32 mismatch".to_string());
    }
    if want_isize != out.len() as u32 {
        return Err("ISIZE mismatch".to_string());
    }
    Ok(out)
}

/// Convenience shared with encode.rs: the exact per-token bit cost of `tok`
/// under the given code-length tables (symbol length + extra bits).
pub(super) fn token_bits(tok: Tok, litlen_lens: &[u8], dist_lens: &[u8]) -> u32 {
    match tok {
        Tok::Lit(b) => litlen_lens[b as usize] as u32,
        Tok::Match { len, dist } => {
            let lc = len_code_index(len) as usize;
            let dc = super::dist_code_index(dist as u32) as usize;
            litlen_lens[257 + lc] as u32
                + LEN_EXTRA[lc] as u32
                + dist_lens[dc] as u32
                + DIST_EXTRA[dc] as u32
        }
    }
}

// ───────────────────────────── tests ────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Known-answer gzip fixtures generated once with python3 zlib/gzip.
    // Raw payloads are reconstructed deterministically in-code below.
    include!("fixtures_gz.rs");

    fn raw_stored() -> Vec<u8> {
        b"Hello, stored deflate block! 1234567890.".to_vec()
    }
    fn raw_fixed() -> Vec<u8> {
        b"aaaaaa".to_vec()
    }
    fn raw_dyn() -> Vec<u8> {
        let mut v = Vec::new();
        for _ in 0..30 {
            v.extend_from_slice(
                b"the quick brown fox jumps over the lazy dog while carrying five dozen liquor jugs. ",
            );
        }
        for _ in 0..30 {
            v.extend_from_slice(
                b"sphinx of black quartz judge my vow; the five boxing wizards jump quickly onward. ",
            );
        }
        v
    }
    fn raw_fname() -> Vec<u8> {
        b"payload with a filename header set".to_vec()
    }

    fn conservation_holds(gz: &[u8]) {
        let (ts, out) = extract_gz(gz).expect("extract");
        // attributed_bits == deflate_bits (exact).
        assert_eq!(
            ts.attributed_bits(),
            ts.deflate_bits,
            "attributed bits must equal deflate_bits"
        );
        // reencode_conserve reproduces the deflate stream bytes exactly.
        let deflate = &gz[(ts.gzip_header_bytes as usize - 8)..][..ts.deflate_bytes as usize];
        let re = super::super::encode::reencode_conserve(&ts);
        assert_eq!(re, deflate, "G0a: reencode must be byte-identical");
        // inflate_gz agrees with extract output.
        assert_eq!(inflate_gz(gz).expect("inflate"), out);
    }

    #[test]
    fn stored_known_answer() {
        let (_, out) = extract_gz(GZ_STORED).expect("extract stored");
        assert_eq!(out, raw_stored());
        let (ts, _) = extract_gz(GZ_STORED).unwrap();
        assert_eq!(ts.blocks.len(), 1);
        assert_eq!(ts.blocks[0].kind, BlockKind::Stored);
        conservation_holds(GZ_STORED);
    }

    #[test]
    fn fixed_known_answer() {
        let (ts, out) = extract_gz(GZ_FIXED).expect("extract fixed");
        assert_eq!(out, raw_fixed());
        assert_eq!(ts.blocks[0].kind, BlockKind::Fixed);
        conservation_holds(GZ_FIXED);
    }

    #[test]
    fn dynamic_multiblock_known_answer() {
        let (ts, out) = extract_gz(GZ_DYN).expect("extract dyn");
        assert_eq!(out, raw_dyn());
        assert!(ts.blocks.len() >= 2, "expected multiple blocks");
        assert!(ts.blocks.iter().any(|b| b.kind == BlockKind::Dynamic));
        // Non-inert: matches present.
        assert!(ts.tokens.iter().any(|t| matches!(t.tok, Tok::Match { .. })));
        conservation_holds(GZ_DYN);
    }

    #[test]
    fn fname_header_known_answer() {
        let (ts, out) = extract_gz(GZ_FNAME).expect("extract fname");
        assert_eq!(out, raw_fname());
        // Header (before deflate) is longer than the bare 10 bytes due to FNAME.
        assert!(ts.gzip_header_bytes - 8 > 10);
        conservation_holds(GZ_FNAME);
    }

    #[test]
    fn multi_member_rejected() {
        let mut two = GZ_FIXED.to_vec();
        two.extend_from_slice(GZ_FIXED);
        assert!(extract_gz(&two).is_err());
    }

    #[test]
    fn corrupt_crc_rejected() {
        let mut bad = GZ_FIXED.to_vec();
        let n = bad.len();
        bad[n - 5] ^= 0xFF; // flip a CRC byte
        assert!(extract_gz(&bad).is_err());
    }

    #[test]
    fn determinism_extract_reencode() {
        let (ts1, _) = extract_gz(GZ_DYN).unwrap();
        let (ts2, _) = extract_gz(GZ_DYN).unwrap();
        assert_eq!(
            super::super::encode::reencode_conserve(&ts1),
            super::super::encode::reencode_conserve(&ts2)
        );
        assert_eq!(ts1.raw_sha, ts2.raw_sha);
    }

    /// Real-corpus G0a conservation on genuine ECT/gzippy/zopfli-class dynamic
    /// headers (far richer than the synthetic fixtures). Skipped where the
    /// corpus is absent. This exercises many blocks whose headers start
    /// mid-byte, proving the verbatim `raw_header` splice is an exact identity.
    ///
    /// NOTE ON WRAPPER SEMANTICS: `gzip_header_bytes` counts ALL non-deflate
    /// wrapper bytes — the pre-deflate header PLUS the 8-byte trailer (per the
    /// frozen mod.rs doc). Hence the invariant `gzip_header_bytes +
    /// deflate_bytes == file_bytes`, and the deflate stream begins at byte
    /// `gzip_header_bytes - 8` (NOT `gzip_header_bytes`).
    #[test]
    fn real_corpus_conservation() {
        use std::path::Path;
        let dir = Path::new("artifacts/ratio-corpus");
        if !dir.exists() {
            return; // corpus not present in this environment
        }
        let mut checked = 0;
        for base in ["markup.xml", "ecoli.fastq", "aozora.txt"] {
            for enc in ["ect", "gzippy"] {
                let p = dir.join(format!("{base}.{enc}.gz"));
                if !p.exists() {
                    continue;
                }
                let gz = std::fs::read(&p).unwrap();
                let (ts, out) = extract_gz(&gz).expect("extract corpus file");
                let rawp = dir.join(base);
                if rawp.exists() {
                    assert_eq!(out, std::fs::read(&rawp).unwrap(), "{base}.{enc}: decode");
                }
                assert_eq!(
                    ts.attributed_bits(),
                    ts.deflate_bits,
                    "{base}.{enc}: attribution"
                );
                assert_eq!(
                    ts.gzip_header_bytes + ts.deflate_bytes,
                    ts.file_bytes,
                    "{base}.{enc}: wrapper invariant"
                );
                let start = ts.gzip_header_bytes as usize - 8;
                let deflate = &gz[start..start + ts.deflate_bytes as usize];
                assert_eq!(
                    super::super::encode::reencode_conserve(&ts),
                    deflate,
                    "{base}.{enc}: G0a conservation"
                );
                checked += 1;
            }
        }
        assert!(checked > 0, "corpus dir present but no .gz matched");
    }
}
