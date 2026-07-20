//! STUB — see contract in ratio/mod.rs. Worker fills this file.
use super::{PosMatches, Prices, Tok, TokenStream};
pub fn optimal_parse(_data: &[u8], _range: (usize, usize), _m: &[PosMatches], _p: &Prices) -> Vec<Tok> { todo!() }
pub fn squeeze(_data: &[u8], _max_chain: u32, _iters: u32, _seeds: &[&TokenStream], _block_cost: &dyn Fn(&[Tok]) -> u64) -> Vec<Vec<Tok>> { todo!() }
