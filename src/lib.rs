#![feature(asm,associated_consts,const_fn,test)]
extern crate byteorder;
extern crate libc;
extern crate llvmint;
extern crate openssl;
extern crate openssl_sys;
extern crate rand;
extern crate rayon;
extern crate simd;
extern crate simdty;
extern crate test;

pub mod prefetch;
pub mod garble;
