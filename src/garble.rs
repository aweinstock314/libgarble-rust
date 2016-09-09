use byteorder::{ByteOrder, LittleEndian};
use libc::{c_int, c_void, calloc, free, posix_memalign};
use llvmint::x86::{aesni_aesenc, aesni_aesenclast};
use openssl::crypto::hash;
use openssl_sys::RAND_bytes;
use rand::Rng;
use rayon::prelude::*;
use simd::u8x16;
use simdty::i64x2;
use std::cmp::min;
use std::ops::Range;
use std::{mem, ptr, slice};

pub type Block = u8x16;

#[inline]
fn block_from_i64x2(x: i64x2) -> Block {
    block_from_u64x2(x.0 as u64, x.1 as u64)
}

#[inline]
fn i64x2_from_block(x: Block) -> i64x2 {
    let mut tmp = [0u8; 16];
    x.store(&mut tmp, 0);
    i64x2(LittleEndian::read_i64(&tmp[0..8]), LittleEndian::read_i64(&tmp[8..16]))
}

#[inline]
fn block_from_u64x2(lo: u64, hi: u64) -> Block {
    let mut tmp = [0u8;16];
    LittleEndian::write_u64(&mut tmp[0..8], lo);
    LittleEndian::write_u64(&mut tmp[8..16], hi);
    Block::load(&tmp, 0)
}

#[inline]
fn block_equals(x: Block, y: Block) -> bool {
    x.eq(y).all()
}

#[inline]
fn block_setlsb(x: Block) -> Block {
    x | block_from_u64x2(1,0)
}

#[inline]
fn block_clearlsb(x: Block) -> Block {
    x & block_from_u64x2(!0-1,!0)
}

#[inline]
fn double_xmm(mut x: Block) -> Block {
    unsafe { asm!("psllq $$1, $0" : "=x"(x) : "0"(x)); }
    x
}
#[inline]
fn quadruple_xmm(mut x: Block) -> Block {
    unsafe { asm!("psllq $$2, $0" : "=x"(x) : "0"(x)); }
    x
}


static GARBLE_OK: c_int = 0;
static GARBLE_ERR: c_int = -1;


//                              x:  1100
//                              y:  1010
pub static GARBLE_GATE_ZERO: u8 = 0b0000;
pub static GARBLE_GATE_ONE: u8  = 0b1111;
pub static GARBLE_GATE_AND: u8  = 0b1000;
pub static GARBLE_GATE_OR: u8   = 0b1110;
pub static GARBLE_GATE_XOR: u8  = 0b0110;
pub static GARBLE_GATE_NOT: u8  = 0b0101; // |x,y| { !y }

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub enum GarbleType {
    Standard, HalfGates, PrivacyFree
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GarbleGate {
    ty: u8,
    in0: usize, in1: usize, out: usize
}

#[repr(C)]
#[derive(Debug)]
pub struct GarbleCircuit {
    n: usize, m: usize, q: usize, r:usize,
    ty: GarbleType,
    gates: *mut GarbleGate, // q
    table: *mut Block,      // q
    wires: *mut Block,      // 2r
    outputs: *mut c_int,    // m
    output_perms: *mut bool,
    fixed_label: Block,
    global_key: Block
}
// needed for parallelism, should be safe if disjoint parts of the arrays are accessed
unsafe impl Sync for GarbleCircuit {}

#[no_mangle] pub extern fn garble_allocate_blocks(nblocks: usize) -> *mut Block {
    let mut blocks: *mut c_void = ptr::null_mut();
    let res = unsafe { posix_memalign(&mut blocks, mem::align_of::<Block>(), nblocks * mem::size_of::<Block>()) };
    //println!("garble_allocate_blocks({}): {}, {:p}", nblocks, res, blocks);
    if res == 0 {
        blocks as *mut Block
    } else {
        println!("posix_memalign failed: {}", res);
        ptr::null_mut()
    }
}

#[no_mangle] pub extern fn garble_check(gc: *const GarbleCircuit, oldhash: *const u8) -> c_int {
    let gc = if let Some(gc) = unsafe { gc.as_ref() } { gc } else { return GARBLE_ERR; };
    let oldhash = unsafe { if let Some(oldhash) = oldhash.as_ref() { slice::from_raw_parts(oldhash, SHA_DIGEST_LENGTH) } else { return GARBLE_ERR; } };
    //println!("garble_check({:?}, {:?})", gc, oldhash);
    let mut newhash = [0u8; SHA_DIGEST_LENGTH];
    garble_hash(gc, newhash.as_mut_ptr());
    if oldhash == newhash { GARBLE_OK } else { GARBLE_ERR }
}
#[no_mangle] pub extern fn garble_circuit_from_file() {
    panic!("garble_circuit_from_file");
}
#[no_mangle] pub extern fn garble_circuit_to_file() {
    panic!("garble_circuit_to_file");
}
#[no_mangle] pub extern fn garble_create_delta() -> Block {
    let current_rand_index = unsafe { &mut CURRENT_RAND_INDEX };
    create_delta_tweak(current_rand_index)
}

#[inline]
fn create_delta_tweak(tweak: &mut u64) -> Block {
    block_setlsb(random_block_tweak(tweak))
}

#[no_mangle] pub extern fn garble_create_input_labels() {
    panic!("garble_create_input_labels");
}
#[no_mangle] pub extern fn garble_delete(gc: *mut GarbleCircuit) {
    //println!("garble_delete");
    unsafe {
        if let Some(gc) = gc.as_ref() {
            // It's ok to call free on a null pointer, so omit the if's present in the C code
            // man 3 free | grep -B1 'If ptr is NULL, no operation is performed.'
            free(gc.gates as _);
            free(gc.table as _);
            free(gc.wires as _);
            free(gc.outputs as _);
            free(gc.output_perms as _);
        }
    }
}

#[no_mangle] pub extern fn garble_eval(gc: *const GarbleCircuit, input_labels: *const Block, output_labels: *mut Block, outputs: *mut bool) -> c_int {
    //println!("garble_eval({:p}, {:p}, {:p}, {:p})", gc, input_labels, output_labels, outputs);
    let gc = if let Some(gc) = unsafe { gc.as_ref() } { gc } else { return GARBLE_ERR; };
    let mut key = unsafe { mem::uninitialized() };
    aes_set_encrypt_key(gc.global_key, &mut key);
    let labels: &mut [Block] = unsafe { slice::from_raw_parts_mut(garble_allocate_blocks(gc.r), gc.r) };
    unsafe { ptr::copy(input_labels, labels.as_mut_ptr(), gc.n) };
    let fixed_label = gc.fixed_label;
    labels[gc.n] = block_clearlsb(fixed_label);
    labels[gc.n+1] = block_setlsb(fixed_label);

    match gc.ty {
        GarbleType::Standard => eval_loop(eval_gate_standard, gc, labels, &key),
        GarbleType::HalfGates => eval_loop(eval_gate_halfgates, gc, labels, &key),
        GarbleType::PrivacyFree => eval_loop(eval_gate_privacyfree, gc, labels, &key),
    }

    let gc_outputs = unsafe { slice::from_raw_parts(gc.outputs, gc.m) };
    let gc_perms = unsafe { slice::from_raw_parts(gc.output_perms, gc.m) };

    if !output_labels.is_null() {
        let output_labels = unsafe { slice::from_raw_parts_mut(output_labels, gc.m) };
        for (i, label) in output_labels.iter_mut().enumerate() {
            *label = labels[gc_outputs[i] as usize];
        }
    }

    if !outputs.is_null() {
        let outputs = unsafe { slice::from_raw_parts_mut(outputs, gc.m) };
        for (i, out) in outputs.iter_mut().enumerate() {
            *out = (labels[gc_outputs[i] as usize].extract(0) & 1) ^ (gc_perms[i] as u8) == 1;
        }
    }

    unsafe { free(labels.as_ptr() as _); }

    GARBLE_OK
}

fn eval_loop<F>(eval_gate: F, gc: &GarbleCircuit, labels: &mut [Block], key: &AesKey) where
    F: Fn(u8, Block, Block, &mut Block, *const Block, u64, &AesKey) {
    let mult = garble_table_multiplier(gc.ty);

    /* // this approach would be safer/higher-level, but doesn't currently optimize as well
    let gc_gates = unsafe { slice::from_raw_parts(gc.gates, gc.q) };
    for (i, g) in gc_gates.iter().enumerate() { */
    for i in 0..gc.q {
        let g: &GarbleGate = unsafe { &*gc.gates.offset(i as isize) };
        eval_gate(g.ty,
            labels[g.in0],
            labels[g.in1],
            &mut labels[g.out],
            unsafe { gc.table.offset((mult*i) as isize) },
            i as u64, key);
    }
}

fn eval_gate_standard(ty: u8, a: Block, b: Block, out: &mut Block, table: *const Block, idx: u64, key: &AesKey) {
    if ty == GARBLE_GATE_XOR {
        *out = a ^ b;
    } else {
        let lsb_a = (a.extract(0) & 1) as isize;
        let lsb_b = (b.extract(0) & 1) as isize;
        let ha = double_xmm(a);
        let hb = quadruple_xmm(b);
        let tweak = block_from_u64x2(0, idx);
        let mut val = [ha ^ hb ^ tweak];
        let tmp = if lsb_a + lsb_b > 0 { unsafe { *table.offset(2*lsb_a + lsb_b - 1) ^ val[0] } } else { val[0] };
        aes_ecb_encrypt_blocks::<AesniViaLLVM>(&mut val, key);
        *out = val[0] ^ tmp;
    }
}
fn eval_gate_halfgates(ty: u8, a: Block, b: Block, out: &mut Block, table: *const Block, idx: u64, key: &AesKey) {
    if ty == GARBLE_GATE_XOR {
        *out = a ^ b;
    } else {
        let sa = (a.extract(0) & 1) == 1;
        let sb = (b.extract(0) & 1) == 1;
        let tweak1 = block_from_u64x2(0, 2*idx);
        let tweak2 = block_from_u64x2(0, 2*idx+1);

        let mut keys = [double_xmm(a) ^ tweak1, double_xmm(b) ^ tweak2];
        let masks = keys.clone();
        aes_ecb_encrypt_blocks::<AesniViaAsm>(&mut keys, key);
        let ha = keys[0] ^ masks[0];
        let hb = keys[1] ^ masks[1];

        let mut w = ha ^ hb;
        unsafe {
            if sa { w = w ^ *table.offset(0); }
            if sb { w = w ^ *table.offset(1) ^ a; }
            *out = w;
        }
    }
}
fn eval_gate_privacyfree(ty: u8, a: Block, b: Block, out: &mut Block, table: *const Block, idx: u64, key: &AesKey) {
    if ty == GARBLE_GATE_XOR {
        *out = a ^ b;
    } else {
        let sa = (a.extract(0) & 1) == 1;
        let tweak = block_from_u64x2(0, 2*idx);

        let mut tmp = [double_xmm(a) ^ tweak];
        let mask = tmp.clone();
        aes_ecb_encrypt_blocks::<AesniViaLLVM>(&mut tmp, key);
        let ha = tmp[0] ^ mask[0];

        let w = if sa {
                block_setlsb(ha) ^ unsafe { *table.offset(0) } ^ b
            } else {
                block_clearlsb(ha)
            };

        *out = w;
    }
}

#[no_mangle] pub extern fn garble_extract_labels(extracted_labels: *mut Block, labels: *const Block, bits: *const bool, n: usize) {
    //println!("garble_extract_labels({:p}, {:p}, {:p}, {})", extracted_labels, labels, bits, n);
    let (extracted_labels, labels, bits) = unsafe {(
        slice::from_raw_parts_mut(extracted_labels, n),
        slice::from_raw_parts(labels, 2*n),
        slice::from_raw_parts(bits, n),
    )};
    for i in 0..n {
        extracted_labels[i] = labels[2 * i + (if bits[i] { 1 } else { 0 })];
    }
    //println!("extracted_labels: {:?}\nbits: {:?}", extracted_labels, bits);
}
#[no_mangle] pub extern fn garble_from_buffer(gc: *mut GarbleCircuit, mut buf: *const i8, wires: bool) -> c_int {
    unsafe fn copy_from_buf<T>(pbuf: &mut *const i8, val: *mut T, count: usize) {
        let bytecount = count * mem::size_of::<T>();
        ptr::copy(mem::transmute::<*const i8,*const T>(*pbuf), val, bytecount);
        *pbuf = (*pbuf).offset(bytecount as isize);
    }

    macro_rules! alloc_and_copy_from_buf {
        ($pbuf:expr, $val:expr, $count:expr) => {{
            let pbuf: &mut *const i8 = $pbuf;
            let pval = &mut $val;
            let count: usize = $count;
            let bytecount = count * mem::size_of_val(&**pval);
            *pval = ::libc::malloc(bytecount) as _;
            if (*pval).is_null() {
                ::garble::garble_delete(gc);
                return GARBLE_ERR;
            }
            copy_from_buf(pbuf, *pval, count);
        }}
    }

    unsafe {
        copy_from_buf(&mut buf, &mut (*gc).n, 1);
        copy_from_buf(&mut buf, &mut (*gc).m, 1);
        copy_from_buf(&mut buf, &mut (*gc).q, 1);
        copy_from_buf(&mut buf, &mut (*gc).r, 1);
        copy_from_buf(&mut buf, &mut (*gc).ty, 1);
        alloc_and_copy_from_buf!(&mut buf, (*gc).gates, (*gc).q);
        alloc_and_copy_from_buf!(&mut buf, (*gc).table, (*gc).q * garble_table_multiplier((*gc).ty));
        if wires { alloc_and_copy_from_buf!(&mut buf, (*gc).wires, 2*(*gc).r) };
        alloc_and_copy_from_buf!(&mut buf, (*gc).outputs, (*gc).m);
        alloc_and_copy_from_buf!(&mut buf, (*gc).output_perms, (*gc).m);
        copy_from_buf(&mut buf, &mut (*gc).fixed_label, 1);
        copy_from_buf(&mut buf, &mut (*gc).global_key, 1);
    }

    GARBLE_OK
}

#[inline]
fn garble_table_multiplier(ty: GarbleType) -> usize {
    match ty {
        GarbleType::Standard => 3,
        GarbleType::HalfGates => 2,
        GarbleType::PrivacyFree => 1,
    }
}

#[inline]
fn garble_table_size(gc: *const GarbleCircuit) -> usize {
    match unsafe { gc.as_ref().map(|gc| gc.ty) } {
        None => 0,
        Some(ty) => garble_table_multiplier(ty) * mem::size_of::<Block>(),
    }
}

#[no_mangle] pub extern fn garble_garble(gc: *mut GarbleCircuit, input_labels: *const Block, output_labels: *mut Block) -> c_int {
    //println!("garble_garble");
    let mut key: AesKey = unsafe { mem::uninitialized() };
    let mut tweak = 0;
    let delta: Block;
    let gc = if let Some(gc) = unsafe { gc.as_mut() } { gc } else { return GARBLE_ERR };
    macro_rules! calloc_or_fail {
        ($var:expr, $nchunks:expr, $chunksize:expr) => {
            if $var.is_null() {
                $var = unsafe { calloc($nchunks, $chunksize) } as _;
                if $var.is_null() {
                    return GARBLE_ERR;
                }
            }
        }
    }
    calloc_or_fail!(gc.wires, 2*gc.r, mem::size_of::<Block>());
    calloc_or_fail!(gc.table, gc.q, garble_table_size(gc));
    calloc_or_fail!(gc.output_perms, gc.m, mem::size_of::<bool>());
    if !input_labels.is_null() {
        let input_labels = unsafe { slice::from_raw_parts(input_labels, 2*gc.n) };
        for (i,label) in input_labels.iter().enumerate() {
            unsafe {
                *gc.wires.offset(i as _) = *label;
            }
        }
        delta = unsafe { *gc.wires.offset(0) ^ *gc.wires.offset(1) };
    } else {
        delta = create_delta_tweak(&mut tweak);
        let saved_tweak = tweak;
        ParallelForLoop::for_each(0..gc.n, |i| {
            let mut tweak = saved_tweak+(i as u64);
            let i = i as isize;
            unsafe {
                let wire0 = gc.wires.offset(2*i);
                let wire1 = gc.wires.offset(2*i + 1);
                *wire0 = random_block_tweak(&mut tweak);
                if let GarbleType::PrivacyFree = gc.ty {
                    *wire0 = block_clearlsb(*wire0);
                }
                *wire1 = *wire0 ^ delta;
                if cfg!(feature="privacyfree_debugging") {
                    if let GarbleType::PrivacyFree = gc.ty {
                        if (*wire0).extract(0) & 1 == 1 || (*wire1).extract(0) & 1 == 0 {
                            panic!("privacyfree invalid lsb wire: {}: {:?} {:?}", i, *wire0, *wire1);
                        }
                    }
                }
            }
        });
        tweak = saved_tweak+(gc.n as u64);
    }

    let fixed_label = random_block_tweak(&mut tweak);
    gc.fixed_label = fixed_label;
    unsafe {
        *gc.wires.offset((2*gc.n) as _) = block_clearlsb(fixed_label);
        *gc.wires.offset((2*gc.n+1) as _) = block_clearlsb(fixed_label) ^ delta;

        *gc.wires.offset((2*(gc.n+1)) as _) = block_setlsb(fixed_label) ^ delta;
        *gc.wires.offset((2*(gc.n+1)+1) as _) = block_setlsb(fixed_label);
    }

    gc.global_key = random_block_tweak(&mut tweak);
    aes_set_encrypt_key(gc.global_key, &mut key);
    //println!("global_key: {:?}\nkey: {:?}", gc.global_key, key);

    match gc.ty {
        GarbleType::Standard => garble_loop::<_,SerialForLoop>(garble_gate_standard, gc, &key, delta),
        GarbleType::HalfGates => garble_loop::<_,SerialForLoop>(garble_gate_halfgates, gc, &key, delta),
        GarbleType::PrivacyFree => garble_loop::<_,SerialForLoop>(garble_gate_privacyfree, gc, &key, delta),
    }

    //ParallelForLoop::for_each(0..gc.m, |i| {
    for i in 0..gc.m {
        let i = i as isize;
        unsafe {
            let idx = *gc.outputs.offset(i) as isize;
            *gc.output_perms.offset(i) = (*gc.wires.offset(2 * idx)).extract(0) & 1 == 1;
        }
    }//);

    if !output_labels.is_null() {
        let output_labels = output_labels as isize;
        //ParallelForLoop::for_each(0..gc.m, |i| {
        for i in 0..gc.m {
            let i = i as isize;
            let output_labels = output_labels as *mut Block;
            unsafe {
                let idx = *gc.outputs.offset(i) as isize;
                *output_labels.offset(2*i) = *gc.wires.offset(2 * idx);
                *output_labels.offset(2*i+1) = *gc.wires.offset(2 * idx+1);
            }
        }//);
    }

    GARBLE_OK
}

trait ForLoop {
    //fn for_each<A: Send+Step, F: Fn(A) + Sync>(Range<A>, F) where for<'a> &'a A: Add;
    #[inline(always)]
    fn for_each<F: Fn(usize) + Sync>(Range<usize>, F); // TODO: generalize properly from usize
}

struct SerialForLoop;
impl ForLoop for SerialForLoop {
    //fn for_each<A: Send+Step, F: Fn(A) + Sync>(r: Range<A>, f: F) where for<'a> &'a A: Add {
    fn for_each<F: Fn(usize) + Sync>(r: Range<usize>, f: F) {
        for i in r {
            f(i);
        }
    }
}

struct ParallelForLoop;
impl ForLoop for ParallelForLoop {
    //fn for_each<A: Send+Step, F: Fn(A) + Sync>(r: Range<A>, f: F) where for<'a> &'a A: Add {
    fn for_each<F: Fn(usize) + Sync>(r: Range<usize>, f: F) {
        // TODO: figure out if there's a safe way to construct RangeIter
        let numthreads = 4;
        let iter: ::rayon::par_iter::range::RangeIter<usize> = unsafe { mem::transmute(0usize..numthreads) };
        iter.weight_max().for_each(|i| {
            let delta = r.end - r.start;
            let j0 = r.start+(delta/numthreads)*i;
            let j1 = min(r.start+(delta/numthreads)*(i+1), r.end);
            //println!("ParallelFor: {:?}, {}: {}: {:?}", r, delta, i, j0..j1);
            for j in j0..j1 {
                //println!("{}", j);
                f(j);
            }
        });
    }
}

fn garble_loop<F, L>(garble_gate: F, gc: &mut GarbleCircuit, key: &AesKey, delta: Block) where
    F: Fn(u8, Block, Block, Block, Block, &mut Block, &mut Block, Block, *mut Block, isize, &AesKey) + Sync,
    L: ForLoop {
    let mult = garble_table_multiplier(gc.ty) as isize;
    L::for_each(0..gc.q, |i| {
        let i = i as isize;
        unsafe {
            let g: &mut GarbleGate = &mut *gc.gates.offset(i);
            assert!(g.ty == GARBLE_GATE_XOR || g.ty == GARBLE_GATE_AND);
            garble_gate(g.ty,
                *gc.wires.offset(2 * (g.in0 as isize)),
                *gc.wires.offset(2 * (g.in0 as isize) + 1),
                *gc.wires.offset(2 * (g.in1 as isize)),
                *gc.wires.offset(2 * (g.in1 as isize) + 1),
                &mut *gc.wires.offset(2 * (g.out as isize)),
                &mut *gc.wires.offset(2 * (g.out as isize) + 1),
                delta, gc.table.offset(mult * i), i, key);
        }
    });
}

fn garble_gate_standard(ty: u8,
    mut a0: Block, mut a1: Block, mut b0: Block, mut b1: Block,
    out0: &mut Block, out1: &mut Block,
    delta: Block, table: *mut Block, idx: isize, key: &AesKey) {
    if ty == GARBLE_GATE_XOR {
        *out0 = a0 ^ b0;
        *out1 = *out0 ^ delta;
        //println!("garble_gate_standard: {}: XOR", idx);
    } else {
        let tweak = block_from_u64x2(0, idx as u64);
        let lsb0 = (a0.extract(0) & 1) as isize;
        let lsb1 = (b0.extract(0) & 1) as isize;
        a0 = double_xmm(a0);
        a1 = double_xmm(a1);
        b0 = quadruple_xmm(b0);
        b1 = quadruple_xmm(b1);
        let mut keys = [
            a0 ^ b0 ^ tweak,
            a0 ^ b1 ^ tweak,
            a1 ^ b0 ^ tweak,
            a1 ^ b1 ^ tweak,
        ];
        let mut mask = keys.clone();
        aes_ecb_encrypt_blocks::<AesniViaLLVM>(&mut keys[0..4], key);
        for (m,k) in mask.iter_mut().zip(keys.iter()) {
            *m = *m ^ *k;
        }
        let newtoken0 = mask[(2 * lsb0 + lsb1) as usize];
        let newtoken1 = newtoken0 ^ delta;

        let (label0, label1) = if lsb0 & lsb1 == 1 { (newtoken1, newtoken0) } else { (newtoken0, newtoken1) };
        *out0 = label0;
        *out1 = label1;

        // TODO: it looks like an AND gate is hardcoded here, generalize to support arbitrary gates
        assert_eq!(ty, GARBLE_GATE_AND);
        let blocks = [
            label0,
            label0,
            label0,
            label1,
        ];

        unsafe {
            if 2*   lsb0  +    lsb1  != 0 { *table.offset(2*   lsb0  +    lsb1 -1) = blocks[0] ^ mask[0]; }
            if 2*   lsb0  + (1-lsb1) != 0 { *table.offset(2*   lsb0  + (1-lsb1)-1) = blocks[1] ^ mask[1]; }
            if 2*(1-lsb0) +    lsb1  != 0 { *table.offset(2*(1-lsb0) +    lsb1 -1) = blocks[2] ^ mask[2]; }
            if 2*(1-lsb0) + (1-lsb1) != 0 { *table.offset(2*(1-lsb0) + (1-lsb1)-1) = blocks[3] ^ mask[3]; }
        }
    }
}

fn garble_gate_halfgates(ty: u8,
    a0: Block, a1: Block, b0: Block, b1: Block,
    out0: &mut Block, out1: &mut Block,
    delta: Block, table: *mut Block, idx: isize, key: &AesKey) {
    if ty == GARBLE_GATE_XOR {
        *out0 = a0 ^ b0;
        *out1 = *out0 ^ delta;
    } else {
        let idx = idx as u64;
        let pa = (a0.extract(0) & 1) == 1;
        let pb = (b0.extract(0) & 1) == 1;
        let tweak1 = block_from_u64x2(0, 2*idx);
        let tweak2 = block_from_u64x2(0, 2*idx+1);

        let mut keys = [
            double_xmm(a0) ^ tweak1,
            double_xmm(a1) ^ tweak1,
            double_xmm(b0) ^ tweak2,
            double_xmm(b1) ^ tweak2,
        ];
        let masks = keys.clone();
        aes_ecb_encrypt_blocks::<AesniViaAsm>(&mut keys, key);
        let ha0 = keys[0] ^ masks[0];
        let ha1 = keys[1] ^ masks[1];
        let hb0 = keys[2] ^ masks[2];
        let hb1 = keys[3] ^ masks[3];

        let mut w0 = ha0;
        let tmp = hb0 ^ hb1;
        unsafe {
            *table.offset(0) = ha0 ^ ha1;
            if pb { *table.offset(0) = *table.offset(0) ^ delta; }
            if pa { w0 = w0 ^ *table.offset(0); }
            *table.offset(1) = tmp ^ a0;
            w0 = w0 ^ hb0;
            if pb { w0 = w0 ^ tmp; }

            *out0 = w0;
            *out1 = *out0 ^ delta;
        }
    }
}

fn garble_gate_privacyfree(ty: u8,
    a0: Block, a1: Block, b0: Block, b1: Block,
    out0: &mut Block, out1: &mut Block,
    delta: Block, table: *mut Block, idx: isize, key: &AesKey) {
    if cfg!(feature="privacyfree_debugging") {
        if a0.extract(0) & 1 == 1 || b0.extract(0) & 1 == 1 || a1.extract(0) & 1 == 0 || b1.extract(0) & 1 == 0 {
            panic!("privacyfree invalid lsb: {}: {:?} {:?} {:?} {:?}", idx, a0, b0, a1, b1);
        }
        //println!("garble_gate_privacyfree: {}: {}", idx, if ty == GARBLE_GATE_XOR { "XOR" } else { "AND" });
    }
    if ty == GARBLE_GATE_XOR {
        *out0 = a0 ^ b0;
        *out1 = *out0 ^ delta;
    } else {
        let idx = idx as u64;
        let tweak = block_from_u64x2(0, 2*idx);

        let mut keys = [double_xmm(a0) ^ tweak, double_xmm(a1) ^ tweak];
        let masks = keys.clone();
        aes_ecb_encrypt_blocks::<AesniViaLLVM>(&mut keys, key);
        let ha0 = block_clearlsb(keys[0] ^ masks[0]);
        let ha1 = block_setlsb(keys[1] ^ masks[1]);

        let tmp = ha0 ^ ha1;
        unsafe {
            *table.offset(0) = tmp ^ b0;
        }
        *out0 = ha0;
        *out1 = ha0 ^ delta;
    }
    if cfg!(feature="privacyfree_debugging") && (out0.extract(0) & 1 == 1 || out1.extract(0) & 1 == 0) {
        panic!("privacyfree invalid lsb output: {}: {:?} {:?}", idx, *out0, *out1);
    }
}

const SHA_DIGEST_LENGTH: usize = 20;
#[no_mangle] pub extern fn garble_hash(gc: *const GarbleCircuit, hash_dest: *mut u8) {
    if let Some(gc) = unsafe { gc.as_ref() } {
        let table_bytes = unsafe { mem::transmute::<*mut Block, *mut u8>(gc.table) };
        let table_slice = unsafe { slice::from_raw_parts(table_bytes, gc.q * garble_table_size(gc)) };
        let result = hash::hash(hash::Type::SHA1, table_slice).expect("garble_hash: sha1 failed");
        //println!("garble_hash({:?}) = {:?}", gc, result);
        unsafe { ptr::copy(result.as_ptr(), hash_dest, SHA_DIGEST_LENGTH) };
    } else {
        println!("garble_hash(NULL)");
    }
}
#[no_mangle] pub extern fn garble_load() {
    panic!("garble_load");
}
#[no_mangle] pub extern fn garble_map_outputs(output_labels: *const Block, map: *const Block, vals: *mut bool, m: usize) -> c_int {
    //println!("garble_map_outputs({:p}, {:p}, {:p}, {})", output_labels, map, vals, m);
    let (output_labels, map, vals) = unsafe {(
        slice::from_raw_parts(output_labels, 2*m),
        slice::from_raw_parts(map, m),
        slice::from_raw_parts_mut(vals, m),
    )};
    for (i, (m, v)) in map.iter().zip(vals.iter_mut()).enumerate() {
        let out = [output_labels[2*i], output_labels[2*i+1]];
        //println!("{}: {:?}, {:?}, {:?}", i, *m, out[0], out[1]);
        if block_equals(*m, out[0]) {
            *v = false;
        } else if block_equals(*m, out[1]) {
            *v = true;
        } else {
            return GARBLE_ERR;
        }
    }
    //println!("vals: {:?}", vals);
    GARBLE_OK
}
#[no_mangle] pub extern fn garble_new(gc: *mut GarbleCircuit, n: usize, m: usize, ty: GarbleType) -> c_int {
    //println!("garble_new({:p}, {}, {}, {:?})", gc, n, m, ty);
    match unsafe { gc.as_mut() } {
        None => { GARBLE_ERR }
        Some(mut gc) => {
            gc.gates = ptr::null_mut();
            gc.outputs = unsafe { calloc(m, mem::size_of::<c_int>()) as _ };
            gc.wires = ptr::null_mut();
            gc.table = ptr::null_mut();
            gc.output_perms = ptr::null_mut();
            gc.ty = ty;
            gc.n = n;
            gc.m = m;
            gc.q = 0;
            gc.r = 0;
            //println!("returning {:?}", gc);
            GARBLE_OK
        }
    }
}

#[no_mangle]
#[inline]
pub extern fn garble_random_block() -> Block {
    let current_rand_index = unsafe { &mut CURRENT_RAND_INDEX };
    random_block_tweak(current_rand_index)
}

#[inline]
fn random_block_tweak(tweak: &mut u64) -> Block {
    let rand_aes_key = unsafe { &mut RAND_AES_KEY };

    //let mut tmp = [0u8;16];
    // All 3 of these compile down to the exact same assembly
    // /* 1 */ LittleEndian::write_u64(&mut tmp[0..8], *current_rand_index);
    // /* 2 */ tmp[0..8].copy_from_slice(&unsafe { mem::transmute::<u64,[u8;8]>(*current_rand_index) });
    // /* 3 */ unsafe { ptr::copy(mem::transmute::<&u64,&u8>(current_rand_index), tmp.as_mut_ptr(), 8) };
    //let mut out = [Block::load(&tmp, 0)];

    // This manages to be even more efficient (mov from rcx to xmm0 instead of spilling to the stack)
    let mut out = [block_from_u64x2(*tweak, 0)];
    aes_ecb_encrypt_blocks::<AesniViaLLVM>(&mut out, rand_aes_key);

    *tweak += 1;

    out[0]
}

#[no_mangle] pub extern fn garble_save() {
    panic!("garble_save");
}

#[derive(Debug)]
struct AesKey {
    rd_key: [Block; 11],
    rounds: usize
}

static mut RAND_AES_KEY: AesKey = AesKey { rd_key: [Block::splat(0); 11], rounds: 0 };
static mut CURRENT_RAND_INDEX: u64 = 0;

fn aes_set_encrypt_key(userkey: Block, key: &mut AesKey) {
    macro_rules! expand_assist {
        ($v1:ident, $v2:ident, $v3:ident, $v4:ident, $shuff_const:expr, $aes_const:expr) => {
            unsafe {
                asm!(concat!("aeskeygenassist $$", $aes_const, ", %xmm1, %xmm2") : "={xmm2}"($v2) : "{xmm1}"($v4));
                asm!("shufps $$16, %xmm1, %xmm3" : "={xmm3}"($v3) : "{xmm3}"($v3), "{xmm1}"($v1));
                asm!("pxor %xmm3, %xmm1" : "={xmm1}"($v1) : "{xmm1}"($v1), "{xmm3}"($v3));
                asm!("shufps $$140, %xmm1, %xmm3" : "={xmm3}"($v3) : "{xmm3}"($v3), "{xmm1}"($v1));
                asm!("pxor %xmm3, %xmm1" : "={xmm1}"($v1) : "{xmm1}"($v1), "{xmm3}"($v3));
                asm!(concat!("pshufd $$", $shuff_const, ", %xmm2, %xmm2") : "={xmm2}"($v2) : "{xmm2}"($v2));
                asm!("pxor %xmm2, %xmm1" : "={xmm1}"($v1) : "{xmm1}"($v1), "{xmm2}"($v2));
            }
        }
    }
    let mut x0 = userkey;
    let mut x1: Block;
    let mut x2 = Block::splat(0);
    key.rd_key[0] = x0;
    expand_assist!(x0, x1, x2, x0, "255", "1");
    key.rd_key[1] = x0;
    expand_assist!(x0, x1, x2, x0, "255", "2");
    key.rd_key[2] = x0;
    expand_assist!(x0, x1, x2, x0, "255", "4");
    key.rd_key[3] = x0;
    expand_assist!(x0, x1, x2, x0, "255", "8");
    key.rd_key[4] = x0;
    expand_assist!(x0, x1, x2, x0, "255", "16");
    key.rd_key[5] = x0;
    expand_assist!(x0, x1, x2, x0, "255", "32");
    key.rd_key[6] = x0;
    expand_assist!(x0, x1, x2, x0, "255", "64");
    key.rd_key[7] = x0;
    expand_assist!(x0, x1, x2, x0, "255", "128");
    key.rd_key[8] = x0;
    expand_assist!(x0, x1, x2, x0, "255", "27");
    key.rd_key[9] = x0;
    expand_assist!(x0, x1, x2, x0, "255", "54");
    key.rd_key[10] = x0;
    key.rounds = 10;
}

trait Aesni {
    fn aesenc(block: Block, subkey: Block) -> Block;
    fn aesenclast(block: Block, subkey: Block) -> Block;
}

struct AesniViaAsm;
impl Aesni for AesniViaAsm {
    fn aesenc(mut block: Block, subkey: Block) -> Block {
        unsafe { asm!("vaesenc $1, $0, $0" : "=x"(block) : "x"(subkey), "0"(block)); }
        block
    }
    fn aesenclast(mut block: Block, subkey: Block) -> Block {
        unsafe { asm!("vaesenclast $1, $0, $0" : "=x"(block) : "x"(subkey), "0"(block)); }
        block
    }
}

struct AesniViaLLVM;
impl Aesni for AesniViaLLVM {
    fn aesenc(block: Block, subkey: Block) -> Block {
        unsafe { block_from_i64x2(aesni_aesenc(i64x2_from_block(block), i64x2_from_block(subkey))) }
    }
    fn aesenclast(block: Block, subkey: Block) -> Block {
        unsafe { block_from_i64x2(aesni_aesenclast(i64x2_from_block(block), i64x2_from_block(subkey))) }
    }
}

#[inline]
fn aes_ecb_encrypt_blocks<A: Aesni>(blocks: &mut [Block], key: &AesKey) {
    static ROUNDS: usize = 10;
    for b in blocks.iter_mut() {
        *b = *b ^ key.rd_key[0];
    }
    for j in 1..ROUNDS {
        for b in blocks.iter_mut() {
            *b = A::aesenc(*b, key.rd_key[j]);
        }
    }
    for b in blocks.iter_mut() {
        *b = A::aesenclast(*b, key.rd_key[ROUNDS]);
    }
}

#[no_mangle] pub extern fn garble_seed(seed: *const Block) -> Block {
    //println!("garble_seed({:p})", seed);
    let mut cur_seed: Block = unsafe { mem::uninitialized() };
    unsafe {
        CURRENT_RAND_INDEX = 0;
    }
    match unsafe { seed.as_ref() } {
        Some(seed) => { cur_seed = *seed; }
        None => {
            if unsafe { RAND_bytes(mem::transmute(&mut cur_seed), 16) } == 0 {
                println!("RAND_bytes failed");
                cur_seed = Block::splat(0);
            }
        }
    }
    let aes: &mut AesKey = unsafe { &mut RAND_AES_KEY };
    aes_set_encrypt_key(cur_seed, aes);
    //println!("seeded: {:?}", aes);
    cur_seed
}
#[no_mangle] pub extern fn garble_size(gc: *const GarbleCircuit, wires: bool) -> usize {
    use std::mem::size_of_val as s;
    use std::mem::size_of as t;
    let gc: &GarbleCircuit = unsafe { &*gc };
    let mut size = 0;

    size += s(&gc.n) + s(&gc.m) + s(&gc.q) + s(&gc.r);
    size += s(&gc.ty);
    size += t::<GarbleGate>() * gc.q;
    size += garble_table_size(gc) * gc.q;
    if wires { size += t::<Block>() * 2 * gc.r };
    size += t::<c_int>() * gc.m;
    size += t::<bool>() * gc.m;
    size += s(&gc.fixed_label);
    size += s(&gc.global_key);

    size
}
#[no_mangle] pub extern fn garble_to_buffer(gc: *const GarbleCircuit, mut buf: *mut i8, wires: bool) -> c_int {
    // The C library tries to malloc if buf is null, but does it in a way that introduces an unconditional memory leak (it'd need char** buf to be correct)
    if buf.is_null() { return GARBLE_ERR; }
    // No null-checking is performed on gc
    let gc: &GarbleCircuit = unsafe { &*gc };

    unsafe fn copy_to_buf<T>(pbuf: &mut *mut i8, val: &T, count: usize) {
        let bytecount = count * mem::size_of::<T>();
        ptr::copy(mem::transmute::<&T,*const i8>(val), *pbuf, bytecount);
        *pbuf = (*pbuf).offset(bytecount as isize);
    }

    unsafe {
        println!("1 {:p}", buf);
        copy_to_buf(&mut buf, &gc.n, 1);
        println!("2 {:p}", buf);
        copy_to_buf(&mut buf, &gc.m, 1);
        println!("3 {:p}", buf);
        copy_to_buf(&mut buf, &gc.q, 1);
        println!("4 {:p}", buf);
        copy_to_buf(&mut buf, &gc.r, 1);
        println!("5 {:p}", buf);
        copy_to_buf(&mut buf, &gc.ty, 1);
        println!("6 {:p}", buf);
        copy_to_buf(&mut buf, &*gc.gates, gc.q);
        println!("7 {:p}", buf);
        copy_to_buf(&mut buf, &*gc.table, gc.q * garble_table_multiplier(gc.ty));
        println!("8 {:p}", buf);
        if wires { copy_to_buf(&mut buf, &*gc.wires, 2*gc.r) };
        println!("9 {:p}", buf);
        copy_to_buf(&mut buf, &*gc.outputs, gc.m);
        println!("a {:p}", buf);
        copy_to_buf(&mut buf, &*gc.output_perms, gc.m);
        println!("b {:p}", buf);
        copy_to_buf(&mut buf, &gc.fixed_label, 1);
        println!("c {:p}", buf);
        copy_to_buf(&mut buf, &gc.global_key, 1);
        println!("d {:p}", buf);
    }

    GARBLE_OK
}

pub fn generate_random_circuit<R: Rng>(mut rng: R, ty: GarbleType, n: usize, m: usize, q: usize) -> GarbleCircuit {
    let mut gc = unsafe { mem::uninitialized() };
    garble_new(&mut gc, n, m, ty);
    gc.q = q;
    let mut gates = vec![GarbleGate { ty: 0, in0: 0, in1: 0, out: 0 }; q];
    for (i, mut g) in gates.iter_mut().enumerate() {
        g.ty = if rng.gen() { GARBLE_GATE_XOR } else { GARBLE_GATE_AND };
        g.in0 = rng.gen_range(0, i+n);
        g.in1 = rng.gen_range(0, i+n);
        g.out = i;
    }
    gc.gates = gates.as_mut_ptr();
    mem::forget(gates); // ensure that gates outlives this function, gc is now considered to own the memory

    gc.r = n+q;
    for i in 0..gc.m {
        unsafe { *gc.outputs.offset(i as _) = (gc.r - gc.m + i) as _; }
    }

    gc
}

/*
>>> expected = __import__('Crypto').Cipher.AES.new('0123456789ABCDEF').encrypt("\0"*16)
>>> expected.encode('hex')
'9d2cda901b682d3359709a5ab2419624'
>>> __import__('struct').unpack(16*"B", expected)
(157, 44, 218, 144, 27, 104, 45, 51, 89, 112, 154, 90, 178, 65, 150, 36)
*/
#[test]
fn test_garblerandomblock() {
    let seed = Block::new(b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'A', b'B', b'C', b'D', b'E', b'F');
    garble_seed(&seed as _);
    let a = garble_random_block();
    println!("a: {:?}", a);
    assert!(a.eq(Block::new(157, 44, 218, 144, 27, 104, 45, 51, 89, 112, 154, 90, 178, 65, 150, 36)).all());
    garble_seed(&seed as _);
    let b = garble_create_delta();
    println!("b: {:?}", b);
    assert!(b.eq(Block::new(157, 44, 218, 144, 27, 104, 45, 51, 89, 112, 154, 90, 178, 65, 150, 36)).all());
    assert!(seed.eq(Block::new(b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'A', b'B', b'C', b'D', b'E', b'F')).all());
}

#[test]
fn test_garble_consistencycheck() {
    let mut rng = ::rand::StdRng::new().unwrap();
    //use rand::SeedableRng; let mut rng = ::rand::StdRng::from_seed(&[13]);

    const N: usize = 128;
    const M: usize = 128;
    const Q: usize = 1024;

    let mut hash1 = [0; SHA_DIGEST_LENGTH];

    let mut outputs1 = [false; M];
    let mut outputs2 = [false; M];

    let input_labels = garble_allocate_blocks(2 * N);
    let extracted_labels = garble_allocate_blocks(N);
    let output_map = garble_allocate_blocks(2 * M);
    let computed_output_map = garble_allocate_blocks(M);

    let inputs: Vec<bool> = rng.gen_iter().take(N).collect();
    println!("{:?}", inputs);

    let seed = garble_seed(ptr::null());
    //let seed = garble_seed(&Block::new(13, 51, 160, 67, 16, 185, 160, 164, 193, 84, 26, 6, 252, 133, 65, 250));
    let rng = rng; // avoid accidentally mutating the rng

    // assert that rng cloning is deterministic
    assert_eq!(rng.clone().gen_iter().take(N).collect::<Vec<u8>>(), rng.clone().gen_iter().take(N).collect::<Vec<u8>>());

    let mut gc1 = generate_random_circuit(rng.clone(), GarbleType::HalfGates, N, M, Q);
    println!("gc1 before garble {:?}", gc1);
    garble_garble(&mut gc1, ptr::null(), output_map);
    println!("gc1 after garble {:?}", gc1);
    garble_hash(&gc1, hash1.as_mut_ptr());
    unsafe { ptr::copy(gc1.wires, input_labels, 2 * N) };

    garble_extract_labels(extracted_labels, input_labels, inputs.as_ptr(), N);
    garble_eval(&gc1, extracted_labels, computed_output_map, outputs1.as_mut_ptr());
    assert!(garble_map_outputs(output_map, computed_output_map, outputs2.as_mut_ptr(), M) == GARBLE_OK);
    assert!(outputs1.iter().zip(outputs2.iter()).all(|(o1,o2)| o1 == o2));

    println!("seed {:?}", seed);
    let seed2 = garble_seed(&seed);
    println!("seed2 {:?}", seed2);
    let mut gc2 = generate_random_circuit(rng.clone(), GarbleType::HalfGates, N, M, Q);
    println!("gc2 before garble {:?}", gc2);
    garble_garble(&mut gc2, ptr::null(), ptr::null_mut());
    println!("gc2 after garble {:?}", gc2);

    unsafe {
        assert_eq!(slice::from_raw_parts(gc1.gates, gc1.q), slice::from_raw_parts(gc2.gates, gc2.q));
        // u8x16 doesn't support PartialEq, consider making Block a newtype? (would also enable hex printouts)
        //assert_eq!(slice::from_raw_parts(gc1.table, gc1.q), slice::from_raw_parts(gc2.table, gc2.q));
        //assert_eq!(slice::from_raw_parts(gc1.wires, 2*gc1.r), slice::from_raw_parts(gc2.wires, 2*gc2.r));
    }
    assert!(gc1.fixed_label.eq(gc2.fixed_label).all());
    assert!(gc1.global_key.eq(gc2.global_key).all());

    assert_eq!(garble_size(&gc1, true), garble_size(&gc2, true));
    let size = garble_size(&gc1, true);
    println!("size: {}", size);
    let mut bytes1 = vec![0; size];
    let mut bytes2 = vec![0; size];
    assert!(garble_to_buffer(&gc1, bytes1.as_mut_ptr(), true) == GARBLE_OK);
    assert!(garble_to_buffer(&gc2, bytes2.as_mut_ptr(), true) == GARBLE_OK);
    for i in 0..size {
        if bytes1[i] != bytes2[i] {
            println!("inequality at {}: {:x} {:x}", i, bytes1[i] as u8, bytes2[i] as u8);
        }
    }
    //assert_eq!(bytes1, bytes2);

    assert!(garble_check(&gc2, hash1.as_ptr()) == GARBLE_OK);

    unsafe {
        free(computed_output_map as _);
        free(extracted_labels as _);
        free(output_map as _);
        free(input_labels as _);
    }
    garble_delete(&mut gc1);
    garble_delete(&mut gc2);
}

#[cfg(test)]
mod benchmarks {
    use garble::*;
    use rand::{Rng, StdRng};
    use std::ptr;
    use test::Bencher;
    const N: usize = 128;
    const M: usize = 128;
    const Q: usize = 4096;

    #[inline(always)]
    fn bench_harness<F>(b: &mut Bencher, ty: GarbleType, f: F) where
        F: Fn(&mut Bencher, *mut Block, *mut Block, *mut Block, *mut Block, *mut bool, *const bool, *mut GarbleCircuit) {
        let mut rng = StdRng::new().unwrap();

        let input_labels = garble_allocate_blocks(2 * N);
        let extracted_labels = garble_allocate_blocks(N);
        let output_map = garble_allocate_blocks(2 * M);
        let computed_output_map = garble_allocate_blocks(M);
        let mut outputs = [false; M];
        let inputs: Vec<bool> = rng.gen_iter().take(N).collect();

        let rng = rng;

        let mut gc = generate_random_circuit(rng.clone(), ty, N, M, Q);
        f(b, input_labels, extracted_labels, output_map, computed_output_map, outputs.as_mut_ptr(), inputs.as_ptr(), &mut gc);
    }

    #[inline(always)]
    fn bench_garble(b: &mut Bencher, ty: GarbleType) {
        bench_harness(b, ty, |b, input_labels, extracted_labels, output_map, computed_output_map, outputs, inputs, gc| {
            b.iter(|| { garble_garble(gc, ptr::null(), output_map) });
            garble_extract_labels(extracted_labels, input_labels, inputs, N);
            garble_eval(gc, extracted_labels, computed_output_map, outputs);
        });
    }
    #[inline(always)]
    fn bench_eval(b: &mut Bencher, ty: GarbleType) {
        bench_harness(b, ty, |b, input_labels, extracted_labels, output_map, computed_output_map, outputs, inputs, gc| {
            garble_garble(gc, ptr::null(), output_map);
            b.iter(|| {
                garble_extract_labels(extracted_labels, input_labels, inputs, N);
                garble_eval(gc, extracted_labels, computed_output_map, outputs);
            });
        });
    }

    #[bench] fn bench_garble_standard(b: &mut Bencher) { bench_garble(b, GarbleType::Standard); }
    #[bench] fn bench_garble_halfgates(b: &mut Bencher) { bench_garble(b, GarbleType::HalfGates); }
    #[bench] fn bench_garble_privacyfree(b: &mut Bencher) { bench_garble(b, GarbleType::PrivacyFree); }
    #[bench] fn bench_eval_standard(b: &mut Bencher) { bench_eval(b, GarbleType::Standard);}
    #[bench] fn bench_eval_halfgates(b: &mut Bencher) { bench_eval(b, GarbleType::HalfGates);}
    #[bench] fn bench_eval_privacyfree(b: &mut Bencher) { bench_eval(b, GarbleType::PrivacyFree);}
}
