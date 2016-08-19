use libc::{c_int, c_void, calloc, posix_memalign};
use simd::u8x16;
use std::mem;
use std::ptr;

type Block = u8x16;

static GARBLE_OK: c_int = 0;
static GARBLE_ERR: c_int = -1;

#[repr(C)]
#[derive(Debug)]
pub enum GarbleType {
    Standard, HalfGates, PrivacyFree
}

#[repr(C)]
#[derive(Debug)]
pub struct GarbleGate {
    ty: u8,
    in0: u64, in1: u64, out: u64
}

#[repr(C)]
#[derive(Debug)]
pub struct GarbleCircuit {
    n: u64, m: u64, q: u64, r:u64,
    ty: GarbleType,
    gates: *mut GarbleGate, // q
    table: *mut Block,      // q
    wires: *mut Block,      // 2r
    outputs: *mut c_int,    // m
    output_perms: *mut bool,
    fixed_label: Block,
    global_key: Block
}

#[no_mangle] pub extern fn garble_allocate_blocks(nblocks: usize) -> *mut Block {
    let mut blocks: *mut c_void = ptr::null_mut();
    let res = unsafe { posix_memalign(&mut blocks, mem::align_of::<Block>(), nblocks * mem::size_of::<Block>()) };
    println!("garble_allocate_blocks: {}, {:p}", res, blocks);
    if res == 0 {
        blocks as *mut Block
    } else {
        println!("posix_memalign failed: {}", res);
        ptr::null_mut()
    }
}

#[no_mangle] pub extern fn garble_check() {
    panic!("garble_check");
}
#[no_mangle] pub extern fn garble_circuit_from_file() {
    panic!("garble_circuit_from_file");
}
#[no_mangle] pub extern fn garble_circuit_to_file() {
    panic!("garble_circuit_to_file");
}
#[no_mangle] pub extern fn garble_create_delta() {
    panic!("garble_create_delta");
}
#[no_mangle] pub extern fn garble_create_input_labels() {
    panic!("garble_create_input_labels");
}
#[no_mangle] pub extern fn garble_delete() {
    panic!("garble_delete");
}
#[no_mangle] pub extern fn garble_eval() {
    panic!("garble_eval");
}
#[no_mangle] pub extern fn garble_extract_labels() {
    panic!("garble_extract_labels");
}
#[no_mangle] pub extern fn garble_from_buffer() {
    panic!("garble_from_buffer");
}
#[no_mangle] pub extern fn garble_garble() {
    panic!("garble_garble");
}
#[no_mangle] pub extern fn garble_hash() {
    panic!("garble_hash");
}
#[no_mangle] pub extern fn garble_load() {
    panic!("garble_load");
}
#[no_mangle] pub extern fn garble_map_outputs() {
    panic!("garble_map_outputs");
}
#[no_mangle] pub extern fn garble_new(gc: *mut GarbleCircuit, n: u64, m: u64, ty: GarbleType) -> c_int {
    println!("garble_new({:p}, {}, {}, {:?})", gc, n, m, ty);
    match unsafe { gc.as_mut() } {
        None => { GARBLE_ERR }
        Some(mut gc) => {
            gc.gates = ptr::null_mut();
            gc.outputs = unsafe { calloc(m as usize, mem::size_of::<c_int>()) as _ };
            gc.wires = ptr::null_mut();
            gc.table = ptr::null_mut();
            gc.output_perms = ptr::null_mut();
            gc.ty = ty;
            gc.n = n;
            gc.m = m;
            gc.q = 0;
            gc.r = 0;
            println!("returning {:?}", gc);
            GARBLE_OK
        }
    }
}
#[no_mangle] pub extern fn garble_random_block() {
    panic!("garble_random_block");
}
#[no_mangle] pub extern fn garble_save() {
    panic!("garble_save");
}
#[no_mangle] pub extern fn garble_seed() {
    panic!("garble_seed");
}
#[no_mangle] pub extern fn garble_size() {
    panic!("garble_size");
}
#[no_mangle] pub extern fn garble_to_buffer() {
    panic!("garble_to_buffer");
}
