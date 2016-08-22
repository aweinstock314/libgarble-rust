use libc::{c_int, c_void, calloc, posix_memalign};
use openssl_sys::RAND_bytes;
use simd::u8x16;
use std::cell::UnsafeCell;
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
    println!("garble_allocate_blocks({}): {}, {:p}", nblocks, res, blocks);
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

#[derive(Debug)]
struct AesKey {
    rd_key: [Block; 11],
    rounds: usize
}
struct GlobalWrapper<T>(UnsafeCell<T>);
unsafe impl<T> Sync for GlobalWrapper<T> {}

// unsafe global variable for compatibility with the C library
static RAND_AES_KEY: GlobalWrapper<AesKey> = GlobalWrapper(UnsafeCell::new(
    AesKey { rd_key: [Block::splat(0); 11], rounds: 0 }
));

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

#[no_mangle] pub extern fn garble_seed(seed: *mut Block) -> Block {
    println!("garble_seed({:p})", seed);
    let mut cur_seed: Block = unsafe { mem::uninitialized() };
    match unsafe { seed.as_mut() } {
        Some(seed) => { cur_seed = *seed; }
        None => {
            if unsafe { RAND_bytes(mem::transmute(&mut cur_seed), 16) } == 0 {
                println!("RAND_bytes failed");
                cur_seed = Block::splat(0);
            }
        }
    }
    let aes: &mut AesKey = unsafe { RAND_AES_KEY.0.get().as_mut().unwrap() };
    aes_set_encrypt_key(cur_seed, aes);
    println!("seeded: {:?}", aes);
    cur_seed
}
#[no_mangle] pub extern fn garble_size() {
    panic!("garble_size");
}
#[no_mangle] pub extern fn garble_to_buffer() {
    panic!("garble_to_buffer");
}
