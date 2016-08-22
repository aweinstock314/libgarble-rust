use byteorder::{ByteOrder, LittleEndian};
use libc::{c_int, c_void, calloc, posix_memalign};
use openssl_sys::RAND_bytes;
use simd::u8x16;
use std::cell::UnsafeCell;
use std::{mem, ptr, slice};

type Block = u8x16;

static GARBLE_OK: c_int = 0;
static GARBLE_ERR: c_int = -1;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub enum GarbleType {
    Standard, HalfGates, PrivacyFree
}

#[repr(C)]
#[derive(Debug)]
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
#[no_mangle] pub extern fn garble_create_delta() -> Block {
    println!("garble_create_delta");
    let delta = garble_random_block();
    delta.replace(0, delta.extract(0) | 1)
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

#[inline]
fn garble_table_size(gc: *const GarbleCircuit) -> usize {
    match unsafe { gc.as_ref().map(|gc| gc.ty) } {
        None => 0,
        Some(GarbleType::Standard) => 3 * mem::size_of::<Block>(),
        Some(GarbleType::HalfGates) => 2 * mem::size_of::<Block>(),
        Some(GarbleType::PrivacyFree) => mem::size_of::<Block>(),
    }
}

#[no_mangle] pub extern fn garble_garble(gc: *mut GarbleCircuit, input_labels: *const Block, output_labels: *mut Block) -> c_int {
    println!("garble_garble");
    let mut key: AesKey = unsafe { mem::uninitialized() };
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
        delta = garble_create_delta();
        for i in 0..gc.n {
            let i = i as isize;
            unsafe {
                let wire0 = gc.wires.offset(2*i);
                let wire1 = gc.wires.offset(2*i + 1);
                *wire0 = garble_random_block();
                if let GarbleType::PrivacyFree = gc.ty {
                    *wire0 = (*wire0).replace(0, (*wire0).extract(0) & 0xfe);
                }
                *wire1 = *wire0 ^ delta;
            }
        }
    }

    let mut fixed_label = garble_random_block();
    gc.fixed_label = fixed_label;
    unsafe {
        fixed_label = fixed_label.replace(0, fixed_label.extract(0) & 0xfe);
        *gc.wires.offset((2*gc.n) as _) = fixed_label;
        *gc.wires.offset((2*gc.n+1) as _) = fixed_label ^ delta;

        fixed_label = fixed_label.replace(0, fixed_label.extract(0) | 0x01);
        *gc.wires.offset((2*(gc.n+1)) as _) = fixed_label;
        *gc.wires.offset((2*(gc.n+1)+1) as _) = fixed_label ^ delta;
    }

    gc.global_key = garble_random_block();
    aes_set_encrypt_key(gc.global_key, &mut key);

    match gc.ty {
        GarbleType::Standard => garble_standard(gc, &mut key, delta),
        GarbleType::HalfGates => garble_halfgates(gc, &mut key, delta),
        GarbleType::PrivacyFree => garble_privacyfree(gc, &mut key, delta),
    }

    for i in 0..gc.m {
        let i = i as isize;
        unsafe {
            let idx = *gc.outputs.offset(i) as isize;
            *gc.output_perms.offset(i) = (*gc.wires.offset(2 * idx)).extract(0) & 1 == 1;
        }
    }

    if !output_labels.is_null() {
        for i in 0..gc.m {
            let i = i as isize;
            unsafe {
                let idx = *gc.outputs.offset(i) as isize;
                *output_labels.offset(2*i) = *gc.wires.offset(2 * idx);
                *output_labels.offset(2*i+1) = *gc.wires.offset(2 * idx+1);
            }
        }
    }

    GARBLE_OK
}

fn garble_standard(gc: &mut GarbleCircuit, key: &mut AesKey, delta: Block) {
    let _ = (gc, key, delta); // warning suppression
    panic!("garble_standard");
}
fn garble_halfgates(gc: &mut GarbleCircuit, key: &mut AesKey, delta: Block) {
    let _ = (gc, key, delta); // warning suppression
    panic!("garble_halfgates");
}
fn garble_privacyfree(gc: &mut GarbleCircuit, key: &mut AesKey, delta: Block) {
    let _ = (gc, key, delta); // warning suppression
    panic!("garble_privacyfree");
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
#[no_mangle] pub extern fn garble_new(gc: *mut GarbleCircuit, n: usize, m: usize, ty: GarbleType) -> c_int {
    println!("garble_new({:p}, {}, {}, {:?})", gc, n, m, ty);
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
            println!("returning {:?}", gc);
            GARBLE_OK
        }
    }
}

#[no_mangle]
#[inline]
pub extern fn garble_random_block() -> Block {
    println!("garble_random_block");
    let current_rand_index = unsafe { CURRENT_RAND_INDEX.as_mut() };
    let rand_aes_key = unsafe { RAND_AES_KEY.as_mut() };
    *current_rand_index += 1;
    let mut tmp = [0u8;16];

    // All 3 of these compile down to the exact same assembly
    LittleEndian::write_u64(&mut tmp[0..8], *current_rand_index);
    //tmp[0..8].copy_from_slice(&unsafe { mem::transmute::<u64,[u8;8]>(*current_rand_index) });
    //unsafe { ptr::copy(mem::transmute::<&u64,&u8>(current_rand_index), tmp.as_mut_ptr(), 8) };

    let mut out = Block::load(&tmp, 0);
    out = out ^ rand_aes_key.rd_key[0];
    for i in 1..10 {
        unsafe {
            asm!("aesenc %xmm1, %xmm0" : "={xmm0}"(out) : "{xmm0}"(out), "{xmm1}"(rand_aes_key.rd_key[i]));
        }
    }
    unsafe {
        asm!("aesenclast %xmm1, %xmm0": "={xmm0}"(out) : "{xmm0}"(out), "{xmm1}"(rand_aes_key.rd_key[10]));
    }
    out
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
impl<T> GlobalWrapper<T> {
    unsafe fn as_mut(&self) -> &mut T {
        // unwrap is sound here since an UnsafeCell's inner pointer is never null
        // (unsynchronized global mutable variables are still thread-unsafe)
        self.0.get().as_mut().unwrap()
    }
}
unsafe impl<T> Sync for GlobalWrapper<T> {}

// unsafe global variable for compatibility with the C library
static RAND_AES_KEY: GlobalWrapper<AesKey> = GlobalWrapper(UnsafeCell::new(
    AesKey { rd_key: [Block::splat(0); 11], rounds: 0 }
));
static CURRENT_RAND_INDEX: GlobalWrapper<u64> = GlobalWrapper(UnsafeCell::new(0));

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
    unsafe {
        *CURRENT_RAND_INDEX.as_mut() = 0;
    }
    match unsafe { seed.as_mut() } {
        Some(seed) => { cur_seed = *seed; }
        None => {
            if unsafe { RAND_bytes(mem::transmute(&mut cur_seed), 16) } == 0 {
                println!("RAND_bytes failed");
                cur_seed = Block::splat(0);
            }
        }
    }
    let aes: &mut AesKey = unsafe { RAND_AES_KEY.as_mut() };
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
