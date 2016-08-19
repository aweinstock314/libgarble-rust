use libc::{c_void, posix_memalign};
use simd::u8x16;
use std::mem;
use std::ptr;

#[no_mangle] pub extern fn garble_allocate_blocks(nblocks: usize) -> *mut u8x16 {
    let mut blocks: *mut c_void = ptr::null_mut();
    let res = unsafe { posix_memalign(&mut blocks, mem::align_of::<u8x16>(), nblocks * mem::size_of::<u8x16>()) };
    println!("garble_allocate_blocks: {}, {:p}", res, blocks);
    if res == 0 {
        blocks as *mut u8x16
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
#[no_mangle] pub extern fn garble_new() {
    panic!("garble_new");
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
