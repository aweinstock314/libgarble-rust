# libgarble-rust

This is a port from C to Rust of Alex Malozemoff's [libgarble](https://github.com/amaloz/libgarble). It produces a dynamic library (shared object) that should be a drop-in replacement (although only the functions needed to run his AES test circuit are currently implmented).

## Building and running

```bash
somedir/$ git clone https://github.com/amaloz/libgarble
somedir/$ git clone https://github.com/aweinstock314/libgarble-rust
somedir/libgarble$ autoreconf -f -i && ./configure --with-msgpack=no && make
somedir/libgarble/test$ make aes
somedir/libgarble/test$ ./aes > output_with_c_dylib.txt
somedir/libgarble-rust$ cargo build --release
somedir/libgarble-rust$ ./tamper_with_so.sh # this is not idempotent (should only be run once)
somedir/libgarble/test$ make aes
somedir/libgarble/test$ ./aes > output_with_rust_dylib.txt
```

## Correspondences between this and the C version

- Some of the functions are direct transliterations from C (e.g. `garble_`{`allocate_blocks`,`delete`,`new`,`seed`}).
- `garble_`{`check`,`extract_labels`} are fairly similar to their C versions, but use `slice::from_raw_parts`{,`_mut`} to make things more convenient (e.g. == on slices does structural equality).
- `garble_`{`garble`,`eval`} are similar at a high-level to their C counterparts, but like `check` and `extract_labels` use more rust features for convenience.
- `_garble_`{`standard`,`halfgates`,`privacy_free`} in the C are mostly the same, and were abstracted to `garble_loop`, with their inner-loop functions being passed as arguments (likewise with `s/garble/eval/`).
- `garble_`{`create_delta`,`random_block`} were modified to use helper functions that don't touch global memory for the tweak (although the AES key is still global, since the API doesn't allow have anywhere else to stash the key between `garble_seed` and `garble_garble`).
- `aes_set_encrypt_key` uses inline assembly instead of intrinsics, because I didn't know about the `llvmint` crate for intrinsics at the time.
- `aes_ecb_encrypt_blocks` is templated over a choice of callers using inline assembly and LLVM intrinsics. I initially wrote it in assembly, but the interface between the inline assembly and rust code was generating unneccessary loads from memory to registers (`vaesenc`{,`last`} allow a memory operand for the AES key). Switching to LLVM intrinsics got a speedup in most places, but a slowdown for halfgates mode. I haven't found out the reason (I just tallied it up to processor magic), but the templates allow each callsite to pick the more performant one.
