//! Generates the foreign-language bindings (Swift/Kotlin) for `hop-ffi`.
//!
//! Usage (library mode, after building the cdylib):
//!   cargo run -p hop-ffi --features cli --bin uniffi-bindgen -- \
//!     generate --library target/debug/libhop_ffi.dylib \
//!     --language swift --out-dir target/bindings/swift

fn main() {
    uniffi::uniffi_bindgen_main()
}
