#![allow(
    clippy::missing_safety_doc,
    clippy::redundant_static_lifetimes,
    clippy::too_many_arguments,
    clippy::unreadable_literal,
    clippy::upper_case_acronyms,
    improper_ctypes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_imports
)]
#![no_std]

use core::{
    convert::TryInto,
    ffi::{c_char, c_int, c_uint, c_ulong, c_void},
};

#[allow(clippy::useless_transmute, clippy::derive_partial_eq_without_eq)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
pub use generated::*;

// Modify all of these function pointers to override BoringSSL's
// memory allocator.
#[cfg(any(
    not(unix),
    any(
        target_os = "aix",
        target_os = "ios",
        target_os = "macos",
        target_os = "tvos",
        target_os = "windows",
    )
))]
extern "C" {
    pub static mut OPENSSL_memory_alloc: Option<unsafe extern "C" fn(usize) -> *mut c_void>;
    pub static mut OPENSSL_memory_free: Option<unsafe extern "C" fn(*mut c_void) -> ()>;
    pub static mut OPENSSL_memory_get_size: Option<unsafe extern "C" fn(*mut c_void) -> usize>;
}

// Define all of these functions to override BoringSSL's memory
// allocator.
#[cfg(all(
    all(unix, not(target_os = "aix")),
    not(any(
        target_os = "aix",
        target_os = "ios",
        target_os = "macos",
        target_os = "tvos",
        target_os = "windows",
    ))
))]
extern "C" {
    pub static OPENSSL_memory_alloc: Option<unsafe extern "C" fn(usize) -> *mut c_void>;
    pub static OPENSSL_memory_free: Option<unsafe extern "C" fn(*mut c_void) -> ()>;
    pub static OPENSSL_memory_get_size: Option<unsafe extern "C" fn(*mut c_void) -> usize>;
}

#[cfg(target_pointer_width = "64")]
pub type BN_ULONG = u64;
#[cfg(target_pointer_width = "32")]
pub type BN_ULONG = u32;

pub const fn ERR_PACK(l: c_int, f: c_int, r: c_int) -> c_ulong {
    ((l as c_ulong & 0x0FF) << 24) | ((f as c_ulong & 0xFFF) << 12) | (r as c_ulong & 0xFFF)
}

pub const fn ERR_GET_LIB(l: c_uint) -> c_int {
    ((l >> 24) & 0x0FF) as c_int
}

pub const fn ERR_GET_FUNC(l: c_uint) -> c_int {
    ((l >> 12) & 0xFFF) as c_int
}

pub const fn ERR_GET_REASON(l: c_uint) -> c_int {
    (l & 0xFFF) as c_int
}

//// Initialize BoringSSL.
///
/// This function must be called before using any library
/// routines.
///
/// See <https://github.com/openssl/openssl/issues/3505>.
pub fn init() {
    use core::{
        ptr,
        sync::atomic::{AtomicBool, Ordering},
    };

    // lock is a spinlock guarding access to OPENSSL_init_ssl.
    static lock: AtomicBool = AtomicBool::new(false);

    // done is true if we have invoked OPENSSL_init_ssl.
    static done: AtomicBool = AtomicBool::new(false);

    if done.load(Ordering::SeqCst) {
        // Fast path: we've already invoked OPENSSL_init_ssl.
        return;
    }

    loop {
        if lock
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
        {
            break;
        }
    }

    if done.load(Ordering::SeqCst) {
        // Check again: perhaps somebody invoked OPENSSL_init_ssl
        // while we were spinning.
        return;
    }

    const OPTS: u64 = OPENSSL_INIT_LOAD_SSL_STRINGS as u64;

    // SAFETY: FFI call, no invariants
    assert_eq!(unsafe { OPENSSL_init_crypto(OPTS, ptr::null_mut()) }, 1);

    #[cfg(feature = "ssl")]
    assert_eq!(
        // SAFETY: FFI call, no invariants
        unsafe { OPENSSL_init_ssl(OPTS, ptr::null_mut()) },
        1
    );

    // Mark that we've finished prior to releasing the spinlock.
    // Otherwise, somebody else could see done=false before we're
    // able to mark our progress.
    done.store(true, Ordering::SeqCst);
    lock.store(false, Ordering::SeqCst);
}
