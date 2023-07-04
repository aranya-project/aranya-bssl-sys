#![allow(unstable_name_collisions)]

use {
    bindgen::{EnumVariation, Formatter, MacroTypeVariation},
    std::{
        env, error, fmt,
        io::{self, Write},
        path::{Path, PathBuf},
        process::{Command, ExitStatus},
        result, str,
    },
};

type Result<T> = result::Result<T, Box<dyn error::Error>>;

#[derive(Debug)]
struct ExitStatusError(ExitStatus);

impl fmt::Display for ExitStatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "process exited unsuccessfully: {}", self.0)
    }
}

impl error::Error for ExitStatusError {}

trait StatusResult {
    fn exit_ok(&self) -> result::Result<(), ExitStatusError>;
}

impl StatusResult for ExitStatus {
    fn exit_ok(&self) -> result::Result<(), ExitStatusError> {
        if self.success() {
            Ok(())
        } else {
            Err(ExitStatusError(*self))
        }
    }
}

/// The env var that has the directory we search for precompiled
/// BoringSSL files.
const BSSL_PRECOMPILED_PATH_VAR: &str = "BSSL_PRECOMPILED_PATH";
/// The env var that has the directory we search for BoringSSL
/// source files.
const BSSL_SOURCE_PATH_VAR: &str = "BSSL_SOURCE_PATH";
/// The env var that has the directory we search for BoringSSL
/// header files.
const BSSL_INCLUDE_PATH_VAR: &str = "BSSL_INCLUDE_PATH";
/// The env var that has the git hash we checkout if neither
/// BSSL_PRECOMPILED_PATH nor BSSL_SOURCE_PATH are provided.
const BSSL_GIT_HASH_VAR: &str = "BSSL_GIT_HASH";
/// The env var that tells us whether to skip checking out
/// `BSSL_GIT_HASH`.
const BSSL_GIT_NO_CHECKOUT_VAR: &str = "BSSL_GIT_NO_CHECKOUT";
/// The git hash we checkout if BSSL_GIT_HASH is unset.
///
/// This is master as of 2023/05/08.
const BSSL_GIT_HASH: &str = "a972b78d1b11009cd07852fb4be2cc938489e031";
/// The env var that has the path to `malloc.patch` for patching
/// `OPENSSL_memory_alloc`, etc.
const BSSL_MALLOC_PATCH_PATH_VAR: &str = "BSSL_MALLOC_PATCH_PATH";
/// The directory the baked-in BoringSSL sources are cloned into.
const BSSL_DEPS_PATH: &str = if cfg!(fips) {
    "deps/boringssl-fips"
} else {
    "deps/boringssl"
};

fn cmake_params_android() -> &'static [(&'static str, &'static str)] {
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let cmake_params_android = if cfg!(feature = "ndk-old-gcc") {
        CMAKE_PARAMS_ANDROID_NDK_OLD_GCC
    } else {
        CMAKE_PARAMS_ANDROID_NDK
    };
    for (android_arch, params) in cmake_params_android {
        if *android_arch == arch {
            return params;
        }
    }
    &[]
}

// Additional parameters for Android build of BoringSSL.
//
// Android NDK < 18 with GCC.
const CMAKE_PARAMS_ANDROID_NDK_OLD_GCC: &[(&str, &[(&str, &str)])] = &[
    (
        "aarch64",
        &[("ANDROID_TOOLCHAIN_NAME", "aarch64-linux-android-4.9")],
    ),
    (
        "arm",
        &[("ANDROID_TOOLCHAIN_NAME", "arm-linux-androideabi-4.9")],
    ),
    (
        "x86",
        &[("ANDROID_TOOLCHAIN_NAME", "x86-linux-android-4.9")],
    ),
    (
        "x86_64",
        &[("ANDROID_TOOLCHAIN_NAME", "x86_64-linux-android-4.9")],
    ),
];

// Android NDK >= 19.
const CMAKE_PARAMS_ANDROID_NDK: &[(&str, &[(&str, &str)])] = &[
    ("aarch64", &[("ANDROID_ABI", "arm64-v8a")]),
    ("arm", &[("ANDROID_ABI", "armeabi-v7a")]),
    ("x86", &[("ANDROID_ABI", "x86")]),
    ("x86_64", &[("ANDROID_ABI", "x86_64")]),
];

fn ios_sdk_name() -> &'static str {
    for (name, value) in cmake_params_ios() {
        if *name == "CMAKE_OSX_SYSROOT" {
            return value;
        }
    }
    panic!(
        "cannot find iOS SDK for {} in CMAKE_PARAMS_IOS",
        env::var("TARGET").unwrap_or("???".into())
    );
}

fn cmake_params_ios() -> &'static [(&'static str, &'static str)] {
    let target = env::var("TARGET").unwrap();
    CMAKE_PARAMS_IOS
        .iter()
        .find(|(ios_target, _)| *ios_target == target)
        .map(|x| x.1)
        .unwrap_or(&[])
}

const CMAKE_PARAMS_IOS: &[(&str, &[(&str, &str)])] = &[
    (
        "aarch64-apple-ios",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "arm64"),
            ("CMAKE_OSX_SYSROOT", "iphoneos"),
        ],
    ),
    (
        "aarch64-apple-ios-sim",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "arm64"),
            ("CMAKE_OSX_SYSROOT", "iphonesimulator"),
        ],
    ),
    (
        "x86_64-apple-ios",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "x86_64"),
            ("CMAKE_OSX_SYSROOT", "iphonesimulator"),
        ],
    ),
];

/// Returns a new cmake::Config for building BoringSSL.
///
/// It will add platform-specific parameters if needed.
fn boringssl_cmake_config<P>(dir: P) -> Result<cmake::Config>
where
    P: AsRef<Path>,
{
    let arch = env::var("CARGO_CFG_TARGET_ARCH")?;
    let os = env::var("CARGO_CFG_TARGET_OS")?;
    let host = env::var("HOST")?;
    let target = env::var("TARGET")?;
    let pwd = env::current_dir()?;

    let mut cfg = cmake::Config::new(dir);
    if host != target {
        // Add platform-specific parameters for cross-compilation.
        match os.as_ref() {
            "android" => {
                // We need ANDROID_NDK_HOME to be set properly.
                println!("cargo:rerun-if-env-changed=ANDROID_NDK_HOME");
                let android_ndk_home =
                    env::var("ANDROID_NDK_HOME").expect("ANDROID_NDK_HOME must be set");
                let android_ndk_home = Path::new(&android_ndk_home);
                for (name, value) in cmake_params_android() {
                    eprintln!("android arch={} add {}={}", arch, name, value);
                    cfg.define(name, value);
                }
                let toolchain_file = android_ndk_home.join("build/cmake/android.toolchain.cmake");
                let toolchain_file = toolchain_file.to_str().unwrap();
                eprintln!("android toolchain={}", toolchain_file);
                cfg.define("CMAKE_TOOLCHAIN_FILE", toolchain_file);

                // 21 is the minimum level tested. You can give higher value.
                cfg.define("ANDROID_NATIVE_API_LEVEL", "21");
                cfg.define("ANDROID_STL", "c++_shared");
            }

            "ios" => {
                for (name, value) in cmake_params_ios() {
                    eprintln!("ios arch={} add {}={}", arch, name, value);
                    cfg.define(name, value);
                }

                // Bitcode is always on.
                let bitcode_cflag = "-fembed-bitcode";

                // Hack for Xcode 10.1.
                let target_cflag = if arch == "x86_64" {
                    "-target x86_64-apple-ios-simulator"
                } else {
                    ""
                };

                let cflag = format!("{} {}", bitcode_cflag, target_cflag);
                cfg.define("CMAKE_ASM_FLAGS", &cflag);
                cfg.cflag(&cflag);
            }

            "windows" => {
                if host.contains("windows") {
                    // BoringSSL's CMakeLists.txt isn't set up for cross-compiling using Visual Studio.
                    // Disable assembly support so that it at least builds.
                    cfg.define("OPENSSL_NO_ASM", "YES");
                }
            }

            "linux" => match arch.as_str() {
                "x86" => {
                    cfg.define(
                        "CMAKE_TOOLCHAIN_FILE",
                        pwd.join(env::var("OUT_DIR")?)
                            .join(BSSL_DEPS_PATH)
                            .join("src")
                            .join("util")
                            .join("32-bit-toolchain.cmake")
                            .as_os_str(),
                    );
                }
                "aarch64" => {
                    cfg.define(
                        "CMAKE_TOOLCHAIN_FILE",
                        pwd.join("cmake/aarch64-linux.cmake").as_os_str(),
                    );
                }
                _ => {
                    eprintln!(
                        "warning: no toolchain file configured by boring-sys for {}",
                        target
                    );
                }
            },

            _ => {}
        }
    }

    if look_path("ninja").is_some() {
        cfg.generator("Ninja");
    }
    cfg.very_verbose(true);

    match env::var("OPT_LEVEL")?.as_str() {
        "0" => {
            cfg.define("CFI", "");
        }
        "1" | "2" | "3" => {
            cfg.define("CMAKE_BUILD_TYPE", "Release").define("CFI", "");
        }
        "s" | "z" => {
            // Don't define CFI as it can increase binary size by
            // ~15%.
            cfg.define("OPENSSL_SMALL", "1");
        }
        _ => (),
    };

    if let Ok(prefix) = env::var("BSSL_PREFIX") {
        if let Ok(path) = env::var("BSSL_PREFIX_SYMBOLS") {
            cfg.define("BORINGSSL_PREFIX", prefix)
                .define("BORINGSSL_PREFIX_SYMBOLS", path);
        }
    }

    Ok(cfg)
}

fn look_path<P>(file: P) -> Option<PathBuf>
where
    P: AsRef<Path>,
{
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths)
            .filter_map(|dir| {
                let file = dir.join(&file);
                if file.is_file() {
                    Some(file)
                } else {
                    None
                }
            })
            .next()
    })
}

/// Verify that the toolchains match https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp3678.pdf
/// See "Installation Instructions" under section 12.1.
// TODO: maybe this should also verify the Go and Ninja versions? But those haven't been an issue in practice ...
fn verify_fips_clang_version() -> (&'static str, &'static str) {
    fn version(tool: &str) -> String {
        let output = match Command::new(tool).arg("--version").output() {
            Ok(o) => o,
            Err(e) => {
                eprintln!("warning: missing {}, trying other compilers: {}", tool, e);
                // NOTE: hard-codes that the loop below checks the version
                return String::new();
            }
        };
        assert!(output.status.success());
        let output = str::from_utf8(&output.stdout).expect("invalid utf8 output");
        output.lines().next().expect("empty output").to_string()
    }

    const REQUIRED_CLANG_VERSION: &str = "7.0.1";
    for (cc, cxx) in [
        ("clang-7", "clang++-7"),
        ("clang", "clang++"),
        ("cc", "c++"),
    ] {
        let cc_version = version(cc);
        if cc_version.contains(REQUIRED_CLANG_VERSION) {
            assert!(
                version(cxx).contains(REQUIRED_CLANG_VERSION),
                "mismatched versions of cc and c++"
            );
            return (cc, cxx);
        } else if cc == "cc" {
            panic!(
                "unsupported clang version \"{}\": FIPS requires clang {}",
                cc_version, REQUIRED_CLANG_VERSION
            );
        } else if !cc_version.is_empty() {
            eprintln!(
                "warning: FIPS requires clang version {}, skipping incompatible version \"{}\"",
                REQUIRED_CLANG_VERSION, cc_version
            );
        }
    }
    unreachable!()
}

fn extra_clang_args_for_bindgen() -> Result<Vec<String>> {
    let os = env::var("CARGO_CFG_TARGET_OS")?;

    let mut params = Vec::new();

    // Add platform-specific parameters.
    #[allow(clippy::single_match)]
    match os.as_ref() {
        "ios" => {
            // When cross-compiling for iOS, tell bindgen to use iOS sysroot,
            // and *don't* use system headers of the host macOS.
            let sdk = ios_sdk_name();
            let output = Command::new("xcrun")
                .args(["--show-sdk-path", "--sdk", sdk])
                .output()?;
            if !output.status.success() {
                if let Some(exit_code) = output.status.code() {
                    eprintln!("xcrun failed: exit code {}", exit_code);
                } else {
                    eprintln!("xcrun failed: killed");
                }
                io::stderr().write_all(&output.stderr)?;
                // Uh... let's try anyway, I guess?
                return Ok(params);
            }
            let mut sysroot = String::from_utf8(output.stdout)?;
            // There is typically a newline at the end which confuses clang.
            sysroot.truncate(sysroot.trim_end().len());
            params.push("-isysroot".to_string());
            params.push(sysroot);
        }
        "android" => {
            let android_ndk_home = env::var("ANDROID_NDK_HOME")
                .expect("Please set ANDROID_NDK_HOME for Android build");
            let mut android_sysroot = PathBuf::from(android_ndk_home);
            android_sysroot.push("sysroot");
            params.push("--sysroot".to_string());
            // If ANDROID_NDK_HOME weren't a valid UTF-8 string,
            // we'd already know from env::var.
            params.push(android_sysroot.into_os_string().into_string().unwrap());
        }
        _ => {}
    }

    Ok(params)
}

enum Sources {
    Precompiled(PathBuf),
    Raw(PathBuf),
}

fn find_bssl_sources() -> Result<Sources> {
    // Do we have precompiled sources?
    println!("cargo:rerun-if-env-changed={BSSL_PRECOMPILED_PATH_VAR}");
    if let Ok(dir) = env::var(BSSL_PRECOMPILED_PATH_VAR) {
        let path = Path::new(&dir);
        if path.exists() {
            return Ok(Sources::Precompiled(path.to_owned()));
        }
    }

    // Did the user provide us with a custom path to the raw
    // sources?
    println!("cargo:rerun-if-env-changed={BSSL_SOURCE_PATH_VAR}");
    if let Ok(dir) = env::var(BSSL_SOURCE_PATH_VAR) {
        let path = Path::new(&dir);
        if path.exists() {
            return Ok(Sources::Raw(path.to_owned()));
        }
    }

    // Do we have the git repo locally?
    println!("cargo:rerun-if-env-changed={BSSL_GIT_HASH}");
    let path = Path::new(&env::var("OUT_DIR")?).join(BSSL_DEPS_PATH);
    if !path.join("CMakeLists.txt").exists() {
        println!("cargo:warning=fetching BoringSSL");
        Command::new("git")
            .arg("clone")
            .arg("https://boringssl.googlesource.com/boringssl")
            .arg(&path)
            .status()?
            .exit_ok()?;
    }

    println!("cargo:rerun-if-env-changed={BSSL_GIT_NO_CHECKOUT_VAR}");
    match env::var(BSSL_GIT_NO_CHECKOUT_VAR) {
        Ok(v) if v == "1" => {
            // Make sure we're at the correct commit.
            Command::new("git")
                .arg("reset")
                .arg("--hard")
                .arg("head")
                .current_dir(&path)
                .status()?
                .exit_ok()?;
            let hash = env::var(BSSL_GIT_HASH_VAR).unwrap_or(BSSL_GIT_HASH.to_owned());
            Command::new("git")
                .arg("checkout")
                .arg(hash)
                .current_dir(&path)
                .status()?
                .exit_ok()?;
        }
        _ => {}
    }
    Ok(Sources::Raw(path))
}

fn into_string<P>(path: P) -> String
where
    P: AsRef<Path>,
{
    path.as_ref().to_str().unwrap().to_owned()
}

fn lib_dir<P>(what: &str, dir: P) -> Result<PathBuf>
where
    P: AsRef<Path>,
{
    let mut path = dir.as_ref().join("build").join(what);

    // MSVC generator on Windows place static libs in a target sub-folder,
    // so adjust library location based on platform and build target.
    // See issue: https://github.com/alexcrichton/cmake-rs/issues/18
    if cfg!(target_env = "msvc") {
        // Code under this branch should match the logic in
        // cmake-rs.
        let deb_info = match env::var("DEBUG")?.as_str() {
            "true" => true,
            "false" => false,
            unknown => return Err(format!("unknown DEBUG value: {}", unknown).into()),
        };

        let subdir = match env::var("OPT_LEVEL")?.as_str() {
            "0" => "Debug",
            "1" | "2" | "3" => {
                if deb_info {
                    "RelWithDebInfo"
                } else {
                    "Release"
                }
            }
            "s" | "z" => "MinSizeRel",
            unknown => panic!("Unknown OPT_LEVEL={} env var.", unknown),
        };
        path.push(subdir);
    }

    Ok(path)
}

fn main() -> Result<()> {
    let (src_dir, build_dir) = match find_bssl_sources()? {
        Sources::Precompiled(dir) => (dir.clone(), dir),
        Sources::Raw(dir) => {
            println!("cargo:warning=compiling BoringSSL at {:?}", dir);
            let mut cfg = boringssl_cmake_config(dir.clone())?;
            if cfg!(feature = "fuzzing") {
                cfg.cxxflag("-DBORINGSSL_UNSAFE_DETERMINISTIC_MODE")
                    .cxxflag("-DBORINGSSL_UNSAFE_FUZZER_MODE");
            }
            if cfg!(fips) {
                let (clang, clangxx) = verify_fips_clang_version();
                cfg.define("CMAKE_C_COMPILER", clang);
                cfg.define("CMAKE_CXX_COMPILER", clangxx);
                cfg.define("CMAKE_ASM_COMPILER", clang);
                cfg.define("FIPS", "1");
            }
            match env::var("CARGO_CFG_TARGET_OS")?.as_ref() {
                // See src/lib.rs.
                "aix" | "ios" | "macos" | "tvos" | "windows" => {
                    let patch_path = match env::var(BSSL_MALLOC_PATCH_PATH_VAR) {
                        Ok(path) => path,
                        Err(_) => into_string(Path::new(&env::current_dir()?).join("malloc.patch")),
                    };
                    let res = Command::new("git")
                        .arg("apply")
                        .arg("--reverse")
                        .arg("--check")
                        .arg(&patch_path)
                        .current_dir(dir.clone())
                        .status()?
                        .exit_ok();
                    if res.is_err() {
                        // We couldn't reverse the patch, so
                        // let's assume it hasn't been applied
                        // yet.
                        Command::new("git")
                            .arg("apply")
                            .arg("--ignore-space-change")
                            .arg("--ignore-whitespace")
                            .arg(&patch_path)
                            .current_dir(dir.clone())
                            .status()?
                            .exit_ok()?;
                    }
                }
                _ => {}
            }

            #[cfg(feature = "ssl")]
            cfg.build_target("ssl").build();

            let build_dir = cfg.build_target("crypto").build();
            (dir, build_dir)
        }
    };

    #[cfg(feature = "ssl")]
    println!(
        "cargo:rustc-link-search=native={}",
        lib_dir("ssl", &build_dir)?.as_path().to_str().unwrap()
    );
    println!(
        "cargo:rustc-link-search=native={}",
        lib_dir("crypto", &build_dir)?.as_path().to_str().unwrap()
    );

    #[cfg(feature = "ssl")]
    println!("cargo:rustc-link-lib=static=ssl");

    println!("cargo:rustc-link-lib=static=crypto");

    if env::var("CARGO_CFG_TARGET_OS")? == "macos" {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-undefined,dynamic_lookup");
    }

    println!("cargo:rerun-if-env-changed={BSSL_INCLUDE_PATH_VAR}");
    let include_path = env::var(BSSL_INCLUDE_PATH_VAR)
        .map_or_else(|_| src_dir.join("include"), |v| Path::new(&v).to_owned());

    let mut builder = bindgen::Builder::default()
        .array_pointers_in_arguments(true)
        .clang_args(&["-I", into_string(include_path.clone()).as_str()])
        .clang_args(extra_clang_args_for_bindgen()?)
        .ctypes_prefix("::core::ffi")
        .default_enum_style(EnumVariation::NewType {
            is_bitfield: false,
            is_global: false,
        })
        .default_macro_constant_type(MacroTypeVariation::Signed)
        .derive_copy(true)
        .derive_debug(true)
        .derive_default(true)
        .derive_eq(true)
        .enable_function_attribute_detection()
        .fit_macro_constants(false)
        .formatter(Formatter::Rustfmt)
        .generate_comments(true)
        .layout_tests(true)
        .merge_extern_blocks(true)
        .prepend_enum_name(true)
        .size_t_is_usize(true)
        .time_phases(true)
        .use_core();

    let target = env::var("TARGET")?;
    match target.as_ref() {
        // bindgen produces alignment tests that cause undefined behavior [1]
        // when applied to explicitly unaligned types like OSUnalignedU64.
        //
        // There is no way to disable these tests for only some types
        // and it's not nice to suppress warnings for the entire crate,
        // so let's disable all alignment tests and hope for the best.
        //
        // [1]: https://github.com/rust-lang/rust-bindgen/issues/1651
        "aarch64-apple-ios" | "aarch64-apple-ios-sim" => {
            builder = builder.layout_tests(false);
        }
        _ => {}
    }

    let headers = [
        "aead.h",
        "aes.h",
        "arm_arch.h",
        "asn1.h",
        "asn1_mac.h",
        "asn1t.h",
        "base.h",
        "base64.h",
        "bio.h",
        #[cfg(not(fips))]
        "blake2.h",
        "blowfish.h",
        "bn.h",
        "buf.h",
        "buffer.h",
        "bytestring.h",
        "cast.h",
        "chacha.h",
        "cipher.h",
        "cmac.h",
        "conf.h",
        "cpu.h",
        "crypto.h",
        "ctrdrbg.h",
        "curve25519.h",
        "des.h",
        "dh.h",
        "digest.h",
        "dsa.h",
        "dtls1.h",
        "e_os2.h",
        "ec.h",
        "ec_key.h",
        "ecdh.h",
        "ecdsa.h",
        "engine.h",
        "err.h",
        "evp.h",
        "evp_errors.h",
        "ex_data.h",
        "hkdf.h",
        "hmac.h",
        "hpke.h",
        "hrss.h",
        "is_boringssl.h",
        "kdf.h",
        "kyber.h",
        "lhash.h",
        "md4.h",
        "md5.h",
        "mem.h",
        "nid.h",
        "obj.h",
        "obj_mac.h",
        "objects.h",
        "opensslconf.h",
        "opensslv.h",
        "ossl_typ.h",
        "pem.h",
        "pkcs12.h",
        "pkcs7.h",
        "pkcs8.h",
        "poly1305.h",
        "pool.h",
        "rand.h",
        "rc4.h",
        "ripemd.h",
        "rsa.h",
        "safestack.h",
        "service_indicator.h",
        "sha.h",
        "siphash.h",
        "span.h",
        "srtp.h",
        "ssl.h",
        "ssl3.h",
        "stack.h",
        "thread.h",
        "time.h",
        "tls1.h",
        #[cfg(not(fips))]
        "trust_token.h",
        "type_check.h",
        "x509.h",
        "x509_vfy.h",
        "x509v3.h",
    ];
    for header in &headers {
        builder = builder.header(include_path.join("openssl").join(header).to_str().unwrap());
    }

    let bindings = builder.generate().expect("unable to generate bindings");
    let out_path = PathBuf::from(env::var("OUT_DIR")?);
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("unable to write bindings");
    Ok(())
}
