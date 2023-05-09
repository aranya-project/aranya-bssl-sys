# bssl

BoringSSL bindings for the Rust programming language.

## Configuration

By default, it builds a particular git revision. The revision can
be changed by setting `BSSL_GIT_HASH`.

Other options include:

- `BSSL_PRECOMPILED_PATH`: the directory where pre-built
  libraries can be found.
- `BSSL_SOURCE_PATH`: the directory where BoringSSL source file
  can be found.
- `BSSL_INCLUDE_PATH`: the directory where BoringSSL header files
  can be found. (Note: make sure this stays up-to-date with the
  source files!)

Note that `BSSL_GIT_HASH`, `BSSL_PRECOMPILED_PATH`, and
`BSSL_SOURCE_PATH` are mutually exclusive.

## FIPS

Set `RUSTFLAGS="--config fips"`.
