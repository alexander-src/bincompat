# bincompat

Zero-dependency, `#![forbid(unsafe_code)]` Rust CLI and library that statically audits Linux ELF64 binaries for `GLIBC`/`GLIBCXX` symbol-version requirements, ABI feature tags (such as `GLIBC_ABI_DT_RELR`), and `DT_NEEDED`/`RPATH` portability constraints in CI.

## Why bincompat?

When a binary built on a newer Linux distribution accidentally pulls in a single newer symbol (such as `arc4random@GLIBC_2.36` or `std::__glibcxx_assert_fail@GLIBCXX_3.4.30`) or links with `-z pack-relative-relocs` (`GLIBC_ABI_DT_RELR`), it silently fails to start on older enterprise or LTS targets.

`bincompat` parses ELF64 dynamic tables (`SHT_DYNAMIC`, `SHT_DYNSYM`, `SHT_GNU_VERSYM`, `SHT_GNU_VERNEED`) directly in pure safe Rust and pinpoints the **exact undefined symbols** and **ABI feature tags** responsible for raising your minimum required runtime version.

## Current Capabilities (Milestone 1)

- **Zero external crates:** builds offline in ~1 second; 100% safe Rust (`#![forbid(unsafe_code)]`).
- **Exact symbol attribution:** joins `.dynsym`, `.gnu.version` (masking the `0x8000` hidden bit), and `.gnu.version_r` to map every offending undefined symbol to its shared library and version tag.
- **ABI tag awareness:** detects zero-symbol linker ABI tags such as `GLIBC_ABI_DT_RELR` and `GLIBC_PRIVATE` instead of silently dropping them.
- **Dynamic dependency inspection:** reports `PT_INTERP`, `DT_NEEDED`, `DT_SONAME`, `DT_RPATH`, and `DT_RUNPATH`.
- **CI policy gating:** semantic exit codes (`0` pass, `1` policy violation, `2` error) with `--max-glibc`, `--max-glibcxx`, `--max-version PREFIX=VER`, `--forbid-abi-tag`, and `--forbid-rpath`.
- **Verified against GNU `readelf`:** integration tests cross-check `bincompat` against live Linux system binaries and freshly compiled `g++` binaries alongside byte-by-byte ELF truncation fuzzing.

## Quick Start

```bash
cargo build --release

# Inspect ELF64 dynamic dependencies, max GLIBC/GLIBCXX versions, and ABI tags
./target/release/bincompat scan /usr/bin/env

# Fail CI if any symbol requires GLIBC > 2.28 or if GLIBC_ABI_DT_RELR is present
./target/release/bincompat check ./build/app \
  --max-glibc 2.28 \
  --max-glibcxx 3.4.28 \
  --forbid-abi-tag GLIBC_ABI_DT_RELR \
  --forbid-rpath
```

## Documentation

- [Specification](docs/SPEC.md)
- [Architecture](docs/ARCHITECTURE.md)
- [License (MIT)](LICENSE)
