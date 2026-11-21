# bincompat Specification

## 1. Problem Statement

Shipping prebuilt Linux binaries (Rust, C, C++, Go with cgo) frequently fails at runtime on older enterprise or LTS distributions with errors like:

```text
./app: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.38' not found (required by ./app)
```

Standard tooling (`ldd`, `readelf -V`, `objdump -T`) either requires running on the target host or dumps raw tables without mapping version indices back to the exact offending undefined symbols, ABI feature tags (such as `GLIBC_ABI_DT_RELR` from `-z pack-relative-relocs`), or CI exit codes.

`bincompat` is a zero-dependency, `#![forbid(unsafe_code)]` Rust CLI and library that statically parses ELF64 binaries and verifies symbol-version ceilings and linker portability policies in CI.

## 2. Hard Invariants

1. **Zero external runtime or build crates:** `[dependencies]` in `Cargo.toml` stays empty so builds remain fast, auditable, and offline-capable.
2. **100% safe Rust:** `#![forbid(unsafe_code)]` across library and binary targets.
3. **Total bounds and cycle safety:** Every ELF offset, count, string table lookup, `Elf64_Verneed.vn_next`, and `Elf64_Vernaux.vna_next` traversal uses checked arithmetic and cycle guards. Truncated or malicious inputs must return a structured error and never panic or loop indefinitely.
4. **Deterministic output:** All tables, version groups, and offending symbol lists are sorted deterministically across runs and platforms.
5. **Semantic exit codes:**
   - `0`: Scan succeeded or policy check passed.
   - `1`: Policy check failed (version ceiling exceeded, forbidden ABI tag, or forbidden `RPATH`/`RUNPATH`).
   - `2`: Usage error, I/O error, or invalid/unsupported ELF input.

## 3. ELF64 Coverage (Milestone 1)

- **Header and program headers:** ELF64 little-endian and big-endian (`ET_EXEC`, `ET_DYN`), architecture (`e_machine`), dynamic interpreter (`PT_INTERP`).
- **Dynamic metadata (`SHT_DYNAMIC`):** `DT_NEEDED`, `DT_SONAME`, `DT_RPATH`, `DT_RUNPATH`, `DT_FLAGS`, `DT_FLAGS_1`.
- **GNU Symbol Versioning:**
  - `SHT_DYNSYM` + linked `SHT_STRTAB` (`.dynstr`).
  - `SHT_GNU_VERSYM` (`0x6fffffff`): 16-bit symbol version indices with hidden-version bit (`0x8000`) masked cleanly.
  - `SHT_GNU_VERNEED` (`0x6ffffffe`): `Elf64_Verneed` + `Elf64_Vernaux` records mapped by `vna_other & 0x7fff` to `(library, version_tag)`.
  - Preserves zero-symbol ABI feature tags (such as `GLIBC_ABI_DT_RELR` and `GLIBC_PRIVATE`) alongside numeric versioned tags (`GLIBC_2.38`, `GLIBCXX_3.4.30`, `CXXABI_1.3.13`, `GCC_3.3`).
- **Exact symbol attribution:** Attributes every undefined dynamic symbol (`st_shndx == SHN_UNDEF`) referencing a `VERNEED` version index to `(symbol, library, version_tag)`.

## 4. CLI Contract (Milestone 1)

```text
bincompat scan <path>
bincompat check <path> [options]
```

Supported `check` options in Milestone 1:
- `--max-glibc <VER>`: Maximum permitted numeric `GLIBC` version (for example `2.28`).
- `--max-glibcxx <VER>`: Maximum permitted numeric `GLIBCXX` version (for example `3.4.28`).
- `--max-version <PREFIX=VER>`: Maximum permitted version for any symbol-version family (repeatable, for example `--max-version CXXABI=1.3.11`).
- `--forbid-abi-tag <TAG>`: Fail if a specific non-numeric ABI tag appears in `.gnu.version_r` (repeatable, for example `--forbid-abi-tag GLIBC_ABI_DT_RELR`).
- `--forbid-rpath`: Fail if `DT_RPATH` or `DT_RUNPATH` is present.

## 5. Planned Milestones

- **Milestone 2:** ELF security hardening audit (`PIE`, `NX`/`PT_GNU_STACK`, `RELRO`/`BIND_NOW`, stack canary, `FORTIFY_SOURCE`).
- **Milestone 3:** Built-in Linux distribution compatibility matrix (Ubuntu LTS, Debian Stable/Oldstable, RHEL/Alma/Rocky 8/9, Alpine musl) and `--target <distro>` shortcuts.
- **Milestone 4:** `bincompat diff <before> <after> --fail-on-regression`, plus `--format json|sarif|markdown` for CI PR comments and GitHub Code Scanning.
