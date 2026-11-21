# bincompat

Static ELF64 scanner in zero-dependency safe Rust that maps Linux `GLIBC`/`GLIBCXX` version requirements and linker ABI tags back to the exact undefined symbols causing them.

![demo](assets/demo.png)

## Why

Ship a binary compiled on a newer Linux distro and it can fail to start on older LTS servers because one call pulled in `arc4random@GLIBC_2.36` or the linker emitted `GLIBC_ABI_DT_RELR` (`-z pack-relative-relocs`).

`bincompat` reads `PT_INTERP`, `SHT_DYNAMIC`, `SHT_DYNSYM`, `SHT_GNU_VERSYM` (masking the `0x8000` hidden bit), and `SHT_GNU_VERNEED` directly, then fails CI with the exact library, version tag, and offending symbols.

## Usage

Build from source (`cargo build --release`, ~1s offline, 400 KB stripped):

```bash
# Inspect DT_NEEDED, RPATH/RUNPATH, max symbol versions, and ABI tags
bincompat scan /usr/bin/env

# Fail CI if any symbol exceeds GLIBC 2.28 / GLIBCXX 3.4.28 or pulls in DT_RELR
bincompat check ./build/app \
  --max-glibc 2.28 \
  --max-glibcxx 3.4.28 \
  --forbid-abi-tag GLIBC_ABI_DT_RELR \
  --forbid-rpath
```

Exit codes: `0` pass, `1` policy violation, `2` I/O or malformed ELF error.

## Limitations

- ELF64 only (no ELF32, PE, or Mach-O).
- Static metadata scan only: does not catch symbols resolved dynamically via `dlopen`/`dlsym`.
- Currently covers symbol versions, ABI tags, and dynamic paths (`DT_NEEDED`, `SONAME`, `RPATH`, `RUNPATH`). Binary hardening checks (`PIE`/`NX`/`RELRO`/stack canaries), distro tables, and `diff` mode are next.

## License

MIT. See [LICENSE](LICENSE).
