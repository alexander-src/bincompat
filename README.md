# bincompat

Static ELF64 scanner in zero-dependency safe Rust (`#![forbid(unsafe_code)]`) that checks Linux `GLIBC`/`GLIBCXX` symbol version floors, linker ABI tags, binary hardening flags (`PIE`, `RELRO`, `NX`, stack canaries), and binary-to-binary regressions.

![demo](assets/demo.png)

## Why

A binary built on a newer Linux distro can fail to start on older LTS servers because one call pulled in `arc4random@GLIBC_2.36` or the linker emitted `GLIBC_ABI_DT_RELR` (`-z pack-relative-relocs`). Release builds can also silently drop `-fPIE`, `-z now`, or `-fstack-protector-strong` across toolchain updates.

`bincompat` parses `PT_INTERP`, `PT_GNU_RELRO`, `PT_GNU_STACK`, `SHT_DYNAMIC`, `SHT_DYNSYM`, `SHT_SYMTAB`, `SHT_GNU_VERSYM` (masking the `0x8000` hidden bit), and `SHT_GNU_VERNEED` directly, then exits non-zero in CI with the exact library, version tag, offending symbols, or missing hardening flag.

## Usage

Build from source (`cargo build --release`, ~5s offline, ~550 KB stripped) or download a prebuilt binary from [Releases](https://github.com/alexander-src/bincompat/releases):

```bash
# Inspect DT_NEEDED, RPATH/RUNPATH, hardening flags, symbol versions, ABI tags, and distro compatibility
bincompat scan /usr/bin/env

# Gate a release binary against a distro preset and standard hardening
bincompat check ./build/app --target rhel-8 --forbid-rpath --require-hardening

# Or specify explicit version ceilings and individual hardening rules
bincompat check ./build/app \
  --max-glibc 2.28 \
  --max-glibcxx 3.4.28 \
  --forbid-abi-tag GLIBC_ABI_DT_RELR \
  --require-pie \
  --require-relro full

# Fail CI if a new build adds DT_NEEDED entries, raises symbol version floors, adds RPATH/ABI tags, or drops hardening
bincompat diff ./releases/v1/app ./build/app

# Write SARIF directly to a file for GitHub Code Scanning uploads
bincompat check ./build/app --target rhel-8 --format sarif -o bincompat.sarif

# List built-in Linux distro baselines (text, json, or markdown)
bincompat targets
```

All report commands accept `--format text|json|markdown|sarif` and `-o` / `--out <FILE>` (SARIF 2.1.0 emits rules `BC001`..`BC007` for `check` and `BC101`..`BC105` for `diff`).

Built-in `--target` presets: `centos-7` (`manylinux2014`, `rhel-7`), `rhel-8` (`rocky-8`, `manylinux_2_28`), `ubuntu-20.04`, `debian-11`, `rhel-9`, `ubuntu-22.04`, `debian-12`, `ubuntu-24.04`, `rhel-10` (`rocky-10`), and `debian-13`.

Exit codes: `0` pass, `1` policy violation or diff regression, `2` usage, I/O, or malformed ELF error.

## Limitations

- ELF64 only (no ELF32, PE, or Mach-O).
- Static metadata scan only: does not catch symbols resolved at runtime via `dlopen`/`dlsym`.
- Built-in distro presets check `GLIBC`, `GLIBCXX`, and `GLIBC_ABI_DT_RELR` baselines; non-glibc third-party library sonames should be checked with `--max-version` or `diff`.

## License

MIT. See [LICENSE](LICENSE).
