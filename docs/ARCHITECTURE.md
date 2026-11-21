# bincompat Architecture

## Module Layout

```text
src/
  error.rs    Structured error taxonomy (I/O, ELF validation, CLI usage)
  version.rs  Dotted numeric version parsing, family extraction, and Ord comparison
  elf.rs      Zero-dependency bounds-checked ELF64 dynamic and GNU version parser
  policy.rs   Version ceiling, ABI tag, and RPATH/RUNPATH policy evaluator
  report.rs   Deterministic archival terminal formatter for scan and check reports
  lib.rs      Public library API re-exports
  main.rs     Minimal zero-dependency CLI argument parser and exit-code driver
```

## Parsing Pipeline

```text
raw bytes (&[u8])
  -> ElfHeader (ident, endianness, ET_EXEC/ET_DYN, e_machine, phdr/shdr bounds)
  -> Program Headers (PT_INTERP dynamic loader path)
  -> Section Headers (SHT_DYNAMIC, SHT_DYNSYM, SHT_GNU_VERSYM, SHT_GNU_VERNEED)
  -> Dynamic Table (DT_NEEDED, DT_SONAME, DT_RPATH, DT_RUNPATH, DT_FLAGS/1)
  -> Verneed Table (vna_other & 0x7fff -> (library, raw_tag, parsed_family_version))
  -> Dynsym + Versym Join (SHN_UNDEF symbols joined to exact Verneed requirements)
  -> BinaryReport (sorted libraries, sorted version requirements, max per family, ABI tags)
```

## Safety and Verification Strategy

1. **Endian-aware checked readers:** All integer reads slice explicitly with `get(off..end)` and convert via `from_le_bytes` / `from_be_bytes`. No raw pointer casts or `transmute`.
2. **Bounded linked-list traversal:** `Elf64_Verneed` and `Elf64_Vernaux` store relative byte offsets (`vn_next`, `vna_next`). A malformed binary can encode `vn_next == 0` prematurely, point backwards to form a cycle, or overflow section bounds. The parser tracks visited byte offsets and caps iterations by the section byte length, guaranteeing $O(N)$ termination.
3. **Ground-truth testing:**
   - Pure-Rust synthetic ELF64 fixture generator in `tests/synthetic_elf.rs` verifies exact attribution, `0x8000` hidden-version masking, `GLIBC_ABI_DT_RELR` zero-symbol preservation, cyclic `vn_next` rejection, and byte-by-byte truncation fuzzing.
   - Live Linux ground-truth tests in `tests/readelf_ground_truth.rs` compare `bincompat` directly against GNU `readelf -d -V --dyn-syms` on system binaries and a freshly compiled `g++` binary.
