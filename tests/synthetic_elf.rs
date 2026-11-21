use std::fs;
use std::process::Command;

use bincompat::{
    analyze_bytes, analyze_file, BincompatError, Endianness, Policy, Version, VersionTag, Violation,
};

struct StrTab {
    bytes: Vec<u8>,
}

impl StrTab {
    fn new() -> Self {
        Self { bytes: vec![0] }
    }

    fn push(&mut self, s: &str) -> u32 {
        let off = u32::try_from(self.bytes.len()).unwrap();
        self.bytes.extend_from_slice(s.as_bytes());
        self.bytes.push(0);
        off
    }
}

fn put_u16(buf: &mut Vec<u8>, v: u16, le: bool) {
    buf.extend_from_slice(&if le { v.to_le_bytes() } else { v.to_be_bytes() });
}

fn put_u32(buf: &mut Vec<u8>, v: u32, le: bool) {
    buf.extend_from_slice(&if le { v.to_le_bytes() } else { v.to_be_bytes() });
}

fn put_u64(buf: &mut Vec<u8>, v: u64, le: bool) {
    buf.extend_from_slice(&if le { v.to_le_bytes() } else { v.to_be_bytes() });
}

fn put_i64(buf: &mut Vec<u8>, v: i64, le: bool) {
    buf.extend_from_slice(&if le { v.to_le_bytes() } else { v.to_be_bytes() });
}

fn push_shdr(
    buf: &mut Vec<u8>,
    le: bool,
    sh_type: u32,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_entsize: u64,
) {
    put_u32(buf, 0, le); // sh_name
    put_u32(buf, sh_type, le);
    put_u64(buf, 0, le); // sh_flags
    put_u64(buf, 0, le); // sh_addr
    put_u64(buf, sh_offset, le);
    put_u64(buf, sh_size, le);
    put_u32(buf, sh_link, le);
    put_u32(buf, 0, le); // sh_info
    put_u64(buf, 8, le); // sh_addralign
    put_u64(buf, sh_entsize, le);
}

/// Builds a valid minimal ELF64 binary with PT_INTERP, .dynstr, .dynamic,
/// .dynsym, .gnu.version, and .gnu.version_r in either endianness.
fn build_synthetic_dynamic_elf(le: bool) -> Vec<u8> {
    let mut dynstr = StrTab::new();
    let s_libc = dynstr.push("libc.so.6");
    let s_libstdcxx = dynstr.push("libstdc++.so.6");
    let s_soname = dynstr.push("libdemo.so.1");
    let s_runpath = dynstr.push("$ORIGIN/../lib");
    let s_glibc_238 = dynstr.push("GLIBC_2.38");
    let s_glibc_225 = dynstr.push("GLIBC_2.2.5");
    let s_glibc_relr = dynstr.push("GLIBC_ABI_DT_RELR");
    let s_glibcxx_3430 = dynstr.push("GLIBCXX_3.4.30");
    let s_sym_strtol = dynstr.push("__isoc23_strtol");
    let s_sym_puts = dynstr.push("puts");
    let s_sym_weak = dynstr.push("__cxa_finalize");
    let s_sym_assert = dynstr.push("_ZSt21__glibcxx_assert_failPKciS0_S0_");
    let s_sym_defined = dynstr.push("local_export");

    // .dynamic (SHT_DYNAMIC = 6)
    let mut dynamic = Vec::new();
    put_i64(&mut dynamic, 1, le); // DT_NEEDED
    put_u64(&mut dynamic, u64::from(s_libc), le);
    put_i64(&mut dynamic, 1, le); // DT_NEEDED
    put_u64(&mut dynamic, u64::from(s_libstdcxx), le);
    put_i64(&mut dynamic, 14, le); // DT_SONAME
    put_u64(&mut dynamic, u64::from(s_soname), le);
    put_i64(&mut dynamic, 29, le); // DT_RUNPATH
    put_u64(&mut dynamic, u64::from(s_runpath), le);
    put_i64(&mut dynamic, 0, le); // DT_NULL
    put_u64(&mut dynamic, 0, le);

    // .dynsym (SHT_DYNSYM = 11): 6 symbols (index 0 = null)
    let mut dynsym = Vec::new();
    let push_sym = |buf: &mut Vec<u8>, name: u32, info: u8, shndx: u16| {
        put_u32(buf, name, le);
        buf.push(info);
        buf.push(0); // st_other
        put_u16(buf, shndx, le);
        put_u64(buf, 0, le); // st_value
        put_u64(buf, 0, le); // st_size
    };
    push_sym(&mut dynsym, 0, 0, 0); // 0: null
    push_sym(&mut dynsym, s_sym_strtol, (1 << 4) | 2, 0); // 1: GLOBAL FUNC UND -> GLIBC_2.38 (idx 2, hidden bit set)
    push_sym(&mut dynsym, s_sym_puts, (1 << 4) | 2, 0); // 2: GLOBAL FUNC UND -> GLIBC_2.2.5 (idx 3)
    push_sym(&mut dynsym, s_sym_weak, (2 << 4) | 2, 0); // 3: WEAK FUNC UND -> GLIBC_2.2.5 (idx 3)
    push_sym(&mut dynsym, s_sym_assert, (1 << 4) | 2, 0); // 4: GLOBAL FUNC UND -> GLIBCXX_3.4.30 (idx 5)
    push_sym(&mut dynsym, s_sym_defined, (1 << 4) | 2, 1); // 5: defined symbol (must be ignored)

    // .gnu.version (SHT_GNU_VERSYM = 0x6fffffff)
    let mut versym = Vec::new();
    put_u16(&mut versym, 0, le); // null
    put_u16(&mut versym, 2 | 0x8000, le); // GLIBC_2.38 with hidden bit 0x8000
    put_u16(&mut versym, 3, le); // GLIBC_2.2.5
    put_u16(&mut versym, 3, le); // GLIBC_2.2.5 (weak)
    put_u16(&mut versym, 5, le); // GLIBCXX_3.4.30
    put_u16(&mut versym, 1, le); // *global* defined

    // .gnu.version_r (SHT_GNU_VERNEED = 0x6ffffffe)
    // Entry 0 (offset 0): libc.so.6 with 3 vernaux (offsets 16, 32, 48), vn_next = 64
    // Entry 1 (offset 64): libstdc++.so.6 with 1 vernaux (offset 80), vn_next = 0
    let mut verneed = Vec::new();
    // Verneed 0 (libc.so.6)
    put_u16(&mut verneed, 1, le); // vn_version
    put_u16(&mut verneed, 3, le); // vn_cnt
    put_u32(&mut verneed, s_libc, le); // vn_file
    put_u32(&mut verneed, 16, le); // vn_aux
    put_u32(&mut verneed, 64, le); // vn_next -> offset 64
                                   // Vernaux 0: GLIBC_2.38 (idx 2)
    put_u32(&mut verneed, 0, le);
    put_u16(&mut verneed, 0, le);
    put_u16(&mut verneed, 2, le);
    put_u32(&mut verneed, s_glibc_238, le);
    put_u32(&mut verneed, 16, le);
    // Vernaux 1: GLIBC_2.2.5 (idx 3)
    put_u32(&mut verneed, 0, le);
    put_u16(&mut verneed, 0, le);
    put_u16(&mut verneed, 3, le);
    put_u32(&mut verneed, s_glibc_225, le);
    put_u32(&mut verneed, 16, le);
    // Vernaux 2: GLIBC_ABI_DT_RELR (idx 4, zero referencing symbols)
    put_u32(&mut verneed, 0, le);
    put_u16(&mut verneed, 0, le);
    put_u16(&mut verneed, 4, le);
    put_u32(&mut verneed, s_glibc_relr, le);
    put_u32(&mut verneed, 0, le);
    // Verneed 1 (libstdc++.so.6)
    put_u16(&mut verneed, 1, le);
    put_u16(&mut verneed, 1, le);
    put_u32(&mut verneed, s_libstdcxx, le);
    put_u32(&mut verneed, 16, le);
    put_u32(&mut verneed, 0, le);
    // Vernaux 0: GLIBCXX_3.4.30 (idx 5)
    put_u32(&mut verneed, 0, le);
    put_u16(&mut verneed, 0, le);
    put_u16(&mut verneed, 5, le);
    put_u32(&mut verneed, s_glibcxx_3430, le);
    put_u32(&mut verneed, 0, le);

    let interp_bytes = b"/lib64/ld-linux-x86-64.so.2\0";

    // Layout:
    //   0..64:   Elf64_Ehdr
    //   64..120: 1 x Elf64_Phdr (PT_INTERP)
    //   120..:   interp, dynstr, dynamic, dynsym, versym, verneed
    //   end:     6 x Elf64_Shdr (null, .dynstr, .dynamic, .dynsym, .gnu.version, .gnu.version_r)
    let mut elf = vec![0u8; 64 + 56];
    let interp_off = elf.len() as u64;
    elf.extend_from_slice(interp_bytes);
    while elf.len() % 8 != 0 {
        elf.push(0);
    }

    let dynstr_off = elf.len() as u64;
    elf.extend_from_slice(&dynstr.bytes);
    while elf.len() % 8 != 0 {
        elf.push(0);
    }

    let dynamic_off = elf.len() as u64;
    elf.extend_from_slice(&dynamic);

    let dynsym_off = elf.len() as u64;
    elf.extend_from_slice(&dynsym);

    let versym_off = elf.len() as u64;
    elf.extend_from_slice(&versym);
    while elf.len() % 8 != 0 {
        elf.push(0);
    }

    let verneed_off = elf.len() as u64;
    elf.extend_from_slice(&verneed);

    let shoff = elf.len() as u64;
    // Section 0: NULL
    push_shdr(&mut elf, le, 0, 0, 0, 0, 0);
    // Section 1: .dynstr (SHT_STRTAB = 3)
    push_shdr(&mut elf, le, 3, dynstr_off, dynstr.bytes.len() as u64, 0, 0);
    // Section 2: .dynamic (SHT_DYNAMIC = 6, sh_link = 1)
    push_shdr(&mut elf, le, 6, dynamic_off, dynamic.len() as u64, 1, 16);
    // Section 3: .dynsym (SHT_DYNSYM = 11, sh_link = 1)
    push_shdr(&mut elf, le, 11, dynsym_off, dynsym.len() as u64, 1, 24);
    // Section 4: .gnu.version (SHT_GNU_VERSYM = 0x6fffffff, sh_link = 3)
    push_shdr(
        &mut elf,
        le,
        0x6fff_ffff,
        versym_off,
        versym.len() as u64,
        3,
        2,
    );
    // Section 5: .gnu.version_r (SHT_GNU_VERNEED = 0x6ffffffe, sh_link = 1)
    push_shdr(
        &mut elf,
        le,
        0x6fff_fffe,
        verneed_off,
        verneed.len() as u64,
        1,
        0,
    );

    // Patch ELF64 header
    let mut ehdr = Vec::with_capacity(64);
    ehdr.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, if le { 1 } else { 2 }, 1, 0]);
    ehdr.extend_from_slice(&[0u8; 8]);
    put_u16(&mut ehdr, 3, le); // ET_DYN
    put_u16(&mut ehdr, if le { 62 } else { 22 }, le); // x86-64 or s390x
    put_u32(&mut ehdr, 1, le); // EV_CURRENT
    put_u64(&mut ehdr, 0, le); // e_entry
    put_u64(&mut ehdr, 64, le); // e_phoff
    put_u64(&mut ehdr, shoff, le); // e_shoff
    put_u32(&mut ehdr, 0, le); // e_flags
    put_u16(&mut ehdr, 64, le); // e_ehsize
    put_u16(&mut ehdr, 56, le); // e_phentsize
    put_u16(&mut ehdr, 1, le); // e_phnum
    put_u16(&mut ehdr, 64, le); // e_shentsize
    put_u16(&mut ehdr, 6, le); // e_shnum
    put_u16(&mut ehdr, 0, le); // e_shstrndx
    elf[0..64].copy_from_slice(&ehdr);

    // Patch Program Header (PT_INTERP = 3)
    let mut phdr = Vec::with_capacity(56);
    put_u32(&mut phdr, 3, le); // PT_INTERP
    put_u32(&mut phdr, 4, le); // PF_R
    put_u64(&mut phdr, interp_off, le);
    put_u64(&mut phdr, 0, le);
    put_u64(&mut phdr, 0, le);
    put_u64(&mut phdr, interp_bytes.len() as u64, le);
    put_u64(&mut phdr, interp_bytes.len() as u64, le);
    put_u64(&mut phdr, 1, le);
    elf[64..120].copy_from_slice(&phdr);

    elf
}

#[test]
fn parses_synthetic_le_and_be_elf_with_exact_attribution() {
    for (le, expected_endian, expected_machine) in [
        (true, Endianness::Little, "x86-64"),
        (false, Endianness::Big, "s390x"),
    ] {
        let elf = build_synthetic_dynamic_elf(le);
        let report = analyze_bytes(&elf).expect("valid synthetic ELF64 should parse");

        assert_eq!(report.elf_type, "ET_DYN");
        assert_eq!(report.machine, expected_machine);
        assert_eq!(report.endianness, expected_endian);
        assert!(report.is_dynamic);
        assert_eq!(
            report.interpreter.as_deref(),
            Some("/lib64/ld-linux-x86-64.so.2")
        );
        assert_eq!(report.soname.as_deref(), Some("libdemo.so.1"));
        assert_eq!(report.runpath.as_deref(), Some("$ORIGIN/../lib"));
        assert_eq!(report.needed, vec!["libc.so.6", "libstdc++.so.6"]);
        assert_eq!(
            report.max_versions.get("GLIBC"),
            Some(&Version::parse("2.38").unwrap())
        );
        assert_eq!(
            report.max_versions.get("GLIBCXX"),
            Some(&Version::parse("3.4.30").unwrap())
        );
        assert_eq!(report.abi_tags.len(), 1);
        assert_eq!(report.abi_tags[0].tag, "GLIBC_ABI_DT_RELR");
        assert_eq!(report.abi_tags[0].symbol_count, 0);

        let req_238 = report
            .requirements
            .iter()
            .find(|r| r.raw_tag == "GLIBC_2.38")
            .unwrap();
        assert_eq!(req_238.symbols.len(), 1);
        assert_eq!(req_238.symbols[0].name, "__isoc23_strtol");
        assert!(req_238.symbols[0].is_hidden);
        assert!(!req_238.symbols[0].is_weak);

        let req_225 = report
            .requirements
            .iter()
            .find(|r| r.raw_tag == "GLIBC_2.2.5")
            .unwrap();
        assert_eq!(req_225.symbols.len(), 2);
        assert!(req_225
            .symbols
            .iter()
            .any(|s| s.name == "__cxa_finalize" && s.is_weak));
        assert!(req_225
            .symbols
            .iter()
            .any(|s| s.name == "puts" && !s.is_weak));

        let req_cxx = report
            .requirements
            .iter()
            .find(|r| r.raw_tag == "GLIBCXX_3.4.30")
            .unwrap();
        assert_eq!(
            req_cxx.parsed,
            VersionTag::Versioned {
                family: "GLIBCXX".to_string(),
                version: Version::parse("3.4.30").unwrap(),
            }
        );
        assert_eq!(req_cxx.symbols.len(), 1);
        assert_eq!(
            req_cxx.symbols[0].name,
            "_ZSt21__glibcxx_assert_failPKciS0_S0_"
        );
    }
}

#[test]
fn policy_enforces_version_ceilings_abi_tags_and_rpath() {
    let elf = build_synthetic_dynamic_elf(true);
    let analysis = analyze_bytes(&elf).unwrap();

    let mut strict = Policy::default();
    strict.set_max_version("GLIBC", Version::parse("2.34").unwrap());
    strict.set_max_version("GLIBCXX", Version::parse("3.4.28").unwrap());
    strict
        .forbid_abi_tags
        .insert("GLIBC_ABI_DT_RELR".to_string());
    strict.forbid_rpath = true;

    let eval = strict.evaluate(&analysis);
    assert!(!eval.passed);
    assert_eq!(eval.violations.len(), 4);
    assert!(eval.violations.iter().any(|v| matches!(
        v,
        Violation::VersionExceeded { raw_tag, .. } if raw_tag == "GLIBC_2.38"
    )));
    assert!(eval.violations.iter().any(|v| matches!(
        v,
        Violation::VersionExceeded { raw_tag, .. } if raw_tag == "GLIBCXX_3.4.30"
    )));
    assert!(eval.violations.iter().any(|v| matches!(
        v,
        Violation::ForbiddenAbiTag { tag, .. } if tag == "GLIBC_ABI_DT_RELR"
    )));
    assert!(eval.violations.iter().any(|v| matches!(
        v,
        Violation::ForbiddenRpath { kind, .. } if kind == "DT_RUNPATH"
    )));

    let mut permissive = Policy::default();
    permissive.set_max_version("GLIBC", Version::parse("2.38").unwrap());
    permissive.set_max_version("GLIBCXX", Version::parse("3.4.30").unwrap());
    assert!(permissive.evaluate(&analysis).passed);
}

#[test]
fn handles_static_elf_without_dynamic_or_verneed_sections() {
    let mut ehdr = Vec::with_capacity(64);
    ehdr.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
    ehdr.extend_from_slice(&[0u8; 8]);
    put_u16(&mut ehdr, 2, true); // ET_EXEC
    put_u16(&mut ehdr, 62, true); // x86-64
    put_u32(&mut ehdr, 1, true);
    put_u64(&mut ehdr, 0, true);
    put_u64(&mut ehdr, 0, true);
    put_u64(&mut ehdr, 0, true);
    put_u32(&mut ehdr, 0, true);
    put_u16(&mut ehdr, 64, true);
    put_u16(&mut ehdr, 56, true);
    put_u16(&mut ehdr, 0, true);
    put_u16(&mut ehdr, 64, true);
    put_u16(&mut ehdr, 0, true);
    put_u16(&mut ehdr, 0, true);

    let report = analyze_bytes(&ehdr).unwrap();
    assert_eq!(report.elf_type, "ET_EXEC");
    assert!(!report.is_dynamic);
    assert!(report.needed.is_empty());
    assert!(report.requirements.is_empty());
}

#[test]
fn rejects_cyclic_verneed_chain_without_hanging() {
    let mut elf = build_synthetic_dynamic_elf(true);
    // Locate the first verneed section offset by reading section header 5 (last 64 bytes)
    let shdr5_base = elf.len() - 64;
    let verneed_off =
        u64::from_le_bytes(elf[shdr5_base + 24..shdr5_base + 32].try_into().unwrap()) as usize;
    // Set second Elf64_Verneed.vn_next (at verneed_off + 64 + 12) to point backward by -64 (wrapping u32)
    let back_step = (-64i32) as u32;
    elf[verneed_off + 64 + 12..verneed_off + 64 + 16].copy_from_slice(&back_step.to_le_bytes());

    let err = analyze_bytes(&elf).expect_err("cyclic verneed must fail");
    assert!(
        matches!(err, BincompatError::CorruptVerneed(_)),
        "expected CorruptVerneed, got {err:?}"
    );
}

#[test]
fn byte_by_byte_truncation_never_panics() {
    let elf = build_synthetic_dynamic_elf(true);
    for len in 0..elf.len() {
        let res = analyze_bytes(&elf[..len]);
        assert!(
            res.is_err(),
            "truncated synthetic ELF at length {len}/{} must return Err",
            elf.len()
        );
    }
}

#[test]
fn cli_exit_codes_and_output_on_synthetic_file() {
    let elf = build_synthetic_dynamic_elf(true);
    let mut path = std::env::temp_dir();
    path.push(format!("bincompat_cli_test_{}.elf", std::process::id()));
    fs::write(&path, &elf).unwrap();

    // Library analyze_file smoke check
    let parsed = analyze_file(&path).unwrap();
    assert_eq!(parsed.needed.len(), 2);

    let bin = env!("CARGO_BIN_EXE_bincompat");

    let scan = Command::new(bin).arg("scan").arg(&path).output().unwrap();
    assert_eq!(scan.status.code(), Some(0));
    let scan_stdout = String::from_utf8_lossy(&scan.stdout);
    assert!(scan_stdout.contains("GLIBC_2.38"));
    assert!(scan_stdout.contains("__isoc23_strtol"));
    assert!(scan_stdout.contains("GLIBC_ABI_DT_RELR"));

    let pass = Command::new(bin)
        .args(["check"])
        .arg(&path)
        .args(["--max-glibc", "2.38", "--max-glibcxx", "3.4.30"])
        .output()
        .unwrap();
    assert_eq!(pass.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&pass.stdout).contains("Policy Status: PASS"));

    let fail = Command::new(bin)
        .args(["check"])
        .arg(&path)
        .args([
            "--max-glibc",
            "2.34",
            "--forbid-abi-tag",
            "GLIBC_ABI_DT_RELR",
            "--forbid-rpath",
        ])
        .output()
        .unwrap();
    assert_eq!(fail.status.code(), Some(1));
    let fail_stdout = String::from_utf8_lossy(&fail.stdout);
    assert!(fail_stdout.contains("Policy Status: FAIL"));
    assert!(fail_stdout.contains("__isoc23_strtol@GLIBC_2.38"));
    assert!(fail_stdout.contains("GLIBC_ABI_DT_RELR"));
    assert!(fail_stdout.contains("DT_RUNPATH"));

    let bad_args = Command::new(bin)
        .args(["check"])
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(bad_args.status.code(), Some(2));

    let _ = fs::remove_file(&path);
}
