use std::fs;
use std::process::Command;

use bincompat::{
    analyze_bytes, diff_analyses, evaluate_distro_matrix, render_check, render_diff, render_scan,
    DiffRegression, OutputFormat, Policy, Version,
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

fn put_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn put_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn put_i64(buf: &mut Vec<u8>, v: i64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn push_shdr(
    buf: &mut Vec<u8>,
    sh_type: u32,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_entsize: u64,
) {
    put_u32(buf, 0);
    put_u32(buf, sh_type);
    put_u64(buf, 0);
    put_u64(buf, 0);
    put_u64(buf, sh_offset);
    put_u64(buf, sh_size);
    put_u32(buf, sh_link);
    put_u32(buf, 0);
    put_u64(buf, 8);
    put_u64(buf, sh_entsize);
}

#[derive(Clone)]
struct SyntheticSpec {
    e_type: u16,
    needed: Vec<&'static str>,
    runpath: Option<&'static str>,
    glibc_tag: &'static str,
    glibc_sym: &'static str,
    dt_relr: bool,
    full_relro: bool,
    nx_enabled: bool,
    canary: bool,
}

fn build_elf(spec: &SyntheticSpec) -> Vec<u8> {
    let mut dynstr = StrTab::new();
    let needed_offs: Vec<u32> = spec.needed.iter().map(|s| dynstr.push(s)).collect();
    let s_libc = dynstr.push("libc.so.6");
    let s_runpath = spec.runpath.map(|r| dynstr.push(r));
    let s_glibc_tag = dynstr.push(spec.glibc_tag);
    let s_glibc_sym = dynstr.push(spec.glibc_sym);
    let s_relr_tag = spec.dt_relr.then(|| dynstr.push("GLIBC_ABI_DT_RELR"));
    let s_canary = spec.canary.then(|| dynstr.push("__stack_chk_fail"));

    let mut dynamic = Vec::new();
    for off in &needed_offs {
        put_i64(&mut dynamic, 1); // DT_NEEDED
        put_u64(&mut dynamic, u64::from(*off));
    }
    if let Some(rp) = s_runpath {
        put_i64(&mut dynamic, 29); // DT_RUNPATH
        put_u64(&mut dynamic, u64::from(rp));
    }
    let mut flags_1 = 0u64;
    if spec.e_type == 3 {
        flags_1 |= 0x0800_0000; // DF_1_PIE
    }
    if spec.full_relro {
        flags_1 |= 0x0000_0001; // DF_1_NOW
    }
    if flags_1 != 0 {
        put_i64(&mut dynamic, 0x6fff_fffb); // DT_FLAGS_1
        put_u64(&mut dynamic, flags_1);
    }
    put_i64(&mut dynamic, 0);
    put_u64(&mut dynamic, 0);

    let push_sym = |buf: &mut Vec<u8>, name: u32, info: u8, shndx: u16| {
        put_u32(buf, name);
        buf.push(info);
        buf.push(0);
        put_u16(buf, shndx);
        put_u64(buf, 0);
        put_u64(buf, 0);
    };

    let mut dynsym = Vec::new();
    let mut versym = Vec::new();
    push_sym(&mut dynsym, 0, 0, 0);
    put_u16(&mut versym, 0);

    push_sym(&mut dynsym, s_glibc_sym, (1 << 4) | 2, 0);
    put_u16(&mut versym, 2);

    if let Some(c_off) = s_canary {
        push_sym(&mut dynsym, c_off, (1 << 4) | 2, 0);
        put_u16(&mut versym, 2);
    }

    let mut verneed = Vec::new();
    let vn_cnt = if s_relr_tag.is_some() { 2u16 } else { 1u16 };
    put_u16(&mut verneed, 1);
    put_u16(&mut verneed, vn_cnt);
    put_u32(&mut verneed, s_libc);
    put_u32(&mut verneed, 16);
    put_u32(&mut verneed, 0);
    // Vernaux 0: GLIBC tag (idx 2)
    put_u32(&mut verneed, 0);
    put_u16(&mut verneed, 0);
    put_u16(&mut verneed, 2);
    put_u32(&mut verneed, s_glibc_tag);
    put_u32(&mut verneed, if s_relr_tag.is_some() { 16 } else { 0 });
    if let Some(relr_off) = s_relr_tag {
        put_u32(&mut verneed, 0);
        put_u16(&mut verneed, 0);
        put_u16(&mut verneed, 3);
        put_u32(&mut verneed, relr_off);
        put_u32(&mut verneed, 0);
    }

    let interp_bytes = b"/lib64/ld-linux-x86-64.so.2\0";
    let phdr_count = 3u16; // PT_INTERP, PT_GNU_RELRO (or PT_NULL), PT_GNU_STACK
    let mut elf = vec![0u8; 64 + usize::from(phdr_count) * 56];

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
    push_shdr(&mut elf, 0, 0, 0, 0, 0);
    push_shdr(&mut elf, 3, dynstr_off, dynstr.bytes.len() as u64, 0, 0);
    push_shdr(&mut elf, 6, dynamic_off, dynamic.len() as u64, 1, 16);
    push_shdr(&mut elf, 11, dynsym_off, dynsym.len() as u64, 1, 24);
    push_shdr(&mut elf, 0x6fff_ffff, versym_off, versym.len() as u64, 3, 2);
    push_shdr(
        &mut elf,
        0x6fff_fffe,
        verneed_off,
        verneed.len() as u64,
        1,
        0,
    );

    let mut ehdr = Vec::with_capacity(64);
    ehdr.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
    ehdr.extend_from_slice(&[0u8; 8]);
    put_u16(&mut ehdr, spec.e_type);
    put_u16(&mut ehdr, 62);
    put_u32(&mut ehdr, 1);
    put_u64(&mut ehdr, 0);
    put_u64(&mut ehdr, 64);
    put_u64(&mut ehdr, shoff);
    put_u32(&mut ehdr, 0);
    put_u16(&mut ehdr, 64);
    put_u16(&mut ehdr, 56);
    put_u16(&mut ehdr, phdr_count);
    put_u16(&mut ehdr, 64);
    put_u16(&mut ehdr, 6);
    put_u16(&mut ehdr, 0);
    elf[0..64].copy_from_slice(&ehdr);

    let mut write_phdr = |slot: usize, p_type: u32, p_flags: u32, p_offset: u64, p_filesz: u64| {
        let mut ph = Vec::with_capacity(56);
        put_u32(&mut ph, p_type);
        put_u32(&mut ph, p_flags);
        put_u64(&mut ph, p_offset);
        put_u64(&mut ph, 0);
        put_u64(&mut ph, 0);
        put_u64(&mut ph, p_filesz);
        put_u64(&mut ph, p_filesz);
        put_u64(&mut ph, 8);
        let start = 64 + slot * 56;
        elf[start..start + 56].copy_from_slice(&ph);
    };

    write_phdr(0, 3, 4, interp_off, interp_bytes.len() as u64); // PT_INTERP
    if spec.full_relro {
        write_phdr(1, 0x6474_e552, 4, 0, 0); // PT_GNU_RELRO
    } else {
        write_phdr(1, 0, 0, 0, 0); // PT_NULL
    }
    write_phdr(2, 0x6474_e551, if spec.nx_enabled { 6 } else { 7 }, 0, 0); // PT_GNU_STACK

    elf
}

/// Minimal strict RFC-8259 JSON syntax validator (zero external dependencies).
fn assert_valid_json(input: &str) {
    struct Parser<'a> {
        bytes: &'a [u8],
        pos: usize,
    }
    impl<'a> Parser<'a> {
        fn skip_ws(&mut self) {
            while self.pos < self.bytes.len()
                && matches!(self.bytes[self.pos], b' ' | b'\n' | b'\r' | b'\t')
            {
                self.pos += 1;
            }
        }
        fn peek(&self) -> Option<u8> {
            self.bytes.get(self.pos).copied()
        }
        fn parse_value(&mut self) -> Result<(), String> {
            self.skip_ws();
            match self.peek() {
                Some(b'{') => self.parse_object(),
                Some(b'[') => self.parse_array(),
                Some(b'"') => self.parse_string(),
                Some(b't') => self.expect_lit(b"true"),
                Some(b'f') => self.expect_lit(b"false"),
                Some(b'n') => self.expect_lit(b"null"),
                Some(b'-' | b'0'..=b'9') => self.parse_number(),
                other => Err(format!("unexpected byte {other:?} at offset {}", self.pos)),
            }
        }
        fn expect_lit(&mut self, lit: &[u8]) -> Result<(), String> {
            if self.bytes.get(self.pos..self.pos + lit.len()) == Some(lit) {
                self.pos += lit.len();
                Ok(())
            } else {
                Err(format!("expected literal at offset {}", self.pos))
            }
        }
        fn parse_string(&mut self) -> Result<(), String> {
            if self.peek() != Some(b'"') {
                return Err(format!("expected '\"' at {}", self.pos));
            }
            self.pos += 1;
            while self.pos < self.bytes.len() {
                let b = self.bytes[self.pos];
                self.pos += 1;
                match b {
                    b'"' => return Ok(()),
                    b'\\' => {
                        let esc = *self
                            .bytes
                            .get(self.pos)
                            .ok_or_else(|| "unterminated escape".to_string())?;
                        self.pos += 1;
                        match esc {
                            b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {}
                            b'u' => {
                                if self.pos + 4 > self.bytes.len() {
                                    return Err("short \\u escape".to_string());
                                }
                                for &h in &self.bytes[self.pos..self.pos + 4] {
                                    if !h.is_ascii_hexdigit() {
                                        return Err("invalid hex in \\u escape".to_string());
                                    }
                                }
                                self.pos += 4;
                            }
                            _ => return Err(format!("invalid escape '\\{}'", esc as char)),
                        }
                    }
                    0x00..=0x1f => return Err(format!("unescaped control byte 0x{b:02x}")),
                    _ => {}
                }
            }
            Err("unterminated string".to_string())
        }
        fn parse_number(&mut self) -> Result<(), String> {
            if self.peek() == Some(b'-') {
                self.pos += 1;
            }
            let start = self.pos;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
            if self.pos == start {
                return Err(format!("invalid number at {}", self.pos));
            }
            Ok(())
        }
        fn parse_array(&mut self) -> Result<(), String> {
            self.pos += 1; // '['
            self.skip_ws();
            if self.peek() == Some(b']') {
                self.pos += 1;
                return Ok(());
            }
            loop {
                self.parse_value()?;
                self.skip_ws();
                match self.peek() {
                    Some(b',') => self.pos += 1,
                    Some(b']') => {
                        self.pos += 1;
                        return Ok(());
                    }
                    other => return Err(format!("expected ',' or ']', got {other:?}")),
                }
            }
        }
        fn parse_object(&mut self) -> Result<(), String> {
            self.pos += 1; // '{'
            self.skip_ws();
            if self.peek() == Some(b'}') {
                self.pos += 1;
                return Ok(());
            }
            loop {
                self.skip_ws();
                self.parse_string()?;
                self.skip_ws();
                if self.peek() != Some(b':') {
                    return Err(format!("expected ':' at {}", self.pos));
                }
                self.pos += 1;
                self.parse_value()?;
                self.skip_ws();
                match self.peek() {
                    Some(b',') => self.pos += 1,
                    Some(b'}') => {
                        self.pos += 1;
                        return Ok(());
                    }
                    other => return Err(format!("expected ',' or '}}', got {other:?}")),
                }
            }
        }
    }

    let mut p = Parser {
        bytes: input.as_bytes(),
        pos: 0,
    };
    p.parse_value()
        .unwrap_or_else(|e| panic!("invalid JSON: {e}\n--- input ---\n{input}"));
    p.skip_ws();
    assert_eq!(
        p.pos,
        p.bytes.len(),
        "trailing bytes after JSON document at {}",
        p.pos
    );
}

#[test]
fn distro_matrix_and_target_presets_enforce_glibc_and_dt_relr() {
    let elf = build_elf(&SyntheticSpec {
        e_type: 3,
        needed: vec!["libc.so.6"],
        runpath: None,
        glibc_tag: "GLIBC_2.34",
        glibc_sym: "pthread_create",
        dt_relr: true,
        full_relro: true,
        nx_enabled: true,
        canary: true,
    });
    let analysis = analyze_bytes(&elf).unwrap();

    let matrix = evaluate_distro_matrix(&analysis);
    let find = |id: &str| matrix.iter().find(|d| d.baseline.id == id).unwrap();

    // Fails RHEL 8 (GLIBC 2.34 > 2.28 AND DT_RELR) and Ubuntu 22.04 (DT_RELR needs glibc >= 2.36)
    assert!(!find("rhel-8").compatible);
    assert!(!find("ubuntu-22.04").compatible);
    assert!(find("ubuntu-22.04")
        .reasons
        .iter()
        .any(|r| r.contains("GLIBC_ABI_DT_RELR")));

    // Passes Debian 12 (glibc 2.36 + DT_RELR) and Ubuntu 24.04 (glibc 2.39 + DT_RELR)
    assert!(find("debian-12").compatible);
    assert!(find("ubuntu-24.04").compatible);

    // Policy::apply_distro_target mirrors the matrix
    let mut u22 = Policy::default();
    assert_eq!(u22.apply_distro_target("jammy").unwrap(), "ubuntu-22.04");
    assert!(!u22.evaluate(&analysis).passed);

    let mut d12 = Policy::default();
    assert_eq!(d12.apply_distro_target("debian-12").unwrap(), "debian-12");
    assert!(d12.evaluate(&analysis).passed);
}

#[test]
fn diff_detects_all_regressions_and_reverse_improvements() {
    let baseline_bytes = build_elf(&SyntheticSpec {
        e_type: 3, // PIE
        needed: vec!["libc.so.6"],
        runpath: None,
        glibc_tag: "GLIBC_2.28",
        glibc_sym: "fcntl64",
        dt_relr: false,
        full_relro: true,
        nx_enabled: true,
        canary: true,
    });
    let candidate_bytes = build_elf(&SyntheticSpec {
        e_type: 2, // no-PIE
        needed: vec!["libc.so.6", "libm.so.6"],
        runpath: Some("/opt/private/lib"),
        glibc_tag: "GLIBC_2.38",
        glibc_sym: "__isoc23_strtol",
        dt_relr: true,
        full_relro: false,
        nx_enabled: false,
        canary: false,
    });

    let base = analyze_bytes(&baseline_bytes).unwrap();
    let cand = analyze_bytes(&candidate_bytes).unwrap();

    // Forward: regressions across every category
    let fwd = diff_analyses(&base, &cand);
    assert!(!fwd.passed);
    assert!(fwd.regressions.iter().any(|r| matches!(
        r,
        DiffRegression::AddedNeeded { library } if library == "libm.so.6"
    )));
    assert!(fwd.regressions.iter().any(|r| matches!(
        r,
        DiffRegression::VersionBumped {
            family,
            baseline_max: Some(prev),
            candidate_max,
            raw_tag,
            symbols,
            ..
        } if family == "GLIBC"
            && *prev == Version::parse("2.28").unwrap()
            && *candidate_max == Version::parse("2.38").unwrap()
            && raw_tag == "GLIBC_2.38"
            && symbols.iter().any(|s| s.name == "__isoc23_strtol")
    )));
    assert!(fwd.regressions.iter().any(|r| matches!(
        r,
        DiffRegression::AddedAbiTag { tag, .. } if tag == "GLIBC_ABI_DT_RELR"
    )));
    assert!(fwd.regressions.iter().any(|r| matches!(
        r,
        DiffRegression::AddedRpath { kind, value } if kind == "DT_RUNPATH" && value == "/opt/private/lib"
    )));
    for ctrl in ["PIE", "RELRO", "NX", "stack-canary"] {
        assert!(
            fwd.regressions.iter().any(|r| matches!(
                r,
                DiffRegression::HardeningRegressed { control, .. } if control == ctrl
            )),
            "expected hardening regression for {ctrl}"
        );
    }

    // Reverse: zero regressions, all improvements captured
    let rev = diff_analyses(&cand, &base);
    assert!(rev.passed);
    assert!(rev.regressions.is_empty());
    assert_eq!(rev.improvements.removed_needed, vec!["libm.so.6"]);
    assert_eq!(rev.improvements.lowered_versions.len(), 1);
    assert_eq!(rev.improvements.removed_abi_tags.len(), 1);
    assert_eq!(rev.improvements.removed_rpath.len(), 1);
    assert_eq!(rev.improvements.hardening_improved.len(), 4);

    // Every output format is valid and deterministic
    let mut policy = Policy::default();
    policy.apply_distro_target("rhel-8").unwrap();
    policy.forbid_rpath = true;
    policy.enable_standard_hardening();
    let eval = policy.evaluate(&cand);

    for fmt in [
        OutputFormat::Text,
        OutputFormat::Json,
        OutputFormat::Markdown,
        OutputFormat::Sarif,
    ] {
        let s = render_scan(fmt, "cand.elf", &cand);
        let c = render_check(fmt, "cand.elf", &cand, &policy, &eval);
        let d = render_diff(fmt, "base.elf", "cand.elf", &fwd);
        assert!(!s.is_empty() && !c.is_empty() && !d.is_empty());
        if matches!(fmt, OutputFormat::Json | OutputFormat::Sarif) {
            assert_valid_json(&s);
            assert_valid_json(&c);
            assert_valid_json(&d);
        }
        if fmt == OutputFormat::Sarif {
            assert!(c.contains("\"version\": \"2.1.0\""));
            assert!(c.contains("\"ruleId\": \"BC001\""));
            assert!(c.contains("\"ruleId\": \"BC002\""));
            assert!(c.contains("\"ruleId\": \"BC003\""));
            assert!(c.contains("\"ruleId\": \"BC004\""));
            assert!(d.contains("\"ruleId\": \"BC101\""));
            assert!(d.contains("\"ruleId\": \"BC102\""));
            assert!(d.contains("\"ruleId\": \"BC103\""));
            assert!(d.contains("\"ruleId\": \"BC104\""));
            assert!(d.contains("\"ruleId\": \"BC105\""));
        }
        if fmt == OutputFormat::Markdown {
            assert!(s.contains("### Distro Compatibility"));
            assert!(c.contains("### Policy Status: FAIL"));
            assert!(d.contains("### Regressions"));
        }
    }
}

#[test]
fn cli_supports_target_diff_and_all_formats() {
    let pid = std::process::id();
    let base_path = std::env::temp_dir().join(format!("bincompat_diff_base_{pid}.elf"));
    let cand_path = std::env::temp_dir().join(format!("bincompat_diff_cand_{pid}.elf"));

    fs::write(
        &base_path,
        build_elf(&SyntheticSpec {
            e_type: 3,
            needed: vec!["libc.so.6"],
            runpath: None,
            glibc_tag: "GLIBC_2.28",
            glibc_sym: "fcntl64",
            dt_relr: false,
            full_relro: true,
            nx_enabled: true,
            canary: true,
        }),
    )
    .unwrap();
    fs::write(
        &cand_path,
        build_elf(&SyntheticSpec {
            e_type: 3,
            needed: vec!["libc.so.6", "libz.so.1"],
            runpath: Some("$ORIGIN/lib"),
            glibc_tag: "GLIBC_2.36",
            glibc_sym: "arc4random",
            dt_relr: true,
            full_relro: true,
            nx_enabled: true,
            canary: true,
        }),
    )
    .unwrap();

    let bin = env!("CARGO_BIN_EXE_bincompat");

    // scan --format json
    let scan_json = Command::new(bin)
        .args(["scan", "--format", "json"])
        .arg(&cand_path)
        .output()
        .unwrap();
    assert_eq!(scan_json.status.code(), Some(0));
    let scan_json_str = String::from_utf8(scan_json.stdout).unwrap();
    assert_valid_json(&scan_json_str);
    assert!(scan_json_str.contains("\"distro_compatibility\""));

    // check --target rhel-8 --format sarif -> exit 1 + valid SARIF
    let check_sarif = Command::new(bin)
        .args(["check"])
        .arg(&cand_path)
        .args(["--target", "rhel-8", "--format", "sarif"])
        .output()
        .unwrap();
    assert_eq!(check_sarif.status.code(), Some(1));
    let check_sarif_str = String::from_utf8(check_sarif.stdout).unwrap();
    assert_valid_json(&check_sarif_str);
    assert!(check_sarif_str.contains("BC001"));
    assert!(check_sarif_str.contains("BC002"));

    // check --target ubuntu-24.04 -> exit 0
    let check_pass = Command::new(bin)
        .args(["check"])
        .arg(&base_path)
        .args(["--target", "rhel-8", "--require-hardening"])
        .output()
        .unwrap();
    assert_eq!(check_pass.status.code(), Some(0));

    // diff base -> cand (fails with exit 1 in JSON + Markdown)
    let diff_json = Command::new(bin)
        .args(["diff"])
        .arg(&base_path)
        .arg(&cand_path)
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert_eq!(diff_json.status.code(), Some(1));
    let diff_json_str = String::from_utf8(diff_json.stdout).unwrap();
    assert_valid_json(&diff_json_str);
    assert!(diff_json_str.contains("arc4random"));
    assert!(diff_json_str.contains("libz.so.1"));

    // diff cand -> base (passes with exit 0 in Markdown)
    let diff_md = Command::new(bin)
        .args(["diff"])
        .arg(&cand_path)
        .arg(&base_path)
        .args(["--format", "markdown"])
        .output()
        .unwrap();
    assert_eq!(diff_md.status.code(), Some(0));
    let diff_md_str = String::from_utf8(diff_md.stdout).unwrap();
    assert!(diff_md_str.contains("Status: **PASS**"));
    assert!(diff_md_str.contains("### Improvements"));

    // Unknown --target and unknown --format return exit 2
    let bad_target = Command::new(bin)
        .args(["check"])
        .arg(&base_path)
        .args(["--target", "solaris-9"])
        .output()
        .unwrap();
    assert_eq!(bad_target.status.code(), Some(2));

    let bad_fmt = Command::new(bin)
        .args(["scan", "--format", "xml"])
        .arg(&base_path)
        .output()
        .unwrap();
    assert_eq!(bad_fmt.status.code(), Some(2));

    let _ = fs::remove_file(&base_path);
    let _ = fs::remove_file(&cand_path);
}

#[cfg(target_os = "linux")]
#[test]
fn live_gcc_hardening_regression_detected_by_diff_and_sarif() {
    if Command::new("gcc").arg("--version").output().is_err() {
        return;
    }

    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!("bincompat_gcc_diff_{pid}"));
    let _ = fs::create_dir_all(&dir);
    let src = dir.join("app.c");
    let hardened = dir.join("app_hardened");
    let regressed = dir.join("app_regressed");

    fs::write(
        &src,
        "#include <stdio.h>\n#include <string.h>\nint main(int argc, char **argv) {\n  char buf[32];\n  if (argc > 1) { strncpy(buf, argv[1], sizeof(buf) - 1); buf[31] = 0; puts(buf); }\n  return 0;\n}\n",
    )
    .unwrap();

    let s1 = Command::new("gcc")
        .args([
            "-O2",
            "-fPIE",
            "-pie",
            "-fstack-protector-strong",
            "-Wl,-z,relro,-z,now",
            "-Wl,-z,noexecstack",
        ])
        .arg(&src)
        .arg("-o")
        .arg(&hardened)
        .status()
        .unwrap();
    assert!(s1.success(), "hardened gcc build should succeed");

    let s2 = Command::new("gcc")
        .args([
            "-O2",
            "-fno-PIE",
            "-no-pie",
            "-fno-stack-protector",
            "-Wl,-z,norelro",
            "-Wl,-z,execstack",
            "-Wl,-rpath,/tmp/bincompat-leak",
        ])
        .arg(&src)
        .arg("-o")
        .arg(&regressed)
        .status()
        .unwrap();
    assert!(s2.success(), "regressed gcc build should succeed");

    let bin = env!("CARGO_BIN_EXE_bincompat");
    let out = Command::new(bin)
        .args(["diff"])
        .arg(&hardened)
        .arg(&regressed)
        .args(["--format", "sarif"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let sarif = String::from_utf8(out.stdout).unwrap();
    assert_valid_json(&sarif);
    assert!(sarif.contains("\"ruleId\": \"BC104\"")); // AddedRpath
    assert!(sarif.contains("\"ruleId\": \"BC105\"")); // HardeningRegressed
    assert!(sarif.contains("PIE"));
    assert!(sarif.contains("RELRO"));
    assert!(sarif.contains("NX"));
    assert!(sarif.contains("stack-canary"));

    let _ = fs::remove_dir_all(&dir);
}
