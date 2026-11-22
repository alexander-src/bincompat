use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;

use bincompat::{analyze_file, NxStatus, PieStatus, Policy, RelroStatus, Version};

fn command_available(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn readelf_needed(path: &Path) -> Vec<String> {
    let out = Command::new("readelf")
        .args(["-d", "-W"])
        .arg(path)
        .output()
        .expect("readelf -d failed");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    let mut libs = Vec::new();
    for line in text.lines() {
        if line.contains("(NEEDED)") {
            if let (Some(l), Some(r)) = (line.find('['), line.rfind(']')) {
                let name = line[l + 1..r].to_string();
                if !libs.contains(&name) {
                    libs.push(name);
                }
            }
        }
    }
    libs
}

fn readelf_verneed_tags(path: &Path) -> BTreeSet<(String, String)> {
    let out = Command::new("readelf")
        .args(["-V", "-W"])
        .arg(path)
        .output()
        .expect("readelf -V failed");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    let mut in_verneed = false;
    let mut current_file = String::new();
    let mut tags = BTreeSet::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Version needs section") {
            in_verneed = true;
            continue;
        }
        if !in_verneed {
            continue;
        }
        if let Some(rest) = trimmed.split("File: ").nth(1) {
            if let Some(file) = rest.split_whitespace().next() {
                current_file = file.to_string();
            }
        } else if let Some(rest) = trimmed.split("Name: ").nth(1) {
            if let Some(tag) = rest.split_whitespace().next() {
                if !current_file.is_empty() {
                    tags.insert((current_file.clone(), tag.to_string()));
                }
            }
        }
    }
    tags
}

fn readelf_undef_versioned_symbols(path: &Path) -> BTreeMap<String, BTreeSet<String>> {
    let out = Command::new("readelf")
        .args(["--dyn-syms", "-W"])
        .arg(path)
        .output()
        .expect("readelf --dyn-syms failed");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    let mut by_tag: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // Format: Num: Value Size Type Bind Vis Ndx Name [ (ver) ]
        if cols.len() < 8 || !cols[0].ends_with(':') {
            continue;
        }
        if cols[6] != "UND" {
            continue;
        }
        let raw_name = cols[7];
        if let Some((sym, ver_part)) = raw_name.split_once('@') {
            let ver = ver_part.trim_start_matches('@');
            if !sym.is_empty() && !ver.is_empty() {
                by_tag
                    .entry(ver.to_string())
                    .or_default()
                    .insert(sym.to_string());
            }
        }
    }
    by_tag
}

#[test]
fn matches_gnu_readelf_on_live_linux_system_binaries() {
    if !cfg!(target_os = "linux") || !command_available("readelf") {
        return;
    }

    let candidates = ["/usr/bin/env", "/usr/bin/ls"];
    let mut checked = 0usize;
    for candidate in candidates {
        let path = Path::new(candidate);
        if !path.exists() {
            continue;
        }
        checked += 1;

        let analysis = analyze_file(path).expect("bincompat failed on system binary");
        assert_eq!(
            analysis.needed,
            readelf_needed(path),
            "DT_NEEDED mismatch on {candidate}"
        );

        let actual_tags: BTreeSet<(String, String)> = analysis
            .requirements
            .iter()
            .map(|r| (r.library.clone(), r.raw_tag.clone()))
            .collect();
        assert_eq!(
            actual_tags,
            readelf_verneed_tags(path),
            "VERNEED tag mismatch on {candidate}"
        );

        let mut actual_syms: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for req in &analysis.requirements {
            if !req.symbols.is_empty() {
                let entry = actual_syms.entry(req.raw_tag.clone()).or_default();
                for sym in &req.symbols {
                    entry.insert(sym.name.clone());
                }
            }
        }
        assert_eq!(
            actual_syms,
            readelf_undef_versioned_symbols(path),
            "attributed undefined symbols mismatch on {candidate}"
        );

        let (has_relro, expected_nx, bind_now) = readelf_hardening(path);
        let expected_relro = match (has_relro, bind_now) {
            (true, true) => RelroStatus::Full,
            (true, false) => RelroStatus::Partial,
            (false, _) => RelroStatus::None,
        };
        assert_eq!(
            analysis.hardening.relro, expected_relro,
            "RELRO mismatch vs readelf on {candidate}"
        );
        assert_eq!(
            analysis.hardening.nx, expected_nx,
            "NX mismatch vs readelf on {candidate}"
        );
    }

    assert!(checked > 0, "expected at least one Linux system binary");
}

#[test]
fn matches_live_gxx_binary_with_glibcxx_and_runpath() {
    if !cfg!(target_os = "linux") || !command_available("g++") || !command_available("readelf") {
        return;
    }

    let tmp_dir = std::env::temp_dir().join(format!("bincompat_gxx_{}", std::process::id()));
    fs::create_dir_all(&tmp_dir).unwrap();
    let src_path = tmp_dir.join("sample.cpp");
    let out_path = tmp_dir.join("sample_bin");

    fs::write(
        &src_path,
        r#"
#include <iostream>
#include <string>
#include <vector>

int main() {
    std::vector<std::string> items = {"elf64", "glibc", "glibcxx"};
    for (const auto& s : items) {
        std::cout << s << "\n";
    }
    return 0;
}
"#,
    )
    .unwrap();

    let status = Command::new("g++")
        .args(["-O2", "-Wl,-rpath,/opt/bincompat-test", "-o"])
        .arg(&out_path)
        .arg(&src_path)
        .status()
        .expect("failed to invoke g++");
    assert!(status.success(), "g++ compilation failed");

    let analysis = analyze_file(&out_path).unwrap();
    assert!(analysis.is_dynamic);
    assert!(analysis
        .needed
        .iter()
        .any(|l| l.starts_with("libstdc++.so")));
    assert!(analysis.needed.iter().any(|l| l.starts_with("libc.so")));
    assert!(analysis.max_versions.contains_key("GLIBC"));
    assert!(analysis.max_versions.contains_key("GLIBCXX"));
    assert!(
        analysis.rpath.as_deref() == Some("/opt/bincompat-test")
            || analysis.runpath.as_deref() == Some("/opt/bincompat-test")
    );

    let mut policy = Policy::default();
    policy.set_max_version("GLIBC", Version::parse("2.1").unwrap());
    policy.forbid_rpath = true;
    let eval = policy.evaluate(&analysis);
    assert!(!eval.passed);
    assert!(eval.violations.len() >= 2);

    let _ = fs::remove_dir_all(&tmp_dir);
}

fn readelf_hardening(path: &Path) -> (bool, NxStatus, bool) {
    let ph_out = Command::new("readelf")
        .args(["-l", "-W"])
        .arg(path)
        .output()
        .expect("readelf -l failed");
    assert!(ph_out.status.success());
    let ph_text = String::from_utf8_lossy(&ph_out.stdout);

    let mut has_relro = false;
    let mut nx = NxStatus::Missing;
    for line in ph_text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.is_empty() {
            continue;
        }
        if cols[0] == "GNU_RELRO" {
            has_relro = true;
        } else if cols[0] == "GNU_STACK" {
            // Format: Type Offset VirtAddr PhysAddr FileSiz MemSiz Flg Align
            let flg = cols.get(6).copied().unwrap_or("");
            nx = if flg.contains('E') {
                NxStatus::Disabled
            } else {
                NxStatus::Enabled
            };
        }
    }

    let dyn_out = Command::new("readelf")
        .args(["-d", "-W"])
        .arg(path)
        .output()
        .expect("readelf -d failed");
    assert!(dyn_out.status.success());
    let dyn_text = String::from_utf8_lossy(&dyn_out.stdout);
    let mut bind_now = false;
    for line in dyn_text.lines() {
        if line.contains("(BIND_NOW)")
            || (line.contains("(FLAGS)") && line.contains("BIND_NOW"))
            || (line.contains("(FLAGS_1)") && line.split_whitespace().any(|t| t == "NOW"))
        {
            bind_now = true;
        }
    }

    (has_relro, nx, bind_now)
}

#[test]
fn matches_readelf_hardening_on_live_gxx_hardened_partial_and_unhardened_builds() {
    if !cfg!(target_os = "linux") || !command_available("g++") || !command_available("readelf") {
        return;
    }

    let tmp_dir = std::env::temp_dir().join(format!("bincompat_harden_{}", std::process::id()));
    fs::create_dir_all(&tmp_dir).unwrap();
    let src_path = tmp_dir.join("canary_sample.cpp");
    let hardened_bin = tmp_dir.join("hardened_app");
    let partial_bin = tmp_dir.join("partial_relro_app");
    let unhardened_bin = tmp_dir.join("unhardened_app");

    // Stack buffer copy guarantees -fstack-protector-strong emits __stack_chk_fail
    fs::write(
        &src_path,
        r#"
#include <cstring>
#include <iostream>

__attribute__((noinline))
size_t copy_and_measure(const char* input) {
    char buf[64];
    std::strncpy(buf, input, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    return std::strlen(buf);
}

int main(int argc, char** argv) {
    const char* msg = argc > 1 ? argv[1] : "bincompat";
    std::cout << copy_and_measure(msg) << "\n";
    return 0;
}
"#,
    )
    .unwrap();

    let compile = |out: &Path, flags: &[&str]| {
        let output = Command::new("g++")
            .args(flags)
            .arg("-o")
            .arg(out)
            .arg(&src_path)
            .output()
            .expect("failed to invoke g++");
        assert!(
            output.status.success(),
            "g++ failed for {}:\n{}",
            out.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    };

    compile(
        &hardened_bin,
        &[
            "-O2",
            "-fPIE",
            "-pie",
            "-Wl,-z,relro,-z,now",
            "-Wl,-z,noexecstack",
            "-fstack-protector-strong",
        ],
    );
    compile(
        &partial_bin,
        &[
            "-O2",
            "-fPIE",
            "-pie",
            "-Wl,-z,relro,-z,lazy",
            "-Wl,-z,noexecstack",
            "-fstack-protector-strong",
        ],
    );
    compile(
        &unhardened_bin,
        &[
            "-O2",
            "-fno-pie",
            "-no-pie",
            "-Wl,-z,norelro",
            "-Wl,-z,execstack",
            "-fno-stack-protector",
        ],
    );

    // Cross-check all three against GNU readelf -l / -d
    for path in [&hardened_bin, &partial_bin, &unhardened_bin] {
        let analysis = analyze_file(path).unwrap();
        let (has_relro, expected_nx, bind_now) = readelf_hardening(path);
        let expected_relro = match (has_relro, bind_now) {
            (true, true) => RelroStatus::Full,
            (true, false) => RelroStatus::Partial,
            (false, _) => RelroStatus::None,
        };
        assert_eq!(
            analysis.hardening.relro,
            expected_relro,
            "RELRO mismatch vs readelf on {}",
            path.display()
        );
        assert_eq!(
            analysis.hardening.nx,
            expected_nx,
            "NX mismatch vs readelf on {}",
            path.display()
        );
    }

    let h = analyze_file(&hardened_bin).unwrap();
    assert_eq!(h.hardening.pie, PieStatus::Pie);
    assert_eq!(h.hardening.relro, RelroStatus::Full);
    assert_eq!(h.hardening.nx, NxStatus::Enabled);
    assert!(h.hardening.stack_canary);

    let p = analyze_file(&partial_bin).unwrap();
    assert_eq!(p.hardening.pie, PieStatus::Pie);
    assert_eq!(p.hardening.relro, RelroStatus::Partial);
    assert_eq!(p.hardening.nx, NxStatus::Enabled);
    assert!(p.hardening.stack_canary);

    let u = analyze_file(&unhardened_bin).unwrap();
    assert_eq!(u.hardening.pie, PieStatus::NoPie);
    assert_eq!(u.hardening.relro, RelroStatus::None);
    assert_eq!(u.hardening.nx, NxStatus::Disabled);
    assert!(!u.hardening.stack_canary);

    // Exercise the actual CLI binary on hardened, partial, and unhardened builds
    let cli = env!("CARGO_BIN_EXE_bincompat");

    let pass = Command::new(cli)
        .args(["check"])
        .arg(&hardened_bin)
        .arg("--require-hardening")
        .output()
        .unwrap();
    assert_eq!(pass.status.code(), Some(0));
    let pass_out = String::from_utf8_lossy(&pass.stdout);
    assert!(pass_out.contains("hardening     : PIE=pie, RELRO=full, NX=enabled, canary=present"));
    assert!(pass_out.contains("Policy Status: PASS"));

    let partial_pass = Command::new(cli)
        .args(["check"])
        .arg(&partial_bin)
        .args([
            "--require-pie",
            "--require-relro",
            "partial",
            "--require-nx",
            "--require-canary",
        ])
        .output()
        .unwrap();
    assert_eq!(partial_pass.status.code(), Some(0));

    let partial_fail = Command::new(cli)
        .args(["check"])
        .arg(&partial_bin)
        .args(["--require-relro", "full"])
        .output()
        .unwrap();
    assert_eq!(partial_fail.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&partial_fail.stdout)
        .contains("RELRO=full required, found partial"));

    let unhardened_fail = Command::new(cli)
        .args(["check"])
        .arg(&unhardened_bin)
        .arg("--require-hardening")
        .output()
        .unwrap();
    assert_eq!(unhardened_fail.status.code(), Some(1));
    let fail_out = String::from_utf8_lossy(&unhardened_fail.stdout);
    assert!(fail_out.contains("Policy Status: FAIL"));
    assert!(fail_out.contains("PIE required, found no-pie"));
    assert!(fail_out.contains("RELRO=full required, found none"));
    assert!(fail_out.contains("NX stack required, found disabled"));
    assert!(fail_out.contains("stack canary required"));

    let _ = fs::remove_dir_all(&tmp_dir);
}
