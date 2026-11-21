use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;

use bincompat::{analyze_file, Policy, Version};

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
