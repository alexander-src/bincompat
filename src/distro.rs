use crate::elf::BinaryAnalysis;
use crate::version::Version;

/// Reference Linux distribution baseline for glibc, libstdc++, and DT_RELR support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DistroBaseline {
    pub id: &'static str,
    pub display_name: &'static str,
    pub glibc: &'static str,
    pub glibcxx: &'static str,
    pub supports_dt_relr: bool,
}

/// Built-in reference baselines for common LTS and enterprise Linux distributions.
pub const DISTRO_BASELINES: &[DistroBaseline] = &[
    DistroBaseline {
        id: "rhel-8",
        display_name: "RHEL / Rocky 8",
        glibc: "2.28",
        glibcxx: "3.4.25",
        supports_dt_relr: false,
    },
    DistroBaseline {
        id: "ubuntu-20.04",
        display_name: "Ubuntu 20.04 LTS",
        glibc: "2.31",
        glibcxx: "3.4.28",
        supports_dt_relr: false,
    },
    DistroBaseline {
        id: "debian-11",
        display_name: "Debian 11",
        glibc: "2.31",
        glibcxx: "3.4.28",
        supports_dt_relr: false,
    },
    DistroBaseline {
        id: "rhel-9",
        display_name: "RHEL / Rocky 9",
        glibc: "2.34",
        glibcxx: "3.4.29",
        supports_dt_relr: false,
    },
    DistroBaseline {
        id: "ubuntu-22.04",
        display_name: "Ubuntu 22.04 LTS",
        glibc: "2.35",
        glibcxx: "3.4.30",
        supports_dt_relr: false,
    },
    DistroBaseline {
        id: "debian-12",
        display_name: "Debian 12",
        glibc: "2.36",
        glibcxx: "3.4.30",
        supports_dt_relr: true,
    },
    DistroBaseline {
        id: "ubuntu-24.04",
        display_name: "Ubuntu 24.04 LTS",
        glibc: "2.39",
        glibcxx: "3.4.32",
        supports_dt_relr: true,
    },
    DistroBaseline {
        id: "debian-13",
        display_name: "Debian 13",
        glibc: "2.41",
        glibcxx: "3.4.33",
        supports_dt_relr: true,
    },
];

/// Compatibility result for one Linux distribution baseline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistroCompatibility {
    pub baseline: DistroBaseline,
    pub compatible: bool,
    pub reasons: Vec<String>,
}

/// Looks up a built-in distribution target preset (case-insensitive, accepts common aliases).
pub fn lookup_distro(spec: &str) -> Option<DistroBaseline> {
    let normalized = spec.trim().to_ascii_lowercase().replace('_', "-");
    let canonical = match normalized.as_str() {
        "rhel-8" | "rhel8" | "rocky-8" | "rocky8" | "alma-8" | "el8" | "manylinux-2-28" => "rhel-8",
        "rhel-9" | "rhel9" | "rocky-9" | "rocky9" | "alma-9" | "el9" | "manylinux-2-34" => "rhel-9",
        "ubuntu-20.04" | "ubuntu20.04" | "focal" => "ubuntu-20.04",
        "ubuntu-22.04" | "ubuntu22.04" | "jammy" => "ubuntu-22.04",
        "ubuntu-24.04" | "ubuntu24.04" | "noble" => "ubuntu-24.04",
        "debian-11" | "debian11" | "bullseye" => "debian-11",
        "debian-12" | "debian12" | "bookworm" => "debian-12",
        "debian-13" | "debian13" | "trixie" => "debian-13",
        other => other,
    };
    DISTRO_BASELINES.iter().copied().find(|d| d.id == canonical)
}

/// Returns the sorted list of canonical distribution target IDs accepted by `--target`.
pub fn supported_target_ids() -> Vec<&'static str> {
    DISTRO_BASELINES.iter().map(|d| d.id).collect()
}

/// Evaluates an ELF64 binary analysis against all built-in Linux distribution baselines.
pub fn evaluate_distro_matrix(analysis: &BinaryAnalysis) -> Vec<DistroCompatibility> {
    let has_dt_relr = analysis
        .abi_tags
        .iter()
        .any(|t| t.tag == "GLIBC_ABI_DT_RELR");
    let req_glibc = analysis.max_versions.get("GLIBC");
    let req_glibcxx = analysis.max_versions.get("GLIBCXX");

    DISTRO_BASELINES
        .iter()
        .copied()
        .map(|baseline| {
            let mut reasons = Vec::new();
            let max_glibc = Version::parse(baseline.glibc).expect("valid static glibc version");
            let max_glibcxx =
                Version::parse(baseline.glibcxx).expect("valid static glibcxx version");

            if let Some(found) = req_glibc {
                if found > &max_glibc {
                    reasons.push(format!("GLIBC_{found} > {}", baseline.glibc));
                }
            }
            if let Some(found) = req_glibcxx {
                if found > &max_glibcxx {
                    reasons.push(format!("GLIBCXX_{found} > {}", baseline.glibcxx));
                }
            }
            if has_dt_relr && !baseline.supports_dt_relr {
                reasons.push("requires GLIBC_ABI_DT_RELR (glibc >= 2.36)".to_string());
            }

            DistroCompatibility {
                baseline,
                compatible: reasons.is_empty(),
                reasons,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_canonical_and_alias_targets() {
        assert_eq!(lookup_distro("rhel-8").unwrap().glibc, "2.28");
        assert_eq!(lookup_distro("rocky-8").unwrap().id, "rhel-8");
        assert_eq!(lookup_distro("manylinux_2_28").unwrap().id, "rhel-8");
        assert_eq!(lookup_distro("Ubuntu-22.04").unwrap().glibc, "2.35");
        assert_eq!(lookup_distro("bookworm").unwrap().id, "debian-12");
        assert!(lookup_distro("unknown-os").is_none());
    }
}
