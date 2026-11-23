use std::collections::{BTreeMap, BTreeSet};

use crate::distro::{lookup_distro, supported_target_ids};
use crate::elf::{AttributedSymbol, BinaryAnalysis, NxStatus, PieStatus, RelroStatus};
use crate::error::{BincompatError, Result};
use crate::version::{Version, VersionTag};

/// Portability and hardening policy enforced by `bincompat check`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    pub max_versions: BTreeMap<String, Version>,
    pub forbid_abi_tags: BTreeSet<String>,
    pub forbid_rpath: bool,
    pub require_pie: bool,
    pub require_nx: bool,
    pub min_relro: Option<RelroStatus>,
    pub require_canary: bool,
}

impl Policy {
    pub fn is_empty(&self) -> bool {
        self.max_versions.is_empty()
            && self.forbid_abi_tags.is_empty()
            && !self.forbid_rpath
            && !self.require_pie
            && !self.require_nx
            && self.min_relro.is_none()
            && !self.require_canary
    }

    pub fn set_max_version(&mut self, family: impl Into<String>, version: Version) {
        self.max_versions.insert(family.into(), version);
    }

    /// Applies a built-in Linux distribution compatibility baseline (`--target`).
    pub fn apply_distro_target(&mut self, target: &str) -> Result<&'static str> {
        let baseline = lookup_distro(target).ok_or_else(|| {
            BincompatError::InvalidArgument(format!(
                "unknown --target '{target}' (supported: {})",
                supported_target_ids().join(", ")
            ))
        })?;
        let glibc = Version::parse(baseline.glibc).expect("valid static glibc version");
        let glibcxx = Version::parse(baseline.glibcxx).expect("valid static glibcxx version");
        self.set_min_max_version("GLIBC", glibc);
        self.set_min_max_version("GLIBCXX", glibcxx);
        if !baseline.supports_dt_relr {
            self.forbid_abi_tags.insert("GLIBC_ABI_DT_RELR".to_string());
        }
        Ok(baseline.id)
    }

    fn set_min_max_version(&mut self, family: &str, version: Version) {
        match self.max_versions.get(family) {
            Some(existing) if existing <= &version => {}
            _ => {
                self.max_versions.insert(family.to_string(), version);
            }
        }
    }

    /// Enables standard Linux binary hardening checks: PIE, full RELRO, NX stack,
    /// and stack canary.
    pub fn enable_standard_hardening(&mut self) {
        self.require_pie = true;
        self.require_nx = true;
        self.min_relro = Some(RelroStatus::Full);
        self.require_canary = true;
    }

    /// Parses a RELRO level (`partial` or `full`) for `--require-relro`.
    pub fn parse_relro_level(spec: &str) -> Result<RelroStatus> {
        match spec.to_ascii_lowercase().as_str() {
            "partial" => Ok(RelroStatus::Partial),
            "full" => Ok(RelroStatus::Full),
            _ => Err(BincompatError::InvalidArgument(format!(
                "expected 'partial' or 'full' for --require-relro, got '{spec}'"
            ))),
        }
    }

    /// Parses a `PREFIX=VERSION` specification such as `CXXABI=1.3.11`.
    pub fn parse_max_version_spec(spec: &str) -> Result<(String, Version)> {
        let (family, ver_str) = spec.split_once('=').ok_or_else(|| {
            BincompatError::InvalidArgument(format!(
                "expected PREFIX=VERSION for --max-version, got '{spec}'"
            ))
        })?;
        if family.is_empty() {
            return Err(BincompatError::InvalidArgument(format!(
                "empty version prefix in '{spec}'"
            )));
        }
        let version = Version::parse(ver_str).ok_or_else(|| {
            BincompatError::InvalidArgument(format!(
                "invalid dotted version '{ver_str}' in '{spec}'"
            ))
        })?;
        Ok((family.to_string(), version))
    }

    /// Evaluates this policy against a parsed ELF64 binary analysis.
    pub fn evaluate(&self, analysis: &BinaryAnalysis) -> PolicyEvaluation {
        let mut violations = Vec::new();

        for req in &analysis.requirements {
            match &req.parsed {
                VersionTag::Versioned { family, version } => {
                    if let Some(max_allowed) = self.max_versions.get(family) {
                        if version > max_allowed {
                            violations.push(Violation::VersionExceeded {
                                library: req.library.clone(),
                                family: family.clone(),
                                raw_tag: req.raw_tag.clone(),
                                required: version.clone(),
                                max_allowed: max_allowed.clone(),
                                symbols: req.symbols.clone(),
                            });
                        }
                    }
                }
                VersionTag::AbiTag { raw } => {
                    if self.forbid_abi_tags.contains(raw) {
                        violations.push(Violation::ForbiddenAbiTag {
                            library: req.library.clone(),
                            tag: raw.clone(),
                            symbols: req.symbols.clone(),
                        });
                    }
                }
            }
        }

        if self.forbid_rpath {
            if let Some(rpath) = &analysis.rpath {
                violations.push(Violation::ForbiddenRpath {
                    kind: "DT_RPATH".to_string(),
                    value: rpath.clone(),
                });
            }
            if let Some(runpath) = &analysis.runpath {
                violations.push(Violation::ForbiddenRpath {
                    kind: "DT_RUNPATH".to_string(),
                    value: runpath.clone(),
                });
            }
        }

        if self.require_pie && !analysis.hardening.pie.is_position_independent() {
            violations.push(Violation::MissingPie {
                actual: analysis.hardening.pie,
            });
        }

        if let Some(required) = self.min_relro {
            if analysis.hardening.relro < required {
                violations.push(Violation::InsufficientRelro {
                    actual: analysis.hardening.relro,
                    required,
                });
            }
        }

        if self.require_nx && !analysis.hardening.nx.is_enabled() {
            violations.push(Violation::MissingNx {
                actual: analysis.hardening.nx,
            });
        }

        if self.require_canary && !analysis.hardening.stack_canary {
            violations.push(Violation::MissingStackCanary);
        }

        PolicyEvaluation {
            passed: violations.is_empty(),
            violations,
        }
    }
}

/// Individual portability or hardening policy failure with exact attribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Violation {
    VersionExceeded {
        library: String,
        family: String,
        raw_tag: String,
        required: Version,
        max_allowed: Version,
        symbols: Vec<AttributedSymbol>,
    },
    ForbiddenAbiTag {
        library: String,
        tag: String,
        symbols: Vec<AttributedSymbol>,
    },
    ForbiddenRpath {
        kind: String,
        value: String,
    },
    MissingPie {
        actual: PieStatus,
    },
    InsufficientRelro {
        actual: RelroStatus,
        required: RelroStatus,
    },
    MissingNx {
        actual: NxStatus,
    },
    MissingStackCanary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEvaluation {
    pub passed: bool,
    pub violations: Vec<Violation>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_prefix_version_specs() {
        let (fam, ver) = Policy::parse_max_version_spec("GLIBCXX=3.4.28").unwrap();
        assert_eq!(fam, "GLIBCXX");
        assert_eq!(ver, Version::parse("3.4.28").unwrap());

        assert!(Policy::parse_max_version_spec("GLIBC").is_err());
        assert!(Policy::parse_max_version_spec("=2.34").is_err());
        assert!(Policy::parse_max_version_spec("GLIBC=abc").is_err());
    }

    #[test]
    fn parses_relro_levels() {
        assert_eq!(
            Policy::parse_relro_level("partial").unwrap(),
            RelroStatus::Partial
        );
        assert_eq!(
            Policy::parse_relro_level("FULL").unwrap(),
            RelroStatus::Full
        );
        assert!(Policy::parse_relro_level("none").is_err());
        assert!(Policy::parse_relro_level("strict").is_err());
    }
}
