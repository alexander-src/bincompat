use std::collections::{BTreeMap, BTreeSet};

use crate::elf::{AttributedSymbol, BinaryAnalysis};
use crate::error::{BincompatError, Result};
use crate::version::{Version, VersionTag};

/// Portability policy enforced by `bincompat check`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    pub max_versions: BTreeMap<String, Version>,
    pub forbid_abi_tags: BTreeSet<String>,
    pub forbid_rpath: bool,
}

impl Policy {
    pub fn is_empty(&self) -> bool {
        self.max_versions.is_empty() && self.forbid_abi_tags.is_empty() && !self.forbid_rpath
    }

    pub fn set_max_version(&mut self, family: impl Into<String>, version: Version) {
        self.max_versions.insert(family.into(), version);
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

        PolicyEvaluation {
            passed: violations.is_empty(),
            violations,
        }
    }
}

/// Individual portability policy failure with exact symbol attribution.
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
}
