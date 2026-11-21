use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};

/// Numeric dotted version (for example `2.38`, `3.4.30`, `2.2.5`).
///
/// Comparisons normalize trailing zeros so `2.3` equals `2.3.0` while
/// `Display` preserves the original parsed components.
#[derive(Debug, Clone)]
pub struct Version {
    parts: Vec<u32>,
}

impl Version {
    /// Parses a dotted unsigned integer version string (for example `"2.34"` or `"3.4.30"`).
    pub fn parse(input: &str) -> Option<Self> {
        if input.is_empty() {
            return None;
        }
        let mut parts = Vec::new();
        for seg in input.split('.') {
            if seg.is_empty() || !seg.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let value = seg.parse::<u32>().ok()?;
            parts.push(value);
        }
        if parts.is_empty() {
            return None;
        }
        Some(Self { parts })
    }

    pub fn parts(&self) -> &[u32] {
        &self.parts
    }

    fn normalized_slice(&self) -> &[u32] {
        let mut end = self.parts.len();
        while end > 1 && self.parts[end - 1] == 0 {
            end -= 1;
        }
        &self.parts[..end]
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.normalized_slice() == other.normalized_slice()
    }
}

impl Eq for Version {}

impl Hash for Version {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.normalized_slice().hash(state);
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        let max_len = self.parts.len().max(other.parts.len());
        for idx in 0..max_len {
            let lhs = self.parts.get(idx).copied().unwrap_or(0);
            let rhs = other.parts.get(idx).copied().unwrap_or(0);
            match lhs.cmp(&rhs) {
                Ordering::Equal => continue,
                ord => return ord,
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (idx, part) in self.parts.iter().enumerate() {
            if idx > 0 {
                f.write_str(".")?;
            }
            write!(f, "{part}")?;
        }
        Ok(())
    }
}

/// Classification of a GNU symbol-version tag from `.gnu.version_r`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionTag {
    /// Numeric versioned requirement such as `GLIBC_2.38` or `GLIBCXX_3.4.30`.
    Versioned { family: String, version: Version },
    /// Non-numeric ABI or private tag such as `GLIBC_ABI_DT_RELR` or `GLIBC_PRIVATE`.
    AbiTag { raw: String },
}

impl VersionTag {
    /// Parses a raw GNU version string into either a numeric `(family, Version)`
    /// pair or a non-numeric `AbiTag`.
    pub fn parse(raw: &str) -> Self {
        if let Some((prefix, suffix)) = raw.rsplit_once('_') {
            if !prefix.is_empty() {
                if let Some(version) = Version::parse(suffix) {
                    return Self::Versioned {
                        family: prefix.to_string(),
                        version,
                    };
                }
            }
        }
        Self::AbiTag {
            raw: raw.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_numeric_versions_not_lexicographically() {
        let v_old = Version::parse("2.4").unwrap();
        let v_new = Version::parse("2.34").unwrap();
        assert!(v_new > v_old);

        let v_2_2_5 = Version::parse("2.2.5").unwrap();
        let v_2_3 = Version::parse("2.3").unwrap();
        assert!(v_2_3 > v_2_2_5);

        let v_2_3_0 = Version::parse("2.3.0").unwrap();
        assert_eq!(v_2_3, v_2_3_0);
        assert_eq!(v_2_3.cmp(&v_2_3_0), Ordering::Equal);
    }

    #[test]
    fn parses_numeric_and_abi_version_tags() {
        assert_eq!(
            VersionTag::parse("GLIBC_2.38"),
            VersionTag::Versioned {
                family: "GLIBC".to_string(),
                version: Version::parse("2.38").unwrap(),
            }
        );
        assert_eq!(
            VersionTag::parse("GLIBCXX_3.4.32"),
            VersionTag::Versioned {
                family: "GLIBCXX".to_string(),
                version: Version::parse("3.4.32").unwrap(),
            }
        );
        assert_eq!(
            VersionTag::parse("GLIBC_ABI_DT_RELR"),
            VersionTag::AbiTag {
                raw: "GLIBC_ABI_DT_RELR".to_string(),
            }
        );
        assert_eq!(
            VersionTag::parse("GLIBC_PRIVATE"),
            VersionTag::AbiTag {
                raw: "GLIBC_PRIVATE".to_string(),
            }
        );
    }
}
