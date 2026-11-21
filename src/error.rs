use std::fmt;
use std::io;
use std::path::PathBuf;

/// Structured errors returned by `bincompat` ELF parsing, policy parsing, and I/O.
#[derive(Debug)]
pub enum BincompatError {
    Io { path: PathBuf, source: io::Error },
    InvalidElf(String),
    UnsupportedClass(u8),
    UnsupportedEndianness(u8),
    CorruptSection(String),
    CorruptDynamic(String),
    CorruptVerneed(String),
    InvalidArgument(String),
}

impl fmt::Display for BincompatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "failed to read '{}': {}", path.display(), source)
            }
            Self::InvalidElf(msg) => write!(f, "invalid ELF file: {msg}"),
            Self::UnsupportedClass(class) => {
                write!(
                    f,
                    "unsupported ELF class {class} (only ELF64 / class 2 is supported)"
                )
            }
            Self::UnsupportedEndianness(data) => {
                write!(
                    f,
                    "unsupported ELF data encoding {data} (expected little-endian 1 or big-endian 2)"
                )
            }
            Self::CorruptSection(msg) => write!(f, "corrupt ELF section table: {msg}"),
            Self::CorruptDynamic(msg) => write!(f, "corrupt ELF dynamic section: {msg}"),
            Self::CorruptVerneed(msg) => write!(f, "corrupt GNU version-need table: {msg}"),
            Self::InvalidArgument(msg) => write!(f, "invalid argument: {msg}"),
        }
    }
}

impl std::error::Error for BincompatError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, BincompatError>;
