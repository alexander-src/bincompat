#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use bincompat::{
    analyze_file, render_check_text, render_scan_text, BincompatError, Policy, Result, Version,
};

const VERSION_STR: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "\
bincompat - Zero-dependency ELF64 Linux binary portability CI gate

USAGE:
  bincompat scan <path>
  bincompat check <path> [options]
  bincompat --help | --version

CHECK OPTIONS:
  --max-glibc <VER>            Fail if any symbol requires GLIBC > VER (e.g. 2.28)
  --max-glibcxx <VER>          Fail if any symbol requires GLIBCXX > VER (e.g. 3.4.28)
  --max-version <PREFIX=VER>   Fail if PREFIX version exceeds VER (repeatable)
  --forbid-abi-tag <TAG>       Fail if ABI tag appears in .gnu.version_r (repeatable)
  --forbid-rpath               Fail if DT_RPATH or DT_RUNPATH is present

EXIT CODES:
  0  Scan succeeded or policy check passed
  1  Policy check failed (violations reported)
  2  Usage, I/O, or ELF parsing error
";

enum Command {
    Help,
    Version,
    Scan { path: PathBuf },
    Check { path: PathBuf, policy: Policy },
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(2)
        }
    }
}

fn run(args: &[String]) -> Result<u8> {
    match parse_args(args)? {
        Command::Help => {
            print!("{USAGE}");
            Ok(0)
        }
        Command::Version => {
            println!("bincompat {VERSION_STR}");
            Ok(0)
        }
        Command::Scan { path } => {
            let analysis = analyze_file(&path)?;
            let label = path.display().to_string();
            print!("{}", render_scan_text(&label, &analysis));
            Ok(0)
        }
        Command::Check { path, policy } => {
            let analysis = analyze_file(&path)?;
            let eval = policy.evaluate(&analysis);
            let label = path.display().to_string();
            print!("{}", render_check_text(&label, &analysis, &policy, &eval));
            Ok(if eval.passed { 0 } else { 1 })
        }
    }
}

fn parse_args(args: &[String]) -> Result<Command> {
    if args.is_empty() {
        return Err(BincompatError::InvalidArgument(
            "missing subcommand (expected 'scan' or 'check'; run --help for usage)".to_string(),
        ));
    }

    match args[0].as_str() {
        "-h" | "--help" | "help" => Ok(Command::Help),
        "-V" | "--version" => Ok(Command::Version),
        "scan" => {
            if args.len() == 2 && (args[1] == "-h" || args[1] == "--help") {
                return Ok(Command::Help);
            }
            if args.len() != 2 {
                return Err(BincompatError::InvalidArgument(
                    "usage: bincompat scan <path>".to_string(),
                ));
            }
            Ok(Command::Scan {
                path: PathBuf::from(&args[1]),
            })
        }
        "check" => parse_check_args(&args[1..]),
        other => Err(BincompatError::InvalidArgument(format!(
            "unknown subcommand '{other}' (expected 'scan' or 'check')"
        ))),
    }
}

fn parse_check_args(args: &[String]) -> Result<Command> {
    let mut path: Option<PathBuf> = None;
    let mut policy = Policy::default();
    let mut idx = 0usize;

    while idx < args.len() {
        match args[idx].as_str() {
            "-h" | "--help" => return Ok(Command::Help),
            "--max-glibc" => {
                let raw = next_value(args, &mut idx, "--max-glibc")?;
                let ver = Version::parse(raw).ok_or_else(|| {
                    BincompatError::InvalidArgument(format!("invalid GLIBC version '{raw}'"))
                })?;
                policy.set_max_version("GLIBC", ver);
            }
            "--max-glibcxx" => {
                let raw = next_value(args, &mut idx, "--max-glibcxx")?;
                let ver = Version::parse(raw).ok_or_else(|| {
                    BincompatError::InvalidArgument(format!("invalid GLIBCXX version '{raw}'"))
                })?;
                policy.set_max_version("GLIBCXX", ver);
            }
            "--max-version" => {
                let raw = next_value(args, &mut idx, "--max-version")?;
                let (family, ver) = Policy::parse_max_version_spec(raw)?;
                policy.set_max_version(family, ver);
            }
            "--forbid-abi-tag" => {
                let raw = next_value(args, &mut idx, "--forbid-abi-tag")?;
                if raw.is_empty() {
                    return Err(BincompatError::InvalidArgument(
                        "--forbid-abi-tag requires a non-empty tag".to_string(),
                    ));
                }
                policy.forbid_abi_tags.insert(raw.to_string());
            }
            "--forbid-rpath" => {
                policy.forbid_rpath = true;
            }
            flag if flag.starts_with('-') => {
                return Err(BincompatError::InvalidArgument(format!(
                    "unknown option '{flag}'"
                )));
            }
            positional => {
                if path.is_some() {
                    return Err(BincompatError::InvalidArgument(format!(
                        "unexpected extra positional argument '{positional}'"
                    )));
                }
                path = Some(PathBuf::from(positional));
            }
        }
        idx += 1;
    }

    let path = path.ok_or_else(|| {
        BincompatError::InvalidArgument("usage: bincompat check <path> [options]".to_string())
    })?;
    if policy.is_empty() {
        return Err(BincompatError::InvalidArgument(
            "check requires at least one constraint (--max-glibc, --max-glibcxx, --max-version, --forbid-abi-tag, or --forbid-rpath)"
                .to_string(),
        ));
    }
    Ok(Command::Check { path, policy })
}

fn next_value<'a>(args: &'a [String], idx: &mut usize, flag: &str) -> Result<&'a str> {
    *idx += 1;
    args.get(*idx)
        .map(String::as_str)
        .ok_or_else(|| BincompatError::InvalidArgument(format!("option '{flag}' requires a value")))
}
