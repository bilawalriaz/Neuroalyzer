use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;

use fixturegen::{Layout, Options, generate};

const USAGE: &str = "usage: fixturegen <root> [--seed N] [--sessions N] [--bytes N] \
[--layouts mac,linux,windows] [--manifest <path>] [--no-insiders]";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("fixturegen: {message}");
            ExitCode::FAILURE
        }
    }
}

fn value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next().ok_or_else(|| format!("{flag} needs a value"))
}

fn number<T: FromStr>(text: &str, flag: &str) -> Result<T, String> {
    text.parse().map_err(|_| format!("{flag}: not a number: {text}"))
}

fn parse_layouts(text: &str) -> Result<Vec<Layout>, String> {
    text.split(',')
        .map(|name| match name.trim() {
            "mac" => Ok(Layout::Mac),
            "linux" => Ok(Layout::Linux),
            "windows" => Ok(Layout::Windows),
            other => Err(format!("unknown layout: {other}")),
        })
        .collect()
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let mut root: Option<PathBuf> = None;
    let mut manifest: Option<PathBuf> = None;
    let mut opts = Options::default();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--seed" => opts.seed = number(&value(&mut args, &arg)?, &arg)?,
            "--sessions" => opts.sessions_per_tool = number(&value(&mut args, &arg)?, &arg)?,
            "--bytes" => opts.target_bytes = Some(number(&value(&mut args, &arg)?, &arg)?),
            "--layouts" => opts.layouts = parse_layouts(&value(&mut args, &arg)?)?,
            "--manifest" => manifest = Some(PathBuf::from(value(&mut args, &arg)?)),
            "--no-insiders" => opts.with_insiders = false,
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(());
            }
            flag if flag.starts_with("--") => {
                return Err(format!("unknown option {flag}\n{USAGE}"));
            }
            _ => {
                if root.is_some() {
                    return Err(format!("unexpected argument {arg}\n{USAGE}"));
                }
                root = Some(PathBuf::from(arg));
            }
        }
    }

    let root = root.ok_or_else(|| USAGE.to_string())?;
    let abs_root = std::path::absolute(&root).map_err(|e| e.to_string())?;
    if let Some(path) = &manifest {
        let abs_manifest = std::path::absolute(path).map_err(|e| e.to_string())?;
        if abs_manifest.starts_with(&abs_root) {
            return Err("the manifest path must be outside the root".to_string());
        }
    }

    let result = generate(&root, &opts).map_err(|e| e.to_string())?;
    if let Some(path) = manifest {
        fs::write(&path, result.to_json()).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    println!(
        "wrote fixtures under {} ({} planted values, {} decoys, {} projects)",
        abs_root.display(),
        result.planted.len(),
        result.decoys.len(),
        result.projects.len()
    );
    Ok(())
}
