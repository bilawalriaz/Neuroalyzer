use clap::{Args, Parser, Subcommand};
use sesscrub::config::Config;
use sesscrub::password::PwArgs;
use sesscrub::run::{self, ScanOpts};
use std::path::PathBuf;
use std::process::ExitCode;

const ABOUT: &str = "Find the local session data of AI coding agents (Claude Code, Codex, Gemini CLI, GitHub Copilot, OpenCode, Hermes Agent, OpenClaw, Factory Droid, pi, omp), back it up encrypted, and redact secrets and personal data in place.";

const AFTER_HELP: &str = "Exit codes: 0 = clean, 1 = scan found something, 2 = error.

Start with `sesscrub list`, then `sesscrub scan`. To try it on a copy first, copy your home-dir session folders into a directory and pass it with --root.";

#[derive(Parser)]
#[command(name = "sesscrub", version, about = ABOUT, after_help = AFTER_HELP)]
struct Cli {
    /// More detail (repeat for more).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,
    /// Only print errors and the final result.
    #[arg(short, long, global = true)]
    quiet: bool,
    /// Turn off coloured output.
    #[arg(long, global = true)]
    no_color: bool,
    /// Use this config file instead of the default one.
    #[arg(long, global = true, value_name = "FILE")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args, Clone)]
struct Common {
    /// Only these tools, comma-separated: copilot, opencode, omp, claude, codex, gemini, hermes, openclaw, droid, pi.
    #[arg(long, value_delimiter = ',', value_name = "TOOLS")]
    only: Vec<String>,
    /// Look for session data under this dir instead of your home dir. Use it to test on a copy.
    #[arg(long, value_name = "DIR")]
    root: Option<PathBuf>,
    /// Also scan this file or directory (repeatable).
    #[arg(long, value_name = "PATH")]
    also: Vec<PathBuf>,
    /// Find names, addresses and organisations with the NER model.
    #[arg(long, overrides_with = "no_ner")]
    ner: bool,
    /// Don't use the NER model.
    #[arg(long, overrides_with = "ner")]
    no_ner: bool,
    /// Print the report as JSON on stdout instead of writing report files.
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show which tools were found, where, how much data, and past backups.
    List {
        #[arg(long, value_delimiter = ',', value_name = "TOOLS")]
        only: Vec<String>,
        #[arg(long, value_name = "DIR")]
        root: Option<PathBuf>,
        #[arg(long, value_name = "PATH")]
        also: Vec<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Report what would be redacted. Changes nothing except writing the report.
    Scan {
        #[command(flatten)]
        common: Common,
    },
    /// Back up the affected files (encrypted), then redact them in place.
    Clean {
        #[command(flatten)]
        common: Common,
        /// Don't ask for confirmation.
        #[arg(short, long)]
        yes: bool,
        /// How many backups to keep.
        #[arg(long, value_name = "N")]
        keep: Option<usize>,
        /// Skip files modified less than this many seconds ago.
        #[arg(long, default_value_t = 120, value_name = "SECS")]
        min_age: u64,
        #[command(flatten)]
        pw: PwArgs,
    },
    /// Put files back from a backup. With no name, lists the backups.
    Restore {
        /// Backup name (or a unique prefix) or path.
        archive: Option<String>,
        /// Overwrite files that changed since they were cleaned, without asking.
        #[arg(long)]
        force: bool,
        #[command(flatten)]
        pw: PwArgs,
    },
    /// Store or remove the backup password in the OS keychain.
    Key {
        #[command(subcommand)]
        cmd: KeyCmd,
    },
    /// Manage the NER model.
    Model {
        #[command(subcommand)]
        cmd: ModelCmd,
    },
}

#[derive(Subcommand)]
enum KeyCmd {
    /// Save the backup password to the OS keychain.
    Save {
        #[command(flatten)]
        pw: PwArgs,
    },
    /// Remove the saved backup password.
    Clear,
}

#[derive(Subcommand)]
enum ModelCmd {
    /// Download the NER model now, so later runs work offline.
    Fetch,
}

fn ner_default(c: &Common, cfg: &Config) -> bool {
    if c.no_ner {
        false
    } else if c.ner {
        true
    } else {
        cfg.defaults.ner.unwrap_or(cfg!(feature = "ner"))
    }
}

fn opts(c: &Common, cfg: &Config, cli: &Cli, min_age: u64) -> ScanOpts {
    ScanOpts {
        only: c.only.clone(),
        root: c.root.clone(),
        also: c.also.clone(),
        ner: ner_default(c, cfg),
        json: c.json,
        min_age,
        quiet: cli.quiet,
        verbose: cli.verbose,
    }
}

fn real_main(cli: Cli) -> anyhow::Result<i32> {
    if cli.no_color || std::env::var_os("NO_COLOR").is_some() {
        console::set_colors_enabled(false);
        console::set_colors_enabled_stderr(false);
    }
    let (cfg, cfg_path) = Config::load(cli.config.as_deref())?;
    if cli.verbose > 0
        && let Some(p) = &cfg_path
    {
        eprintln!("Using config {}", p.display());
    }
    match &cli.cmd {
        Cmd::List { only, root, also, json } => {
            let o = ScanOpts {
                only: only.clone(),
                root: root.clone(),
                also: also.clone(),
                json: *json,
                ..Default::default()
            };
            run::list(&o, &cfg)
        }
        Cmd::Scan { common } => run::scan(&opts(common, &cfg, &cli, 0), &cfg),
        Cmd::Clean {
            common,
            yes,
            keep,
            min_age,
            pw,
        } => {
            let keep = keep.or(cfg.defaults.keep).unwrap_or(5);
            run::clean(&opts(common, &cfg, &cli, *min_age), &cfg, *yes, keep, pw)
        }
        Cmd::Restore { archive, force, pw } => run::restore(archive.clone(), *force, pw, cli.quiet),
        Cmd::Key {
            cmd: KeyCmd::Save { pw },
        } => sesscrub::password::key_save(pw).map(|_| 0),
        Cmd::Key { cmd: KeyCmd::Clear } => sesscrub::password::key_clear().map(|_| 0),
        Cmd::Model { cmd: ModelCmd::Fetch } => sesscrub::ner::fetch(cli.quiet).map(|_| 0),
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match real_main(cli) {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("{} {e:#}", console::style("error:").red().bold());
            ExitCode::from(2)
        }
    }
}
