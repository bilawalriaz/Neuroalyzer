use clap::{Args, Parser, Subcommand};
use neuroalyzer::config::Config;
use neuroalyzer::password::PwArgs;
use neuroalyzer::run::{self, ScanOpts};
use std::path::PathBuf;
use std::process::ExitCode;

const ABOUT: &str = "Find the local session data of AI coding agents (Claude Code, Codex, Gemini CLI, GitHub Copilot, OpenCode, Hermes Agent, OpenClaw, Factory Droid, pi, omp), back it up encrypted, and redact secrets and personal data in place.";

const AFTER_HELP: &str = "Exit codes: 0 = clean, 1 = scan found something, 2 = error.

Start with `neuroalyzer list`, then `neuroalyzer scan`. To try it on a copy first, copy your home-dir session folders into a directory and pass it with --root.";

#[derive(Parser)]
#[command(name = "neuroalyzer", version, about = ABOUT, after_help = AFTER_HELP)]
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
    /// CPU threads to use: a number, max, half or p-cores. Default: auto.
    #[arg(short = 'j', long = "threads", global = true, value_name = "N")]
    threads: Option<String>,
    /// Run at low priority so the machine stays usable (background QoS on macOS, nice on Linux).
    #[arg(long, global = true)]
    low_priority: bool,
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
    /// Parallel NER workers. Default: one per performance core.
    #[arg(long, value_name = "N")]
    ner_sessions: Option<usize>,
    /// Threads per NER worker. Default: 1.
    #[arg(long, value_name = "N")]
    ner_threads: Option<usize>,
    /// Chunks per NER model call. Default: 1.
    #[arg(long, value_name = "N")]
    ner_batch: Option<usize>,
    /// Where NER runs: auto, cpu, coreml, cuda or directml (the last three need a build with that feature).
    #[arg(long, value_name = "DEVICE")]
    ner_device: Option<String>,
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

/// First of: flag, `<PKG>_<env>` variable, config value. Parse errors name the source.
fn pick<T: std::str::FromStr>(flag: Option<T>, env: &str, cfg: Option<T>) -> anyhow::Result<Option<T>>
where
    T::Err: std::fmt::Display,
{
    if flag.is_some() {
        return Ok(flag);
    }
    if let Some(v) = neuroalyzer::paths::env_value(env) {
        return v
            .trim()
            .parse()
            .map(Some)
            .map_err(|e| anyhow::anyhow!("{}={v}: {e}", neuroalyzer::paths::env_name(env)));
    }
    Ok(cfg)
}

fn ner_runtime(c: &Common, cfg: &Config) -> anyhow::Result<neuroalyzer::ner::Runtime> {
    use neuroalyzer::ner::{Device, Runtime};
    let cores = neuroalyzer::hw::detect();
    let mut auto = Runtime::auto(&cores);
    // Stay inside the -j budget (the scan pool is sized before this runs).
    auto.sessions = auto.sessions.min(rayon::current_num_threads()).max(1);
    let device = match pick(c.ner_device.clone(), "NER_DEVICE", cfg.ner.device.clone())? {
        Some(d) => d.parse::<Device>().map_err(|e| anyhow::anyhow!(e))?,
        None => auto.device,
    };
    let positive = |name: &str, v: Option<usize>| -> anyhow::Result<Option<usize>> {
        match v {
            Some(0) => anyhow::bail!("{name} must be at least 1"),
            v => Ok(v),
        }
    };
    let threads = positive("NER threads", pick(c.ner_threads, "NER_THREADS", cfg.ner.threads)?)?;
    // With more threads per worker, default to fewer workers so the total
    // stays on the performance cores.
    let sessions = positive("NER sessions", pick(c.ner_sessions, "NER_SESSIONS", cfg.ner.sessions)?)?
        .unwrap_or_else(|| (auto.sessions / threads.unwrap_or(auto.threads)).max(1));
    Ok(Runtime {
        sessions,
        threads: threads.unwrap_or(auto.threads),
        batch: positive("NER batch", pick(c.ner_batch, "NER_BATCH", cfg.ner.batch)?)?.unwrap_or(auto.batch),
        device,
    })
}

fn opts(c: &Common, cfg: &Config, cli: &Cli, min_age: u64) -> anyhow::Result<ScanOpts> {
    Ok(ScanOpts {
        ner_rt: Some(ner_runtime(c, cfg)?),
        only: c.only.clone(),
        root: c.root.clone(),
        also: c.also.clone(),
        ner: ner_default(c, cfg),
        json: c.json,
        min_age,
        quiet: cli.quiet,
        verbose: cli.verbose,
    })
}

/// Size the scan pool and set priority before any worker threads start.
fn setup_threads(cli: &Cli, cfg: &Config) -> anyhow::Result<()> {
    use neuroalyzer::hw::Budget;
    let low = cli.low_priority || pick(None::<bool>, "LOW_PRIORITY", cfg.defaults.low_priority)?.unwrap_or(false);
    if low {
        neuroalyzer::hw::lower_priority();
    }
    let budget = pick(cli.threads.clone(), "THREADS", cfg.defaults.threads.clone())?
        .map(|s| s.parse::<Budget>().map_err(|e| anyhow::anyhow!("--threads: {e}")))
        .transpose()?
        .unwrap_or(Budget::Auto);
    let cores = neuroalyzer::hw::detect();
    let n = budget.threads(&cores);
    // Ignore "already built": tests and library users may have set it up.
    let _ = rayon::ThreadPoolBuilder::new().num_threads(n).build_global();
    Ok(())
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
    setup_threads(&cli, &cfg)?;
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
        Cmd::Scan { common } => run::scan(&opts(common, &cfg, &cli, 0)?, &cfg),
        Cmd::Clean {
            common,
            yes,
            keep,
            min_age,
            pw,
        } => {
            let keep = keep.or(cfg.defaults.keep).unwrap_or(5);
            run::clean(&opts(common, &cfg, &cli, *min_age)?, &cfg, *yes, keep, pw)
        }
        Cmd::Restore { archive, force, pw } => run::restore(archive.clone(), *force, pw, cli.quiet),
        Cmd::Key {
            cmd: KeyCmd::Save { pw },
        } => neuroalyzer::password::key_save(pw).map(|_| 0),
        Cmd::Key { cmd: KeyCmd::Clear } => neuroalyzer::password::key_clear().map(|_| 0),
        Cmd::Model { cmd: ModelCmd::Fetch } => neuroalyzer::ner::fetch(cli.quiet).map(|_| 0),
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
