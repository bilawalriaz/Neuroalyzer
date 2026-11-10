//! `scan` and `clean` orchestration.

use crate::backup::{self, Source};
use crate::config::Config;
use crate::detect::Detectors;
use crate::discovery::{self, Env, Format, Job};
use crate::engine::{Engine, Outcome};
use crate::fsutil;
use crate::password::{self, Purpose, PwArgs};
use crate::report::{self, Engines, FileReport, Report};
use crate::sqlite::{self, SqlResult};
use crate::token::Tokenizer;
use anyhow::{Result, bail};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Default)]
pub struct ScanOpts {
    /// NER runtime plan (sessions, threads, batch, device).
    pub ner_rt: Option<crate::ner::Runtime>,
    pub only: Vec<String>,
    pub root: Option<PathBuf>,
    pub also: Vec<PathBuf>,
    pub ner: bool,
    pub json: bool,
    pub min_age: u64,
    pub quiet: bool,
    pub verbose: u8,
}

fn bar(len: u64, msg: &str, quiet: bool) -> ProgressBar {
    if quiet || !std::io::stderr().is_terminal() {
        return ProgressBar::hidden();
    }
    let pb = ProgressBar::new(len);
    pb.set_style(
        ProgressStyle::with_template("{msg:>10} [{bar:30}] {bytes}/{total_bytes} {bytes_per_sec} eta {eta}")
            .unwrap()
            .progress_chars("=> "),
    );
    pb.set_message(msg.to_string());
    pb
}

pub struct Prepared {
    pub engine: Engine,
    pub jobs: Vec<Job>,
    pub engines: Engines,
    pub notes: Vec<String>,
}

pub fn prepare(opts: &ScanOpts, cfg: &Config, writing: bool) -> Result<Prepared> {
    let env = Env::new(opts.root.as_deref());
    let mut also = cfg.defaults.also.clone();
    also.extend(opts.also.iter().cloned());
    let only = if opts.only.is_empty() {
        cfg.defaults.only.clone().unwrap_or_default()
    } else {
        opts.only.clone()
    };
    for o in &only {
        if !discovery::TOOLS.iter().any(|(t, _)| t.eq_ignore_ascii_case(o)) {
            bail!(
                "unknown tool '{o}' in --only. Known tools: {}",
                discovery::TOOLS.iter().map(|t| t.0).collect::<Vec<_>>().join(", ")
            );
        }
    }
    let d = discovery::discover(&env, &only, &also);
    let dirs = crate::known::project_dirs(&d.jobs, opts.root.as_deref());
    let known = crate::known::collect(&dirs);
    let det = Detectors::new(cfg, &known)?;
    let data = crate::paths::data_dir();
    let tok = if writing || data.join("hmac.key").exists() {
        Tokenizer::load_or_create(&data)?
    } else {
        Tokenizer::ephemeral()
    };
    let (n, skipped, ver) = det.rule_stats();
    let mut engines = Engines {
        gitleaks_version: ver.into(),
        gitleaks_rules: n,
        gitleaks_rules_skipped: skipped,
        known_values: det.known_count(),
        ..Default::default()
    };
    let ner = if opts.ner {
        let cores = crate::hw::detect();
        let rt = opts.ner_rt.unwrap_or_else(|| crate::ner::Runtime::auto(&cores));
        match crate::ner::Ner::load(&cfg.ner, rt, opts.quiet) {
            Ok(n) => {
                engines.ner = true;
                if opts.verbose > 0 && !opts.quiet {
                    eprintln!(
                        "plan: {cores}; scan pool {} threads; NER {}",
                        rayon::current_num_threads(),
                        n.describe()
                    );
                }
                Some(n)
            }
            Err(e) => {
                engines.ner_note = Some(format!("not used: {e:#}"));
                None
            }
        }
    } else {
        engines.ner_note = Some("off".into());
        None
    };
    if engines.ner_note.as_deref() == Some("off") {
        engines.ner_note = None;
    }
    Ok(Prepared {
        engine: Engine { det, tok, ner },
        jobs: d.jobs,
        engines,
        notes: d.notes,
    })
}

fn fmt_name(f: Format) -> &'static str {
    match f {
        Format::Json => "json",
        Format::Jsonl => "jsonl",
        Format::Sqlite => "sqlite",
        Format::Text => "text",
        Format::JsonlZst => "jsonl.zst",
    }
}

fn file_report(job: &Job, o: &Outcome, modified: bool, skipped: Option<String>) -> FileReport {
    FileReport {
        path: job.path.display().to_string(),
        format: fmt_name(job.format).into(),
        bytes: job.size,
        findings: report::counts_vec(&o.counts),
        modified,
        skipped,
        drift: o.drift.clone(),
    }
}

/// Analyse one file without writing. Returns the outcome or a skip reason.
fn analyse(engine: &Engine, job: &Job, min_age: Option<Duration>) -> std::result::Result<Outcome, String> {
    if let Some(age) = min_age
        && let Some(r) = fsutil::active_reason(&job.path, job.format == Format::Sqlite, age)
    {
        return Err(r);
    }
    match job.format {
        Format::Sqlite => match sqlite::process(engine, job, false) {
            Ok(SqlResult::Done(o)) => Ok(o),
            Ok(SqlResult::Busy) => Err("active: database is locked".into()),
            Ok(SqlResult::Changed(r)) => Err(r),
            Err(e) => Err(format!("error: {e:#}")),
        },
        _ => match fsutil::read(&job.path) {
            Ok(b) => Ok(engine.analyse_bytes(job, &b)),
            Err(e) => Err(format!("error: {e:#}")),
        },
    }
}

fn ner_stats(p: &Prepared, e: &mut Engines) {
    if let Some(n) = &p.engine.ner {
        let (inf, hits) = n.stats();
        e.ner_chunks_inferred = inf;
        e.ner_cache_hits = hits;
    }
}

fn emit(report: &Report, opts: &ScanOpts, notes: &[String]) -> Result<()> {
    if !opts.quiet {
        for n in notes {
            eprintln!("note: {n}");
        }
        report.print_summary();
    }
    if opts.json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else {
        let (j, m) = report.write_files(&crate::paths::reports_dir())?;
        if !opts.quiet {
            eprintln!("\n  Report          {}\n                  {}", j.display(), m.display());
        }
    }
    Ok(())
}

/// Rough work estimate for scheduling: zstd files are scanned decompressed.
fn job_cost(job: &Job) -> u64 {
    match job.format {
        Format::JsonlZst => job.size.saturating_mul(8),
        _ => job.size,
    }
}

/// Run `f` over every job on the rayon pool, biggest first, and return the
/// results in job order. A huge file started last leaves one core busy while
/// the rest idle; started first, it overlaps with everything else.
fn map_jobs<T: Send>(jobs: &[Job], f: impl Fn(&Job) -> T + Sync) -> Vec<T> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let mut order: Vec<usize> = (0..jobs.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(job_cost(&jobs[i])));
    let slots: Vec<Mutex<Option<T>>> = jobs.iter().map(|_| Mutex::new(None)).collect();
    let next = AtomicUsize::new(0);
    rayon::scope(|s| {
        for _ in 0..rayon::current_num_threads().min(jobs.len()) {
            s.spawn(|_| {
                loop {
                    let k = next.fetch_add(1, Ordering::Relaxed);
                    let Some(&i) = order.get(k) else { break };
                    let r = f(&jobs[i]);
                    *slots[i].lock().unwrap() = Some(r);
                }
            });
        }
    });
    slots
        .into_iter()
        .map(|m| m.into_inner().unwrap().expect("every job ran"))
        .collect()
}

fn ner_bar(quiet: bool) -> ProgressBar {
    if quiet || !std::io::stderr().is_terminal() {
        return ProgressBar::hidden();
    }
    let pb = ProgressBar::new(0);
    pb.set_style(
        ProgressStyle::with_template("{prefix:>10} [{bar:30}] {msg} eta {eta}")
            .unwrap()
            .progress_chars("=> "),
    );
    pb.set_prefix("NER");
    pb
}

/// Corpus-wide NER before analysis: collect every uncached prose chunk from
/// all files (deduplicated), infer them on the worker pool, then let the
/// normal analysis find every chunk in the cache. Repeats in rounds if the
/// collected text outgrows its memory budget.
fn ner_pass(p: &Prepared, min_age: Option<Duration>, opts: &ScanOpts) {
    let Some(ner) = &p.engine.ner else { return };
    let total: u64 = p.jobs.iter().map(|j| j.size).sum();
    loop {
        let pb = bar(total, "reading", opts.quiet);
        ner.begin_collect();
        map_jobs(&p.jobs, |job| {
            let _ = analyse(&p.engine, job, min_age);
            pb.inc(job.size);
        });
        let pending = ner.end_collect();
        pb.finish_and_clear();
        let (n, complete) = (pending.chunks.len(), pending.complete);
        if opts.verbose > 0 && !opts.quiet {
            eprintln!("NER: {n} new unique chunks to infer");
        }
        let before = ner.stats().0;
        let ipb = ner_bar(opts.quiet);
        ner.infer_all(pending, &ipb);
        ipb.finish_and_clear();
        // Stop when done, or when a round made no progress (every chunk failed).
        if complete || n == 0 || ner.stats().0 == before {
            break;
        }
    }
}

pub fn scan(opts: &ScanOpts, cfg: &Config) -> Result<i32> {
    let started = chrono::Local::now();
    let t0 = Instant::now();
    let p = prepare(opts, cfg, false)?;
    ner_pass(&p, None, opts);
    let total: u64 = p.jobs.iter().map(|j| j.size).sum();
    let pb = bar(total, "scanning", opts.quiet);
    let results: Vec<(String, FileReport)> = map_jobs(&p.jobs, |job| {
        let r = match analyse(&p.engine, job, None) {
            Ok(o) => file_report(job, &o, false, None),
            Err(reason) => file_report(job, &Outcome::default(), false, Some(reason)),
        };
        pb.inc(job.size);
        (job.tool.to_string(), r)
    });
    pb.finish_and_clear();
    let mut engines = p.engines.clone();
    ner_stats(&p, &mut engines);
    let report = Report::build("scan", started, t0.elapsed().as_secs_f64(), results, engines, None);
    emit(&report, opts, &p.notes)?;
    Ok(if report.total_findings() > 0 { 1 } else { 0 })
}

fn confirm(question: &str) -> Result<bool> {
    if !std::io::stdin().is_terminal() {
        bail!("can't ask for confirmation without a terminal. Re-run with --yes to proceed.");
    }
    eprint!("{question} [y/N] ");
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    Ok(matches!(s.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
}

pub fn clean(opts: &ScanOpts, cfg: &Config, yes: bool, keep: usize, pw_args: &PwArgs) -> Result<i32> {
    let _lock = crate::paths::lock_data_dir()?;
    let mut exit = 0;
    let started = chrono::Local::now();
    let t0 = Instant::now();
    let p = prepare(opts, cfg, true)?;
    let min_age = Duration::from_secs(opts.min_age);
    ner_pass(&p, Some(min_age), opts);
    let total: u64 = p.jobs.iter().map(|j| j.size).sum();
    let pb = bar(total, "scanning", opts.quiet);
    let first: Vec<(usize, std::result::Result<Outcome, String>)> = map_jobs(&p.jobs, |job| {
        let r = analyse(&p.engine, job, Some(min_age));
        pb.inc(job.size);
        r
    })
    .into_iter()
    .enumerate()
    .collect();
    pb.finish_and_clear();

    let mut reports: BTreeMap<usize, FileReport> = BTreeMap::new();
    let mut candidates: Vec<usize> = vec![];
    for (i, r) in &first {
        let job = &p.jobs[*i];
        match r {
            Ok(o) => {
                if o.would_change {
                    candidates.push(*i);
                }
                reports.insert(*i, file_report(job, o, false, None));
            }
            Err(reason) => {
                reports.insert(*i, file_report(job, &Outcome::default(), false, Some(reason.clone())));
            }
        }
    }
    let mut archive: Option<PathBuf> = None;
    if !candidates.is_empty() {
        let findings: u64 = candidates
            .iter()
            .map(|i| reports[i].findings.iter().map(|c| c.count).sum::<u64>())
            .sum();
        if !opts.quiet {
            eprintln!("Found {findings} item(s) to redact in {} file(s).", candidates.len());
        }
        if !yes && !confirm(&format!("Back up and redact {} file(s)?", candidates.len()))? {
            eprintln!("Nothing changed.");
            return Ok(0);
        }
        let pw = password::resolve(pw_args, Purpose::Clean, opts.quiet)?;
        // Build backup sources: each file plus SQLite companions.
        let mut sources = vec![];
        for (g, &i) in candidates.iter().enumerate() {
            let job = &p.jobs[i];
            sources.push(Source {
                group: g,
                role: "main",
                tool: job.tool.into(),
                path: job.path.clone(),
            });
            if job.format == Format::Sqlite {
                for (suf, role) in [("-wal", "wal"), ("-journal", "journal")] {
                    let c = PathBuf::from(format!("{}{suf}", job.path.display()));
                    if c.is_file() {
                        sources.push(Source {
                            group: g,
                            role,
                            tool: job.tool.into(),
                            path: c,
                        });
                    }
                }
            }
        }
        let bytes: u64 = sources
            .iter()
            .filter_map(|s| std::fs::metadata(&s.path).ok())
            .map(|m| m.len())
            .sum();
        let pb = bar(bytes, "backing up", opts.quiet);
        let (apath, manifest) = backup::create(&sources, &pw, &crate::paths::archives_dir(), &pb)?;
        pb.finish_and_clear();
        if !opts.quiet {
            eprintln!("Backup written and verified: {}", apath.display());
        }
        // From here until the sidecar is written, after-hashes go to the
        // journal before each file is replaced, so an interrupted run can
        // still be restored without --force.
        let journal = backup::Journal::create(&apath)?;
        // Redact.
        let after = Mutex::new(BTreeMap::<String, Option<String>>::new());
        let pb = bar(
            candidates.iter().map(|&i| p.jobs[i].size).sum(),
            "redacting",
            opts.quiet,
        );
        let second: Vec<(usize, std::result::Result<Outcome, String>)> = candidates
            .par_iter()
            .enumerate()
            .map(|(g, &i)| {
                let job = &p.jobs[i];
                let group: Vec<&backup::Entry> = manifest.entries.iter().filter(|e| e.group == g).collect();
                let r = redact_group(&p.engine, job, &group, &journal).map(|(o, hashes)| {
                    after.lock().unwrap().extend(hashes);
                    o
                });
                pb.inc(job.size);
                (i, r)
            })
            .collect();
        pb.finish_and_clear();
        // Groups skipped in this pass get no after-hash. Clean never wrote
        // them, so their current contents aren't "as clean left them"; giving
        // them one made restore silently roll back edits the agent made after
        // the backup.
        if crate::fault::hit("after-redact") {
            // Test hook: die like a crash or Ctrl-C would, before the sidecar.
            std::process::exit(3);
        }
        match backup::write_after(
            &apath,
            &backup::After {
                archive: apath.display().to_string(),
                after: after.into_inner().unwrap(),
            },
            &pw,
        ) {
            Ok(()) => journal.remove(),
            Err(e) => {
                // The files are already redacted, so carry on and report them.
                // The journal stays, and restore falls back to it.
                eprintln!(
                    "error: couldn't write the backup's after-hashes ({e:#}). Restore will use {} instead.",
                    backup::journal_path(&apath).display()
                );
                exit = 2;
            }
        }
        for (i, r) in second {
            let job = &p.jobs[i];
            match r {
                Ok(o) => {
                    reports.insert(i, file_report(job, &o, o.would_change, None));
                }
                Err(reason) => {
                    let mut fr = reports.remove(&i).unwrap();
                    fr.skipped = Some(reason);
                    reports.insert(i, fr);
                }
            }
        }
        let removed = backup::prune(&crate::paths::archives_dir(), keep);
        if !removed.is_empty() && opts.verbose > 0 {
            eprintln!("Removed {} old backup(s).", removed.len());
        }
        archive = Some(apath);
    }
    let files: Vec<(String, FileReport)> = reports
        .into_iter()
        .map(|(i, r)| (p.jobs[i].tool.to_string(), r))
        .collect();
    let mut engines = p.engines.clone();
    ner_stats(&p, &mut engines);
    let report = Report::build("clean", started, t0.elapsed().as_secs_f64(), files, engines, archive);
    emit(&report, opts, &p.notes)?;
    Ok(exit)
}

/// Backup entry id -> hash of what clean wrote (None: the file is gone).
type AfterHashes = Vec<(String, Option<String>)>;

/// The write step for one candidate and its SQLite companions.
///
/// Invariant: a file is only replaced if, at the moment of writing, it still
/// holds exactly the bytes in the backup, and its new hash is in the journal
/// before it is replaced. The first pass may have run minutes earlier (the
/// confirmation and password prompts wait on the user), so the lock check is
/// repeated here too.
fn redact_group(
    engine: &Engine,
    job: &Job,
    group: &[&backup::Entry],
    journal: &backup::Journal,
) -> std::result::Result<(Outcome, AfterHashes), String> {
    use std::path::Path;
    for e in group {
        let p = Path::new(&e.path);
        if p.exists()
            && let Some(r) = fsutil::lock_reason(p)
        {
            return Err(r);
        }
    }
    let err = |e: anyhow::Error| {
        if cfg!(windows) && format!("{e:#}").contains("os error 32") {
            "active: open in another process".to_string()
        } else {
            format!("error: {e:#}")
        }
    };
    match job.format {
        Format::Sqlite => {
            let precheck = || -> std::result::Result<(), String> {
                for e in group {
                    let now = fsutil::hash_file(Path::new(&e.path)).map_err(|e| format!("error: {e:#}"))?;
                    if now.as_deref() != Some(e.before.as_str()) {
                        return Err("changed after backup; left as is".into());
                    }
                }
                // A -wal or -journal that wasn't backed up must be empty (our
                // own connection may have just created it); otherwise another
                // process wrote to the database after the backup.
                for c in fsutil::companions(&job.path, true).into_iter().skip(1) {
                    let backed_up = group.iter().any(|e| Path::new(&e.path) == c);
                    if !backed_up && std::fs::metadata(&c).is_ok_and(|m| m.len() > 0) {
                        return Err("changed after backup; left as is".into());
                    }
                }
                Ok(())
            };
            match sqlite::process_checked(engine, job, true, Some(&precheck)) {
                Ok(SqlResult::Done(o)) => {
                    let mut after = vec![];
                    for e in group {
                        let h = fsutil::hash_file(Path::new(&e.path)).ok().flatten();
                        journal.record(&e.id, h.as_deref()).map_err(err)?;
                        after.push((e.id.clone(), h));
                    }
                    Ok((o, after))
                }
                Ok(SqlResult::Busy) => Err("active: database is locked".into()),
                Ok(SqlResult::Changed(r)) => Err(r),
                Err(e) => Err(err(e)),
            }
        }
        _ => {
            let e = group
                .iter()
                .find(|e| e.role == "main")
                .ok_or("error: no backup entry")?;
            let r = fsutil::rewrite_checked(
                &job.path,
                &e.before,
                |b| {
                    let mut o = engine.process_bytes(job, b);
                    let nb = o.new_bytes.take();
                    (o, nb)
                },
                |after| journal.record(&e.id, Some(after)),
            )
            .map_err(err)?;
            match r {
                // `after` is the hash of the bytes we wrote, not a re-read of
                // the file, so a write by the agent right after the rename is
                // never mistaken for our own output.
                fsutil::Rewrite::Done { value, after } => {
                    let h = after.unwrap_or_else(|| e.before.clone());
                    Ok((value, vec![(e.id.clone(), Some(h))]))
                }
                fsutil::Rewrite::Changed => Err("changed after backup; left as is".into()),
            }
        }
    }
}

/// Resolve a `restore` argument: a path to an archive file, an exact backup
/// name, or a prefix that matches exactly one backup.
fn resolve_archive(name: &str, list: &[backup::ArchiveInfo]) -> Result<PathBuf> {
    let p = PathBuf::from(name);
    if p.is_file() {
        return Ok(p);
    }
    if let Some(a) = list.iter().find(|a| a.name == name) {
        return Ok(a.path.clone());
    }
    let hits: Vec<&backup::ArchiveInfo> = list.iter().filter(|a| a.name.starts_with(name)).collect();
    match hits.as_slice() {
        [] => bail!("no backup called '{name}'. Run `neuralyzer restore` to list them."),
        [a] => Ok(a.path.clone()),
        many => bail!(
            "'{name}' matches {} backups:\n{}\nGive more of the name.",
            many.len(),
            many.iter()
                .map(|a| format!("  {}", a.name))
                .collect::<Vec<_>>()
                .join("\n")
        ),
    }
}

pub fn list(opts: &ScanOpts, cfg: &Config) -> Result<i32> {
    let env = Env::new(opts.root.as_deref());
    let mut also = cfg.defaults.also.clone();
    also.extend(opts.also.iter().cloned());
    let only = if opts.only.is_empty() {
        cfg.defaults.only.clone().unwrap_or_default()
    } else {
        opts.only.clone()
    };
    let d = discovery::discover(&env, &only, &also);
    let mut tools: Vec<&str> = discovery::TOOLS
        .iter()
        .map(|t| t.0)
        .filter(|t| only.is_empty() || only.iter().any(|o| o.eq_ignore_ascii_case(t)))
        .collect();
    if d.jobs.iter().any(|j| j.tool == "custom") {
        tools.push("custom");
    }
    if opts.json {
        let v = serde_json::json!({
            "tools": tools.iter().map(|t| {
                let jobs: Vec<&Job> = d.jobs.iter().filter(|j| j.tool == *t).collect();
                serde_json::json!({
                    "tool": t,
                    "roots": d.roots.iter().filter(|r| r.0 == *t).map(|r| r.1.display().to_string()).collect::<Vec<_>>(),
                    "files": jobs.len(),
                    "bytes": jobs.iter().map(|j| j.size).sum::<u64>(),
                })
            }).collect::<Vec<_>>(),
            "archives": backup::list(&crate::paths::archives_dir()).iter().map(|a| serde_json::json!({
                "path": a.path.display().to_string(), "bytes": a.size, "modified": a.modified.to_rfc3339()
            })).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(0);
    }
    use console::style;
    for t in &tools {
        let name = discovery::TOOLS
            .iter()
            .find(|x| x.0 == *t)
            .map_or("extra locations (--also)", |x| x.1);
        let jobs: Vec<&Job> = d.jobs.iter().filter(|j| j.tool == *t).collect();
        let roots: Vec<&PathBuf> = d.roots.iter().filter(|r| r.0 == *t).map(|r| &r.1).collect();
        println!("{} {}", style(*t).bold(), style(format!("({name})")).dim());
        if roots.is_empty() {
            println!("  not found");
        }
        // Attribute each file to the most specific root that contains it.
        let best = |j: &Job| {
            roots
                .iter()
                .filter(|r| j.path.starts_with(r))
                .max_by_key(|r| r.as_os_str().len())
                .copied()
        };
        for r in &roots {
            let rj: Vec<&&Job> = jobs.iter().filter(|j| best(j) == Some(*r)).collect();
            if rj.is_empty() && roots.iter().any(|o| o != r && (o.starts_with(r) || r.starts_with(o))) {
                continue;
            }
            println!(
                "  {}  {} files, {}",
                r.display(),
                rj.len(),
                report::human(rj.iter().map(|j| j.size).sum())
            );
        }
        if !jobs.is_empty() {
            let mut by_fmt: BTreeMap<&str, (usize, u64)> = BTreeMap::new();
            for j in &jobs {
                let e = by_fmt.entry(fmt_name(j.format)).or_default();
                e.0 += 1;
                e.1 += j.size;
            }
            let parts: Vec<String> = by_fmt
                .iter()
                .map(|(k, (n, b))| format!("{n} {k} ({})", report::human(*b)))
                .collect();
            println!("  total: {}", parts.join(", "));
        }
        println!();
    }
    for n in &d.notes {
        println!("note: {n}");
    }
    let archives = backup::list(&crate::paths::archives_dir());
    println!("{}", style("Backups").bold());
    if archives.is_empty() {
        println!("  none yet ({})", crate::paths::archives_dir().display());
    }
    for a in archives {
        println!(
            "  {}  {}  {}",
            a.modified.format("%Y-%m-%d %H:%M:%S"),
            report::human(a.size),
            a.path.display()
        );
    }
    Ok(0)
}

pub fn restore(archive: Option<String>, force: bool, pw_args: &PwArgs, quiet: bool) -> Result<i32> {
    let dir = crate::paths::archives_dir();
    let list = backup::list(&dir);
    let name = match archive {
        Some(n) => n,
        None => {
            if list.is_empty() {
                eprintln!("No backups found in {}.", dir.display());
                return Ok(0);
            }
            eprintln!("Backups, newest first:\n");
            for (i, a) in list.iter().enumerate() {
                eprintln!(
                    "  {:>2}) {}  {}  {}",
                    i + 1,
                    a.name,
                    a.modified.format("%Y-%m-%d %H:%M:%S"),
                    report::human(a.size)
                );
            }
            if !std::io::stdin().is_terminal() {
                eprintln!("\nRestore one with: neuralyzer restore <NAME>");
                return Ok(0);
            }
            eprint!(
                "\nWhich one do you want to restore? [1-{}, Enter to cancel] ",
                list.len()
            );
            let mut s = String::new();
            std::io::stdin().read_line(&mut s)?;
            let s = s.trim();
            if s.is_empty() {
                eprintln!("Nothing restored.");
                return Ok(0);
            }
            match s.parse::<usize>() {
                Ok(n) if (1..=list.len()).contains(&n) => list[n - 1].path.display().to_string(),
                _ => bail!("'{s}' isn't one of the listed numbers"),
            }
        }
    };
    let path = resolve_archive(&name, &list)?;
    let _lock = crate::paths::lock_data_dir()?;
    let pw = password::resolve(pw_args, Purpose::Restore, quiet)?;
    let interactive = std::io::stdin().is_terminal();
    let pb = bar(0, "restoring", quiet);
    let out = backup::restore(
        &path,
        &pw,
        force,
        |e| {
            if !interactive {
                return false;
            }
            pb.suspend(|| {
                confirm(&format!(
                    "{} changed since it was cleaned. Overwrite it with the backup?",
                    e.path
                ))
                .unwrap_or(false)
            })
        },
        &pb,
    )?;
    pb.finish_and_clear();
    if !quiet {
        if out.after_source == Some(backup::AfterSource::Journal) {
            eprintln!(
                "note: the clean that made this backup was interrupted; used its recovery journal to tell which files it changed."
            );
        }
        eprintln!("Restored {} file(s) from {}.", out.restored.len(), path.display());
        if !out.unchanged.is_empty() {
            eprintln!("{} file(s) already matched the backup.", out.unchanged.len());
        }
        for (p, r) in &out.skipped {
            eprintln!("skipped {p}: {r}");
        }
    }
    Ok(if out.skipped.is_empty() { 0 } else { 2 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::Schema;

    fn engine() -> Engine {
        Engine {
            det: Detectors::new(&Config::default(), &[]).unwrap(),
            tok: Tokenizer::ephemeral(),
            ner: None,
        }
    }

    fn setup(d: &std::path::Path) -> (Job, backup::Entry, backup::Journal) {
        let path = d.join("s.jsonl");
        std::fs::write(&path, b"{\"text\":\"mail alice.smith@example.com\"}\n").unwrap();
        let before = fsutil::hash_file(&path).unwrap().unwrap();
        let job = Job {
            tool: "custom",
            size: 0,
            path: path.clone(),
            format: Format::Jsonl,
            schema: Schema::Generic,
        };
        let e = backup::Entry {
            id: "files/000000".into(),
            group: 0,
            role: "main".into(),
            tool: "custom".into(),
            path: path.display().to_string(),
            size: 0,
            mtime: 0,
            mode: None,
            before,
        };
        let j = backup::Journal::create(&d.join("neuralyzer-20261109-120000.tar.zst.age")).unwrap();
        (job, e, j)
    }

    #[test]
    fn redact_group_writes_and_journals_the_written_hash() {
        let d = tempfile::tempdir().unwrap();
        let (job, e, j) = setup(d.path());
        let (o, after) = redact_group(&engine(), &job, &[&e], &j).unwrap();
        assert!(o.would_change);
        let now = fsutil::hash_file(&job.path).unwrap();
        assert_eq!(after, vec![(e.id.clone(), now)]);
        let journal = std::fs::read_to_string(d.path().join("neuralyzer-20261109-120000.after.journal")).unwrap();
        assert!(journal.contains(after[0].1.as_deref().unwrap()));
    }

    #[test]
    fn redact_group_skips_a_file_changed_since_backup() {
        let d = tempfile::tempdir().unwrap();
        let (job, e, j) = setup(d.path());
        let mut f = std::fs::OpenOptions::new().append(true).open(&job.path).unwrap();
        std::io::Write::write_all(&mut f, b"{\"text\":\"new turn\"}\n").unwrap();
        // Close our handle: on Windows an open handle is itself "active".
        drop(f);
        let before = std::fs::read(&job.path).unwrap();
        let r = redact_group(&engine(), &job, &[&e], &j);
        assert_eq!(r.err().as_deref(), Some("changed after backup; left as is"));
        assert_eq!(std::fs::read(&job.path).unwrap(), before);
    }

    /// Regression: the lock check only ran in the first pass, which can be
    /// minutes before the write (the prompts wait on the user). A file the
    /// agent locked in between was replaced anyway.
    #[cfg(unix)]
    #[test]
    fn redact_group_rechecks_locks_before_writing() {
        let d = tempfile::tempdir().unwrap();
        let (job, e, j) = setup(d.path());
        let before = std::fs::read(&job.path).unwrap();
        let lf = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&job.path)
            .unwrap();
        lf.lock().unwrap();
        let r = redact_group(&engine(), &job, &[&e], &j);
        lf.unlock().unwrap();
        assert!(
            r.as_ref().err().is_some_and(|r| r.starts_with("active")),
            "{:?}",
            r.err()
        );
        assert_eq!(std::fs::read(&job.path).unwrap(), before);
    }

    fn info(name: &str) -> backup::ArchiveInfo {
        backup::ArchiveInfo {
            path: PathBuf::from("/nonexistent/archives").join(name),
            name: name.into(),
            size: 0,
            modified: chrono::Local::now(),
        }
    }

    /// Regression: a prefix matching several backups silently picked the first.
    #[test]
    fn ambiguous_prefix_is_refused() {
        let l = [
            info("neuralyzer-20261109-120000-1.tar.zst.age"),
            info("neuralyzer-20261109-120000.tar.zst.age"),
            info("neuralyzer-20261108-090000.tar.zst.age"),
        ];
        let err = resolve_archive("neuralyzer-20261109", &l).unwrap_err();
        assert!(format!("{err}").contains("matches 2 backups"), "{err}");
        assert_eq!(
            resolve_archive("neuralyzer-20261108", &l).unwrap(),
            l[2].path,
            "a unique prefix still works"
        );
        assert_eq!(
            resolve_archive("neuralyzer-20261109-120000.tar.zst.age", &l).unwrap(),
            l[1].path,
            "an exact name wins even when it is also a prefix of another"
        );
    }
}
