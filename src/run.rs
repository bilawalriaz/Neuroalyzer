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
use anyhow::{Context, Result, bail};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Default)]
pub struct ScanOpts {
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
        match crate::ner::Ner::load(&cfg.ner, opts.quiet) {
            Ok(n) => {
                engines.ner = true;
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
            Err(e) => Err(format!("error: {e:#}")),
        },
        _ => match fsutil::read(&job.path) {
            Ok(b) => {
                let mut o = engine.process_bytes(job, &b);
                o.new_bytes = None;
                Ok(o)
            }
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

pub fn scan(opts: &ScanOpts, cfg: &Config) -> Result<i32> {
    let started = chrono::Local::now();
    let t0 = Instant::now();
    let p = prepare(opts, cfg, false)?;
    let total: u64 = p.jobs.iter().map(|j| j.size).sum();
    let pb = bar(total, "scanning", opts.quiet);
    let results: Vec<(String, FileReport)> = p
        .jobs
        .par_iter()
        .map(|job| {
            let r = match analyse(&p.engine, job, None) {
                Ok(o) => file_report(job, &o, false, None),
                Err(reason) => file_report(job, &Outcome::default(), false, Some(reason)),
            };
            pb.inc(job.size);
            (job.tool.to_string(), r)
        })
        .collect();
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
    let started = chrono::Local::now();
    let t0 = Instant::now();
    let p = prepare(opts, cfg, true)?;
    let min_age = Duration::from_secs(opts.min_age);
    let total: u64 = p.jobs.iter().map(|j| j.size).sum();
    let pb = bar(total, "scanning", opts.quiet);
    let first: Vec<(usize, std::result::Result<Outcome, String>)> = p
        .jobs
        .par_iter()
        .enumerate()
        .map(|(i, job)| {
            let r = analyse(&p.engine, job, Some(min_age));
            pb.inc(job.size);
            (i, r)
        })
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
                let r = (|| -> std::result::Result<Outcome, String> {
                    for e in &group {
                        let now =
                            fsutil::hash_file(std::path::Path::new(&e.path)).map_err(|e| format!("error: {e:#}"))?;
                        if now.as_deref() != Some(e.before.as_str()) {
                            return Err("changed after backup; left as is".into());
                        }
                    }
                    let o = match job.format {
                        Format::Sqlite => match sqlite::process(&p.engine, job, true) {
                            Ok(SqlResult::Done(o)) => o,
                            Ok(SqlResult::Busy) => return Err("active: database is locked".into()),
                            Err(e) => return Err(format!("error: {e:#}")),
                        },
                        _ => {
                            let b = fsutil::read(&job.path).map_err(|e| format!("error: {e:#}"))?;
                            let o = p.engine.process_bytes(job, &b);
                            drop(b);
                            if let Some(nb) = &o.new_bytes {
                                fsutil::atomic_write(&job.path, nb).map_err(|e| {
                                    if cfg!(windows) && format!("{e:#}").contains("os error 32") {
                                        "active: open in another process".to_string()
                                    } else {
                                        format!("error: {e:#}")
                                    }
                                })?;
                            }
                            o
                        }
                    };
                    let mut a = after.lock().unwrap();
                    for e in &group {
                        a.insert(
                            e.id.clone(),
                            fsutil::hash_file(std::path::Path::new(&e.path)).ok().flatten(),
                        );
                    }
                    Ok(o)
                })();
                pb.inc(job.size);
                (i, r)
            })
            .collect();
        pb.finish_and_clear();
        // Files that were skipped in this pass keep their original hash as "after".
        {
            let mut a = after.lock().unwrap();
            for e in &manifest.entries {
                a.entry(e.id.clone())
                    .or_insert_with(|| fsutil::hash_file(std::path::Path::new(&e.path)).ok().flatten());
            }
        }
        backup::write_after(
            &apath,
            &backup::After {
                archive: apath.display().to_string(),
                after: after.into_inner().unwrap(),
            },
            &pw,
        )
        .context("couldn't write the backup's after-hashes")?;
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
    Ok(0)
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
                eprintln!("\nRestore one with: sesscrub restore <NAME>");
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
    let path = {
        let p = PathBuf::from(&name);
        if p.is_file() {
            p
        } else if let Some(a) = list.iter().find(|a| a.name == name || a.name.starts_with(&name)) {
            a.path.clone()
        } else {
            bail!("no backup called '{name}'. Run `sesscrub restore` to list them.");
        }
    };
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
