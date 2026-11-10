//! Encrypted backups.
//!
//! Layout: `neuralyzer-<ts>.tar.zst.age` is a tar stream, zstd-compressed (level
//! 3, multithreaded), then age-encrypted with a scrypt passphrase. Nothing is
//! written to disk in plaintext. The first tar entry is `manifest.json` (paths,
//! sizes, mtimes, modes and BLAKE3 "before" hashes); file bodies follow as
//! `files/NNNNNN`.
//!
//! The "after" hashes only exist once redaction finishes, so they go in a small
//! sidecar, `neuralyzer-<ts>.after.age`, encrypted with the same password. That
//! keeps the archive itself write-once and verifiable before any session file
//! is touched.

use age::secrecy::{ExposeSecret, SecretString};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

pub const ARCHIVE_EXT: &str = ".tar.zst.age";
pub const AFTER_EXT: &str = ".after.age";
pub const JOURNAL_EXT: &str = ".after.journal";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Entry {
    pub id: String,
    /// Files in the same group (a SQLite db and its -wal) are restored together.
    pub group: usize,
    pub role: String,
    pub tool: String,
    pub path: String,
    pub size: u64,
    pub mtime: i64,
    pub mode: Option<u32>,
    pub before: String,
}

#[derive(Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    #[serde(default)]
    pub run_id: String,
    pub created_at: String,
    pub neuralyzer_version: String,
    pub entries: Vec<Entry>,
}

// The private undo key lives only inside the encrypted archive manifest.
#[derive(Serialize, Deserialize)]
struct ArchiveManifest<M, T> {
    #[serde(flatten)]
    manifest: M,
    undo_identity: Option<T>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct After {
    pub archive: String,
    /// Entry id -> hash after redaction (None: the file no longer exists).
    /// Only entries clean actually wrote are listed (sidecars written before
    /// v0.1.1 list every entry).
    pub after: BTreeMap<String, Option<String>>,
}

pub struct Source {
    pub group: usize,
    pub role: &'static str,
    pub tool: String,
    pub path: PathBuf,
}

fn io_err<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

fn encryptor(pw: &SecretString) -> age::Encryptor {
    age::Encryptor::with_user_passphrase(pw.clone())
}

fn decrypt_reader<R: Read>(r: R, pw: &SecretString) -> Result<impl Read + use<R>> {
    let d = age::Decryptor::new(r).context("this doesn't look like a neuralyzer archive")?;
    let id = age::scrypt::Identity::new(pw.clone());
    d.decrypt(std::iter::once(&id as &dyn age::Identity))
        .map_err(|e| match e {
            age::DecryptError::DecryptionFailed | age::DecryptError::NoMatchingKeys => {
                anyhow::anyhow!("wrong password, or the archive is damaged")
            }
            other => anyhow::anyhow!("couldn't decrypt the archive: {other}"),
        })
}

struct HashingReader<R> {
    inner: R,
    h: blake3::Hasher,
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.h.update(&buf[..n]);
        Ok(n)
    }
}

/// Pick a fresh archive name and claim it by creating its `.partial` file with
/// `create_new`, so two runs in the same second can never share (and truncate)
/// one partial file. A suffix is added on collision: `-1`, `-2`, ...
fn reserve(dir: &Path) -> Result<(PathBuf, File)> {
    let ts = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    for i in 0u32.. {
        let base = if i == 0 {
            dir.join(format!("neuralyzer-{ts}"))
        } else {
            dir.join(format!("neuralyzer-{ts}-{i}"))
        };
        let final_path = archive_path(&base);
        if final_path.exists() {
            continue;
        }
        let partial = partial_path(&final_path);
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&partial) {
            Ok(f) => return Ok((final_path, f)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e).with_context(|| format!("couldn't create {}", partial.display())),
        }
    }
    unreachable!()
}

fn partial_path(p: &Path) -> PathBuf {
    PathBuf::from(format!("{}.partial", p.display()))
}

/// Ordering key from an archive file name: (timestamp, collision suffix).
/// `None` for names neuralyzer didn't make.
pub fn name_key(name: &str) -> Option<(String, u32)> {
    let stem = name.strip_prefix("neuralyzer-")?.strip_suffix(ARCHIVE_EXT)?;
    let (ts, n) = match stem.get(15..) {
        Some("") => (stem, 0),
        Some(rest) => (&stem[..15], rest.strip_prefix('-')?.parse().ok()?),
        None => return None,
    };
    let ok = ts.len() == 15
        && ts
            .bytes()
            .enumerate()
            .all(|(i, b)| if i == 8 { b == b'-' } else { b.is_ascii_digit() });
    ok.then(|| (ts.to_string(), n))
}

pub fn archive_path(base: &Path) -> PathBuf {
    PathBuf::from(format!("{}{ARCHIVE_EXT}", base.display()))
}

pub fn after_path(archive: &Path) -> PathBuf {
    let s = archive.display().to_string();
    PathBuf::from(format!("{}{AFTER_EXT}", s.strip_suffix(ARCHIVE_EXT).unwrap_or(&s)))
}

pub fn journal_path(archive: &Path) -> PathBuf {
    let s = archive.display().to_string();
    PathBuf::from(format!("{}{JOURNAL_EXT}", s.strip_suffix(ARCHIVE_EXT).unwrap_or(&s)))
}

fn file_meta(p: &Path) -> Result<(u64, i64, Option<u32>)> {
    let m = std::fs::metadata(p).with_context(|| format!("couldn't read {}", p.display()))?;
    let mtime = m
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs() as i64);
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        Some(m.permissions().mode())
    };
    #[cfg(not(unix))]
    let mode = None;
    Ok((m.len(), mtime, mode))
}

/// Create and verify an archive of `sources`. Returns the archive path and manifest.
pub fn create(
    sources: &[Source],
    pw: &SecretString,
    dir: &Path,
    progress: &indicatif::ProgressBar,
) -> Result<(PathBuf, Manifest, age::x25519::Identity)> {
    crate::paths::ensure_private_dir(dir)?;
    let mut entries = vec![];
    for (i, s) in sources.iter().enumerate() {
        let (size, mtime, mode) = file_meta(&s.path)?;
        let before = crate::fsutil::hash_file(&s.path)?.context("a file disappeared before it could be backed up")?;
        entries.push(Entry {
            id: format!("files/{i:06}"),
            group: s.group,
            role: s.role.into(),
            tool: s.tool.clone(),
            path: s.path.display().to_string(),
            size,
            mtime,
            mode,
            before,
        });
    }
    let identity = age::x25519::Identity::generate();
    let key = identity.to_string();
    let mut run_id = [0u8; 16];
    rand::fill(&mut run_id);
    let manifest = Manifest {
        version: 1,
        run_id: hex::encode(run_id),
        created_at: chrono::Local::now().to_rfc3339(),
        neuralyzer_version: env!("CARGO_PKG_VERSION").into(),
        entries,
    };
    let (final_path, f) = reserve(dir)?;
    let partial = partial_path(&final_path);
    let result = (|| -> Result<()> {
        crate::paths::make_private(&partial)?;
        let enc = encryptor(pw).wrap_output(BufWriter::with_capacity(1 << 20, f))?;
        let mut z = zstd::Encoder::new(enc, 3)?;
        let threads = std::thread::available_parallelism().map_or(1, |n| n.get()) as u32;
        z.multithread(threads.clamp(1, 8))?;
        let mut tar = tar::Builder::new(z);
        let mj = zeroize::Zeroizing::new(serde_json::to_vec_pretty(&ArchiveManifest {
            manifest: &manifest,
            undo_identity: Some(key.expose_secret()),
        })?);
        let mut h = tar::Header::new_gnu();
        h.set_size(mj.len() as u64);
        h.set_mode(0o600);
        h.set_cksum();
        tar.append_data(&mut h, "manifest.json", &mj[..])?;
        for e in &manifest.entries {
            let f = File::open(&e.path).with_context(|| format!("couldn't open {}", e.path))?;
            let mut r = HashingReader {
                inner: BufReader::with_capacity(1 << 20, f).take(e.size),
                h: blake3::Hasher::new(),
            };
            let mut h = tar::Header::new_gnu();
            h.set_size(e.size);
            h.set_mode(0o600);
            h.set_cksum();
            tar.append_data(&mut h, &e.id, &mut r)
                .with_context(|| format!("couldn't back up {}", e.path))?;
            if r.h.finalize().to_hex().as_str() != e.before {
                bail!(
                    "{} changed while it was being backed up. Nothing was modified; run clean again.",
                    e.path
                );
            }
            progress.inc(e.size);
        }
        let z = tar.into_inner()?;
        let enc = z.finish()?;
        let mut bw = enc.finish()?;
        bw.flush()?;
        let f = bw.into_inner().map_err(io_err)?;
        f.sync_all()?;
        Ok(())
    })();
    if let Err(e) = result {
        let _ = std::fs::remove_file(&partial);
        return Err(e);
    }
    if let Err(e) = verify(&partial, pw, &manifest) {
        let _ = std::fs::remove_file(&partial);
        return Err(e.context("backup verification failed, so no session files were changed"));
    }
    std::fs::rename(&partial, &final_path)?;
    crate::fsutil::sync_required(dir)?;
    Ok((final_path, manifest, identity))
}

/// Re-open, decrypt and check the entry count and every hash.
pub fn verify(path: &Path, pw: &SecretString, expected: &Manifest) -> Result<()> {
    let f = File::open(path)?;
    let dec = decrypt_reader(BufReader::with_capacity(1 << 20, f), pw)?;
    let z = zstd::Decoder::new(dec)?;
    let mut ar = tar::Archive::new(z);
    let mut seen = 0usize;
    let mut manifest_ok = false;
    for ent in ar.entries()? {
        let mut ent = ent?;
        let name = ent.path()?.to_string_lossy().to_string();
        if name == "manifest.json" {
            let (m, identity) = decode_manifest(&mut ent)?;
            manifest_ok = m.run_id == expected.run_id
                && m.entries.len() == expected.entries.len()
                && (m.run_id.is_empty() || identity.is_some());
            continue;
        }
        let e = expected
            .entries
            .iter()
            .find(|e| e.id == name)
            .with_context(|| format!("unexpected entry {name}"))?;
        let mut h = blake3::Hasher::new();
        std::io::copy(&mut ent, &mut h)?;
        if h.finalize().to_hex().as_str() != e.before {
            bail!("hash mismatch for {}", e.path);
        }
        seen += 1;
    }
    if !manifest_ok || seen != expected.entries.len() {
        bail!("expected {} files, found {seen}", expected.entries.len());
    }
    Ok(())
}

pub(crate) fn write_undo<T: Serialize + serde::de::DeserializeOwned>(
    path: &Path,
    record: &T,
    identity: &age::x25519::Identity,
) -> Result<()> {
    let dir = path.parent().context("undo record has no parent")?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    {
        let recipient = identity.to_public();
        let encryptor = age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))?;
        let mut encrypted = encryptor.wrap_output(tmp.as_file_mut())?;
        serde_json::to_writer(&mut encrypted, record).context("couldn't encode undo record")?;
        encrypted.finish()?.sync_all()?;
    }
    read_undo::<T>(tmp.path(), identity)?;
    tmp.persist_noclobber(path).map_err(|e| e.error)?;
    crate::fsutil::sync_required(dir)?;
    Ok(())
}

pub(crate) fn read_undo<T: serde::de::DeserializeOwned>(path: &Path, identity: &age::x25519::Identity) -> Result<T> {
    let decryptor = age::Decryptor::new(BufReader::new(File::open(path)?))?;
    let mut decrypted = decryptor.decrypt(std::iter::once(identity as &dyn age::Identity))?;
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    decrypted.read_to_end(&mut bytes)?;
    serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid undo record"))
}

fn open_archive(path: &Path, pw: &SecretString) -> Result<tar::Archive<impl Read + use<>>> {
    let file = File::open(path).with_context(|| format!("couldn't open {}", path.display()))?;
    let decrypted = decrypt_reader(BufReader::new(file), pw)?;
    Ok(tar::Archive::new(zstd::Decoder::new(decrypted)?))
}

fn decode_manifest(reader: impl Read) -> Result<(Manifest, Option<age::x25519::Identity>)> {
    let ArchiveManifest {
        manifest,
        undo_identity,
    }: ArchiveManifest<Manifest, String> =
        serde_json::from_reader(reader).map_err(|_| anyhow::anyhow!("the archive manifest is damaged"))?;
    let identity = undo_identity
        .map(|key: String| {
            let key = zeroize::Zeroizing::new(key);
            key.parse().map_err(|_| anyhow::anyhow!("invalid undo key"))
        })
        .transpose()?;
    Ok((manifest, identity))
}

fn manifest_from<R: Read>(entries: &mut tar::Entries<'_, R>) -> Result<(Manifest, Option<age::x25519::Identity>)> {
    let mut entry = entries.next().context("the archive has no manifest")??;
    anyhow::ensure!(
        entry.path()?.as_ref() == Path::new("manifest.json"),
        "the archive has no manifest"
    );
    decode_manifest(&mut entry)
}

pub(crate) fn read_manifest(path: &Path, pw: &SecretString) -> Result<(Manifest, Option<age::x25519::Identity>)> {
    manifest_from(&mut open_archive(path, pw)?.entries()?)
}

/// Recover verified originals into a new directory. The manifest maps each
/// numbered file to its original path, including any SQLite companions.
pub(crate) fn recover(path: &Path, pw: &SecretString, destination: &Path) -> Result<usize> {
    let mut archive = open_archive(path, pw)?;
    let mut entries = archive.entries()?;
    let (manifest, _) = manifest_from(&mut entries)?;
    std::fs::create_dir(destination)
        .with_context(|| format!("couldn't create recovery folder {}", destination.display()))?;
    crate::paths::ensure_private_dir(destination)?;
    let files = destination.join("files");
    std::fs::create_dir(&files)?;
    let mut count = 0;
    for item in entries {
        let mut item = item?;
        let expected = manifest.entries.get(count).context("unexpected archive entry")?;
        let id = format!("files/{count:06}");
        anyhow::ensure!(
            expected.id == id && item.path()?.as_ref() == Path::new(&id),
            "unexpected archive entry"
        );
        let mut tmp = tempfile::NamedTempFile::new_in(&files)?;
        let mut reader = HashingReader {
            inner: &mut item,
            h: blake3::Hasher::new(),
        };
        let size = std::io::copy(&mut reader, tmp.as_file_mut())?;
        anyhow::ensure!(
            size == expected.size && reader.h.finalize().to_hex().as_str() == expected.before,
            "archive entry is damaged"
        );
        tmp.as_file().sync_all()?;
        tmp.persist_noclobber(destination.join(id)).map_err(|e| e.error)?;
        count += 1;
    }
    anyhow::ensure!(count == manifest.entries.len(), "missing archive entries");
    crate::fsutil::atomic_write(
        &destination.join("manifest.json"),
        &serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(count)
}

pub fn write_after(archive: &Path, after: &After, pw: &SecretString) -> Result<()> {
    let p = after_path(archive);
    let tmp = PathBuf::from(format!("{}.partial", p.display()));
    let f = File::create(&tmp)?;
    crate::paths::make_private(&tmp)?;
    let mut w = encryptor(pw).wrap_output(BufWriter::new(f))?;
    w.write_all(&serde_json::to_vec(after)?)?;
    let mut bw = w.finish()?;
    bw.flush()?;
    bw.into_inner().map_err(io_err)?.sync_all()?;
    std::fs::rename(&tmp, &p)?;
    Ok(())
}

/// Where a reader got the archive's after-hashes from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AfterSource {
    Sidecar,
    /// The clean was interrupted before the sidecar was written.
    Journal,
    Missing,
}

pub fn load_after(archive: &Path, pw: &SecretString) -> Result<(Option<After>, AfterSource)> {
    if let Some(a) = read_after(archive, pw)? {
        return Ok((Some(a), AfterSource::Sidecar));
    }
    match read_journal(&journal_path(archive))? {
        Some(a) => Ok((Some(a), AfterSource::Journal)),
        None => Ok((None, AfterSource::Missing)),
    }
}

pub fn read_after(archive: &Path, pw: &SecretString) -> Result<Option<After>> {
    let p = after_path(archive);
    if !p.exists() {
        return Ok(None);
    }
    let mut r = decrypt_reader(BufReader::new(File::open(&p)?), pw)?;
    let mut buf = vec![];
    r.read_to_end(&mut buf)?;
    Ok(Some(serde_json::from_slice(&buf)?))
}

pub struct ArchiveInfo {
    pub path: PathBuf,
    pub name: String,
    pub size: u64,
    pub modified: chrono::DateTime<chrono::Local>,
}

pub fn list(dir: &Path) -> Vec<ArchiveInfo> {
    list_in(std::iter::once(dir))
}

pub fn list_in<'a>(dirs: impl IntoIterator<Item = &'a Path>) -> Vec<ArchiveInfo> {
    let mut v: Vec<ArchiveInfo> = dirs
        .into_iter()
        .flat_map(std::fs::read_dir)
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if !name.ends_with(ARCHIVE_EXT) {
                return None;
            }
            let m = e.metadata().ok()?;
            Some(ArchiveInfo {
                path: e.path(),
                name,
                size: m.len(),
                modified: m.modified().ok()?.into(),
            })
        })
        .collect();
    // Newest first. Compare the timestamp, then the collision suffix as a
    // number: plain name order puts `-1` below the un-suffixed archive of the
    // same second and `-10` below `-2`. Names neuralyzer didn't make go last.
    v.sort_by(|a, b| match (name_key(&a.name), name_key(&b.name)) {
        (Some(x), Some(y)) => y.cmp(&x),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => b.name.cmp(&a.name),
    });
    v
}

/// Keep the newest `keep` archives (and their sidecars); delete the rest.
/// Only archives with names neuralyzer made are counted or deleted. Leftover
/// `.partial` files from interrupted runs are removed too: the caller holds the
/// run lock, so no other run can be writing one.
pub fn prune(dir: &Path, keep: usize) -> Vec<PathBuf> {
    let mut removed = vec![];
    let ours = list(dir).into_iter().filter(|a| name_key(&a.name).is_some());
    for a in ours.skip(keep.max(1)) {
        if std::fs::remove_file(&a.path).is_ok() {
            let _ = std::fs::remove_file(after_path(&a.path));
            let _ = std::fs::remove_file(journal_path(&a.path));
            let _ = std::fs::remove_dir_all(crate::undo::dir(&a.path));
            removed.push(a.path);
        }
    }
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let n = e.file_name().to_string_lossy().to_string();
        if n.starts_with("neuralyzer-") && n.ends_with(".partial") {
            let _ = std::fs::remove_file(e.path());
        }
    }
    removed
}

// ---------- after-hash journal ----------

/// Retains after-hashes while clean runs. It holds entry IDs and BLAKE3
/// hashes. Live restore uses separate commit evidence.
pub struct Journal {
    path: PathBuf,
    f: std::sync::Mutex<File>,
}

impl Journal {
    pub fn create(archive: &Path) -> Result<Self> {
        let path = journal_path(archive);
        let f = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&path)
            .with_context(|| format!("couldn't create {}", path.display()))?;
        crate::paths::make_private(&path)?;
        Ok(Self {
            path,
            f: std::sync::Mutex::new(f),
        })
    }

    /// Record that entry `id` now hashes to `hash` (`None`: the file is gone).
    pub fn record(&self, id: &str, hash: Option<&str>) -> Result<()> {
        let mut f = self.f.lock().unwrap();
        writeln!(f, "{id}\t{}", hash.unwrap_or("-"))?;
        f.sync_data()?;
        Ok(())
    }

    /// The sidecar now holds everything; drop the journal.
    pub fn remove(self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn read_journal(p: &Path) -> Result<Option<After>> {
    let s = match std::fs::read_to_string(p) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("couldn't read {}", p.display())),
    };
    let mut a = After::default();
    // A torn last line (crash mid-append) is ignored; later lines win.
    for line in s.lines() {
        if let Some((id, h)) = line.split_once('\t')
            && id.starts_with("files/")
            && (h == "-" || (h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit())))
        {
            a.after.insert(id.to_string(), (h != "-").then(|| h.to_string()));
        }
    }
    Ok(Some(a))
}

// ---------- restore ----------

#[derive(Default)]
pub struct RestoreOutcome {
    pub restored: Vec<String>,
    pub unchanged: Vec<String>,
    pub skipped: Vec<(String, String)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn touch(dir: &Path, name: &str) {
        std::fs::write(dir.join(name), b"x").unwrap();
    }

    #[test]
    fn name_key_parses_neuralyzer_names_only() {
        assert_eq!(
            name_key("neuralyzer-20261109-120000.tar.zst.age"),
            Some(("20261109-120000".into(), 0))
        );
        assert_eq!(
            name_key("neuralyzer-20261109-120000-12.tar.zst.age"),
            Some(("20261109-120000".into(), 12))
        );
        assert_eq!(name_key("my-copy.tar.zst.age"), None);
        assert_eq!(name_key("neuralyzer-2026-11-09.tar.zst.age"), None);
        assert_eq!(name_key("neuralyzer-20261109-120000-x.tar.zst.age"), None);
    }

    /// Regression: `-1` sorted below the un-suffixed archive of the same second
    /// and `-10` below `-2`, so list showed them out of order and prune deleted
    /// the newest backup.
    #[test]
    fn collision_suffixes_sort_newest_first() {
        let d = tempfile::tempdir().unwrap();
        for n in [
            "neuralyzer-20261109-115959.tar.zst.age",
            "neuralyzer-20261109-120000.tar.zst.age",
            "neuralyzer-20261109-120000-1.tar.zst.age",
            "neuralyzer-20261109-120000-2.tar.zst.age",
            "neuralyzer-20261109-120000-10.tar.zst.age",
        ] {
            touch(d.path(), n);
        }
        let names: Vec<String> = list(d.path()).into_iter().map(|a| a.name).collect();
        assert_eq!(
            names,
            [
                "neuralyzer-20261109-120000-10.tar.zst.age",
                "neuralyzer-20261109-120000-2.tar.zst.age",
                "neuralyzer-20261109-120000-1.tar.zst.age",
                "neuralyzer-20261109-120000.tar.zst.age",
                "neuralyzer-20261109-115959.tar.zst.age",
            ]
        );
    }

    #[test]
    fn prune_keeps_the_newest_collision_and_foreign_files() {
        let d = tempfile::tempdir().unwrap();
        for n in [
            "neuralyzer-20261109-120000.tar.zst.age",
            "neuralyzer-20261109-120000.after.age",
            "neuralyzer-20261109-120000-1.tar.zst.age",
            "neuralyzer-20261109-120000-1.after.age",
            "hand-copied.tar.zst.age",
            "neuralyzer-20261109-110000.tar.zst.age.partial",
        ] {
            touch(d.path(), n);
        }
        let removed = prune(d.path(), 1);
        assert_eq!(removed.len(), 1);
        let mut left: Vec<String> = std::fs::read_dir(d.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        left.sort();
        assert_eq!(
            left,
            [
                "hand-copied.tar.zst.age",
                "neuralyzer-20261109-120000-1.after.age",
                "neuralyzer-20261109-120000-1.tar.zst.age",
            ]
        );
    }

    /// Regression: two runs in the same second both opened the same
    /// `.partial` with `File::create`, truncating each other's archive.
    #[test]
    fn concurrent_reservations_get_distinct_names() {
        let d = tempfile::tempdir().unwrap();
        let paths: Vec<PathBuf> = std::thread::scope(|s| {
            let hs: Vec<_> = (0..8).map(|_| s.spawn(|| reserve(d.path()).unwrap().0)).collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let uniq: std::collections::BTreeSet<_> = paths.iter().collect();
        assert_eq!(uniq.len(), paths.len(), "{paths:?}");
    }

    #[test]
    fn journal_round_trip_ignores_torn_lines() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("neuralyzer-20261109-120000.tar.zst.age");
        let j = Journal::create(&a).unwrap();
        let h = "a".repeat(64);
        j.record("files/000000", Some(&h)).unwrap();
        j.record("files/000001", None).unwrap();
        j.record("files/000000", Some(&"b".repeat(64))).unwrap();
        drop(j);
        let mut f = std::fs::OpenOptions::new().append(true).open(journal_path(&a)).unwrap();
        f.write_all(b"files/000002\tabc").unwrap();
        let got = read_journal(&journal_path(&a)).unwrap().unwrap();
        assert_eq!(got.after.len(), 2);
        assert_eq!(got.after["files/000000"].as_deref(), Some("b".repeat(64).as_str()));
        assert_eq!(got.after["files/000001"], None);
    }
}
