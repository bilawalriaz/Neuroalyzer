//! Backup password resolution. Order: --password-file, --password-stdin,
//! SESSCRUB_PASSWORD, OS keychain, interactive prompt. The password is never
//! taken as a plain argument, never logged, and zeroized after use.

use age::secrecy::SecretString;
use anyhow::{Context, Result, bail};
use std::io::IsTerminal;
use std::path::PathBuf;
use zeroize::Zeroizing;

const KEYRING_SERVICE: &str = "sesscrub";
const KEYRING_USER: &str = "backup-password";

#[derive(clap::Args, Debug, Clone, Default)]
pub struct PwArgs {
    /// Read the backup password from this file (one trailing newline is stripped).
    #[arg(long, value_name = "PATH")]
    pub password_file: Option<PathBuf>,
    /// Read the backup password from the first line of stdin.
    #[arg(long)]
    pub password_stdin: bool,
    /// Accept a password file that other users can read.
    #[arg(long)]
    pub insecure_password_file: bool,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Purpose {
    Clean,
    Restore,
}

fn strip_newline(mut s: String) -> String {
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
    s
}

fn check_file_perms(p: &std::path::Path, insecure: bool) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(p)
            .with_context(|| format!("couldn't read password file {}", p.display()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 && !insecure {
            bail!(
                "password file {} can be read by other users (mode {:o}). Fix it with:\n  chmod 600 {}\nor pass --insecure-password-file to use it anyway.",
                p.display(),
                mode & 0o777,
                p.display()
            );
        }
    }
    let _ = (p, insecure);
    Ok(())
}

fn finish(pw: Zeroizing<String>, quiet: bool) -> Result<SecretString> {
    if pw.is_empty() {
        bail!("the backup password is empty");
    }
    if pw.chars().count() < 12 && !quiet {
        eprintln!("warning: the backup password is shorter than 12 characters. A longer one is much harder to guess.");
    }
    Ok(SecretString::from(pw.as_str().to_owned()))
}

fn keyring_entry() -> Option<keyring::Entry> {
    keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER).ok()
}

pub fn resolve(args: &PwArgs, purpose: Purpose, quiet: bool) -> Result<SecretString> {
    if let Some(p) = &args.password_file {
        check_file_perms(p, args.insecure_password_file)?;
        let s = Zeroizing::new(strip_newline(
            std::fs::read_to_string(p).with_context(|| format!("couldn't read password file {}", p.display()))?,
        ));
        return finish(s, quiet);
    }
    if args.password_stdin {
        let mut line = Zeroizing::new(String::new());
        std::io::stdin()
            .read_line(&mut line)
            .context("couldn't read the password from stdin")?;
        let s = Zeroizing::new(strip_newline(std::mem::take(&mut *line)));
        return finish(s, quiet);
    }
    if let Ok(v) = std::env::var("SESSCRUB_PASSWORD") {
        if !quiet {
            eprintln!(
                "warning: using SESSCRUB_PASSWORD. Environment variables can leak into logs and child processes."
            );
        }
        return finish(Zeroizing::new(v), quiet);
    }
    if std::env::var_os("SESSCRUB_NO_KEYRING").is_none()
        && let Some(e) = keyring_entry()
        && let Ok(pw) = e.get_password()
    {
        return finish(Zeroizing::new(pw), true);
    }
    if !std::io::stdin().is_terminal() && !std::io::stderr().is_terminal() {
        bail!(
            "no backup password available and there's no terminal to ask for one. Use one of:\n  --password-file <path>\n  --password-stdin\n  SESSCRUB_PASSWORD (env var)\n  sesscrub key save (stores it in the OS keychain)"
        );
    }
    let first = Zeroizing::new(rpassword::prompt_password("Backup password: ").context("couldn't read the password")?);
    if purpose == Purpose::Clean {
        let second = Zeroizing::new(rpassword::prompt_password("Repeat it: ").context("couldn't read the password")?);
        if *first != *second {
            bail!("the passwords don't match");
        }
    }
    finish(first, quiet)
}

pub fn key_save(args: &PwArgs) -> Result<()> {
    let pw = resolve(
        &PwArgs {
            password_file: args.password_file.clone(),
            password_stdin: args.password_stdin,
            insecure_password_file: args.insecure_password_file,
        },
        Purpose::Clean,
        false,
    )?;
    let e = keyring_entry().context("the OS keychain isn't available")?;
    use age::secrecy::ExposeSecret;
    e.set_password(pw.expose_secret())
        .context("couldn't save to the OS keychain")?;
    eprintln!("Saved the backup password to the OS keychain.");
    Ok(())
}

pub fn key_clear() -> Result<()> {
    let e = keyring_entry().context("the OS keychain isn't available")?;
    match e.delete_credential() {
        Ok(()) => eprintln!("Removed the backup password from the OS keychain."),
        Err(keyring::Error::NoEntry) => eprintln!("No backup password was stored in the OS keychain."),
        Err(err) => return Err(err).context("couldn't remove it from the OS keychain"),
    }
    Ok(())
}
