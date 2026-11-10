# Safety

This page describes what `clean` and `restore` do, in order, and what each step checks. For the commands and flags, see the [README](../README.md).

## What clean does

`clean` runs these steps in order. If a step fails, the run stops before the next one. The states and invariants behind them are in [STATE_MACHINES.md](STATE_MACHINES.md).

0. Take the run lock (`neuralyzer.lock` in the data directory). If another `clean` or `restore` holds it, stop with a message. The lock is released when the process exits, even on a crash.
1. Scan the files and work out which would change. Active files and files that cannot be written are skipped here.
2. If nothing would change, stop. No backup is written.
3. Ask for confirmation. Skip this with `--yes`. Without a terminal and without `--yes`, Neuralyzer stops and asks you to re-run with `--yes`.
4. Get the backup password. See [Passwords](#passwords).
5. Write the encrypted archive with only the files that will change, including SQLite `-wal` and `-journal` files. Re-open the archive, decrypt it and check every hash. If any check fails, the partial archive is deleted and no session file is changed.
6. Redact each file. Just before each file is written, Neuralyzer checks it is not locked by another process, then reads it once and checks that those bytes match the backup hash. It redacts those same bytes, and checks the file on disk again immediately before replacing it. If the file changed at any point, it is left alone and the report says so. For SQLite the check runs inside the write transaction, so no other process can commit between the check and the redaction.
7. As each file is written, its after-redaction hash is appended to a recovery journal and flushed to disk before the file is replaced.
8. Write the after-redaction hashes to the encrypted sidecar, then delete the journal. If the run stops before this step (Ctrl-C, crash, power loss), the journal stays and `restore` uses it.
9. Delete backups beyond the number to keep (`--keep`, default 5), and any leftover partial files from interrupted runs.

## Backup format

Each backup is one archive plus one sidecar.

| File | Contents |
|---|---|
| `archives/neuralyzer-<timestamp>.tar.zst.age` | The backup itself. Written once, then verified. |
| `archives/neuralyzer-<timestamp>.after.age` | Hashes of each file that clean wrote, after redaction. Written after the redaction pass. |
| `archives/neuralyzer-<timestamp>.after.journal` | Only while `clean` runs, or after it was interrupted. The same hashes, written one by one as files are replaced. It holds entry ids and hashes of redacted content, never values, and is owner-only. |

Two backups made in the same second get a suffix: `neuralyzer-<timestamp>-1`, `-2`, and so on. The suffix counts as newer, so the newest backup is always kept.

The archive is built in three layers. The files are packed with tar, compressed with zstd at level 3 (multithreaded), and then encrypted with age, using a passphrase protected by scrypt. Everything is streamed, so no plaintext copy is written to disk.

The first entry in the tar is `manifest.json`. It lists each file with its original path, size, modification time, Unix mode and BLAKE3 hash, which is the "before" hash. The file bodies follow as `files/000000`, `files/000001` and so on. Each file in the manifest also has a group number. A SQLite database and its `-wal` or `-journal` share a group, so restore handles them together.

The after-redaction hashes cannot go in the archive, because the archive is written before redaction starts. They go in the sidecar, which is encrypted with the same password. The archive itself does not change after it is verified.

The data directory holds the archives in `archives/`. The folder is owner-only (`0700` on Unix), and so are the files (`0600`). `neuralyzer list` shows the backups, with the newest first. Only the newest `--keep` archives are kept, and each deletion removes the sidecar and journal too. Archive files with names Neuralyzer didn't make are listed but never deleted.

## Passwords

Neuralyzer uses the first source it finds, in this order:

| Order | Source | Notes |
|---|---|---|
| 1 | `--password-file PATH` | On Unix, refused if group or other users can read the file. Fix it with `chmod 600 PATH`, or pass `--insecure-password-file`. One trailing newline is stripped. |
| 2 | `--password-stdin` | Reads the first line of stdin. |
| 3 | `NEURALYZER_PASSWORD` | Prints a warning. Environment variables can leak into logs and child processes. |
| 4 | OS keychain | Saved with `neuralyzer key save`. Skipped when `NEURALYZER_NO_KEYRING` is set. The entry is stored under the service `neuralyzer`. |
| 5 | Interactive prompt | Input is not echoed. `clean` asks twice, and `restore` asks once. |

`neuralyzer key save` takes its password from the first three sources or from the prompt. It does not read the keychain first.

The password is never accepted as a plain argument and never written to a log. Neuralyzer clears it from memory after use. A password shorter than 12 characters produces a warning, and the run continues.

Without a terminal and with no source set, Neuralyzer stops with a message that lists the options.

The archive cannot be opened without its password, and Neuralyzer has no recovery option. Keep the password somewhere you can find it.

## Writing files

Each rewritten file goes through the same steps:

1. Read the file once and check those bytes against the backup hash.
2. Write the new contents to a temporary file in the same folder, with the original permissions.
3. Flush the file to disk (`fsync`).
4. Check the original against the backup hash again. If it changed, delete the temporary file and leave the original alone.
5. Record the new hash in the journal.
6. Rename the temporary file over the original. The rename is atomic.

Files with nothing to redact are not written at all.

A file is skipped and marked in the report when any of these is true. The reason text appears in the report.

| Reason in the report | Meaning |
|---|---|
| `active: modified Ns ago` | Modified within `--min-age` seconds. Default 120. `--min-age 0` turns this check off. |
| `active: locked by another process` | Locked, on macOS and Linux. |
| `active: open in another process` | Open elsewhere, on Windows. |
| `active: database is locked` | A SQLite database that another process holds. |
| `not writable: permission denied` | The file cannot be opened for writing. |
| `changed after backup; left as is` | The file changed between the backup and the redaction pass. |

On macOS and Linux, Neuralyzer can only see locks. A program that has a file open without a lock is not detected, so close the agent before you run `clean`.

## SQLite databases

Neuralyzer scans every TEXT cell in a SQLite database, and every BLOB cell that decodes as UTF-8 JSON. Full-text index tables are skipped, and the report says so.

The update path is:

1. Open the database with a busy timeout of 2 seconds. If it is still locked, the file is skipped as active.
2. Turn on `secure_delete`, so that deleted content is overwritten with zeros.
3. Start a write transaction (`BEGIN IMMEDIATE`). From here on, no other process can commit.
4. Check the database and its `-wal` or `-journal` against the backup hashes. A `-wal` or `-journal` that wasn't backed up must be empty. If anything changed, roll back and skip the file.
5. Read the rows, and apply every change in the same transaction.
6. Run `VACUUM`. Applications leave old text in free pages when they edit data, and `VACUUM` rebuilds the file without those pages.
7. Run `wal_checkpoint(TRUNCATE)`, so the write-ahead log no longer holds the old text.

If step 6 or 7 fails, the redaction is already committed. The file is reported as modified, with a note that old text may remain in free pages.

## What restore does

`restore` with no name lists the backups, newest first, and in a terminal asks which one to restore. With a name, it accepts the full name, a unique prefix, or a path to an archive file. A prefix that matches more than one backup is refused, and the matches are listed. Restore takes the same run lock as `clean`.

The steps are:

1. Read the password, decrypt the archive and read the manifest. A wrong password stops the restore here, before any file is written. The after-hashes come from the sidecar or, if the clean was interrupted, from its journal. Restore says when it used the journal.
2. Decide what to do with each group of files (a database and its companions counts as one group):
   - If every file already matches its "before" hash, nothing is restored.
   - If a file in the group is locked or open in another process, the group is skipped, even with `--force`. Close the app and run restore again.
   - If every file still matches its "after" hash, it has not changed since `clean`, so the group is restored without asking.
   - If `clean` never wrote the group (it was skipped because it changed after the backup), the group is skipped. `--force` overwrites it.
   - Otherwise a file in the group changed after cleaning. In a terminal, Neuralyzer asks once for the group. Without a terminal the group is skipped, and with `--force` it is overwritten.
3. Write each restored file atomically, using the same method as `clean`. The file gets its original Unix mode and modification time.
4. For a SQLite database, remove a stale `-shm` file. If the backup has no `-wal` or `-journal` for the database, remove the current one, because it would not match the restored file.

Restore exits with 2 when it skipped any file, and the skipped files are listed. With `--force`, edits made after the clean are overwritten. Check the file list before you use `--force`.

## Reports

Each `scan` and `clean` writes two files to `reports/` in the data directory, `report-<timestamp>.json` and `report-<timestamp>.md`. They are owner-only. `--json` prints the JSON to stdout and writes no files.

A report holds:

- The Neuralyzer version, the mode (`scan` or `clean`), the start time, the duration and the bytes scanned.
- Counts of files scanned, files with findings, files modified and files skipped.
- For each tool, each file: its path, format, size, findings grouped by type and detector with counts, any skip reason, and any format drift note.
- The versions of the detection engines and whether NER ran.
- For `clean`, the path of the archive.

A report never includes the values that were found. File paths are included, and they can show project names. Keep reports private, or delete them when you no longer need them.

## What this does not cover

Neuralyzer changes the files it finds. It cannot reach other copies of that data. These are outside its reach:

- Filesystem snapshots and backups, such as Time Machine.
- Data remnants on an SSD.
- SQLite rollback journals that were already deleted.

The backup holds the original text, encrypted. Treat it as sensitive, keep the password safe, and delete archives you no longer need.
