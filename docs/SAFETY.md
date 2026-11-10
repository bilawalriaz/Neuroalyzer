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
7. For Copilot CLI `events.jsonl`, write and verify the encrypted edit record before replacing the session file. Record after-redaction hashes in the journal, before replacing text files and after committing SQLite changes.
8. Write the after-redaction hashes to the encrypted sidecar, then delete the journal. If the run stops before this step (Ctrl-C, crash, power loss), the journal stays. Copilot live restore uses the edit record and its commit evidence.
9. Delete backups beyond the number to keep (`--keep`, default 5), and any leftover partial files from interrupted runs.

## Backup format

Each backup contains a full-file archive. A run can also write the following companion files.

| File | Contents |
|---|---|
| `neuralyzer-<timestamp>.tar.zst.age` | The backup itself. Written once, then verified. |
| `neuralyzer-<timestamp>.after.age` | Hashes of each file that clean wrote, after redaction. Written after the redaction pass. |
| `neuralyzer-<timestamp>.after.journal` | After-hashes recorded during clean. The journal holds entry IDs and hashes. |
| `neuralyzer-<timestamp>.after.undo/` | Encrypted Copilot edit records and their commit receipts. Keep this folder beside the archive for live restore. |

Two backups made in the same second get a suffix: `neuralyzer-<timestamp>-1`, `-2`, and so on. The suffix counts as newer, so the newest backup is always kept.

The archive is built in three layers. The files are packed with tar, compressed with zstd at level 3 (multithreaded), and then encrypted with age, using a passphrase protected by scrypt. Everything is streamed, so no plaintext copy is written to disk.

The first entry in the tar is `manifest.json`. It lists each file with its original path, size, modification time, Unix mode and BLAKE3 hash, which is the "before" hash. The file bodies follow as `files/000000`, `files/000001` and so on. Each file in the manifest also has a group number. A SQLite database and its `-wal` or `-journal` share a group, so recovery can identify which files belong together.

The after-redaction hashes cannot go in the archive, because the archive is written before redaction starts. They go in the sidecar, which is encrypted with the same password. The archive itself does not change after it is verified.

Windows writes archives and their sidecars beside the executable by default. It also lists existing backups from the local app data archive directory. On macOS and Linux, or when `NEURALYZER_DATA_DIR` is set, backups go in the data directory under `archives/`. On Unix, the folder uses mode `0700` and files use `0600`. `neuralyzer list` shows the backups, with the newest first. Only the newest `--keep` archives are kept, and each deletion removes the sidecar, journal and undo directory too. Archive files with names Neuralyzer didn't make are listed but never deleted.

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

`restore` with no name lists backups and lets you choose one in a terminal. To select a backup directly, pass its full name, a unique prefix or the archive path.

`restore <NAME>` undoes edits in Copilot CLI `events.jsonl`. Each encrypted record stores the event ID, JSON field path, original string and exact replacement. Restore finds each event by its ID and checks the current string against the recorded replacement. If any check fails, it skips the session and prints the reason. If every edited string already holds its original bytes, the session is left unchanged.

Restore validates the edited JSONL, then checks that the live file still matches what it read before replacing it atomically. Event order, line endings and bytes outside the restored strings stay the same. Restore exits with 2 if it skips any session.

Use `restore <NAME> --into <FOLDER>` to recover full files from any archive, including older backups. The folder must be new. The original bytes go into numbered files under `files/`. Use the included `manifest.json` to match those files to their original paths. The command writes only inside the recovery folder.

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
