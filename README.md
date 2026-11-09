# sesscrub

[![CI](https://github.com/bilawalriaz/sesscrub/actions/workflows/ci.yml/badge.svg)](https://github.com/bilawalriaz/sesscrub/actions/workflows/ci.yml)

sesscrub finds the session data that AI coding agents keep on disk: GitHub Copilot (VS Code chat history and Copilot CLI), OpenCode and omp (oh-my-pi). It copies every file it is about to change into an encrypted backup, redacts secrets and personal data in place, and prints a report. `sesscrub restore` puts the files back from a backup.

It is a single binary for Windows, macOS and Linux. It makes no network calls, apart from the optional one-time download of the NER model.

## Quick start

```sh
sesscrub list                 # what was found, where, and past backups
sesscrub scan                 # report what would change, change nothing
sesscrub clean                # back up (encrypted), then redact in place
sesscrub restore              # pick a backup and put the files back
sesscrub restore <NAME>       # restore a specific backup
```

Close your agents before running `clean`. Files modified in the last 120 seconds are skipped, which catches most active sessions but not all of them. `clean` asks for a backup password, then asks you to confirm before it changes anything. The password rules are in [docs/SAFETY.md](docs/SAFETY.md).

## Install

### Prebuilt binaries

Download a binary from the GitHub Releases page. Builds are published for Linux x86_64, macOS arm64, macOS x86_64 and Windows x86_64, with a `SHA256SUMS.txt` file to check the download against.

### Build from source

You need Rust 1.89 or newer. Run `rustup update` if your version is older.

```sh
git clone https://github.com/bilawalriaz/sesscrub
cd sesscrub
cargo build --release
```

The binary is at `target/release/sesscrub`, or `sesscrub.exe` on Windows.

The default build includes the `ner` feature, which pulls in ONNX Runtime. The `ort` crate downloads a prebuilt ONNX Runtime library during the build. If that download is blocked by a locked-down network or proxy, build without the feature:

```sh
cargo build --release --no-default-features
```

Everything works except NER, which finds names, addresses and organisations.

## Commands

| Command | What it does |
|---|---|
| `sesscrub list` | Shows the tools found, where they are, how much data there is, and past backups. |
| `sesscrub scan` | Reports what would be redacted. Writes report files and changes nothing else. |
| `sesscrub clean` | Backs up the affected files, then redacts them in place. |
| `sesscrub restore [ARCHIVE] [--force]` | Restores files from a backup. With no name, lists the backups newest first and asks which one to restore. |
| `sesscrub key save` / `key clear` | Stores or removes the backup password in the OS keychain. |
| `sesscrub model fetch` | Downloads the NER model now, so later runs work offline. |

Exit codes are 0 for a clean result, 1 when `scan` finds something, and 2 for an error. `restore` also exits with 2 when it skipped any file.

Flags for `scan` and `clean`:

| Flag | Effect |
|---|---|
| `--only copilot,opencode,omp` | Only the listed tools. |
| `--root DIR` | Look for session data under DIR instead of your home directory. Use it to test on a copy. |
| `--also PATH` | Also scan a file or directory. Repeatable. |
| `--ner` / `--no-ner` | Turn the NER model on or off for this run. |
| `--json` | Print the report as JSON on stdout instead of writing report files. |

Extra flags for `clean`:

| Flag | Effect |
|---|---|
| `-y`, `--yes` | Skip the confirmation prompt. |
| `--keep N` | Number of backups to keep. Default 5. |
| `--min-age SECS` | Skip files modified more recently than this. Default 120. `0` turns the check off. |
| `--password-file PATH` | Read the backup password from a file. |
| `--password-stdin` | Read the backup password from the first line of stdin. |
| `--insecure-password-file` | Accept a password file that other users can read. |

`restore` takes `--force` to overwrite files that changed since they were cleaned, and the same password flags as `clean`.

Global flags are `-v` (repeat for more detail), `-q`, `--no-color` and `--config FILE`.

## What it finds

sesscrub uses three detection layers.

Secrets come from the gitleaks v8.30.1 default ruleset, vendored into the binary, where 216 rules apply. They also cover connection strings with passwords, Bearer tokens, and key=value pairs near names such as key, token, secret or password, checked with an entropy test. Exact values of secret-looking keys from `.env` files in the project directories the sessions point to are included too.

Personal data is matched by pattern and then checked by a validator. A match that fails its validator is left alone.

| Type | Matches |
|---|---|
| `SECRET` | Keys, tokens, passwords and other secrets. |
| `EMAIL` | Email addresses. |
| `PHONE` | UK and international phone numbers. |
| `POSTCODE` | UK postcodes. |
| `NINO` | National Insurance numbers. |
| `NHS` | NHS numbers, checked with mod 11. |
| `CARD` | Payment card numbers, checked with Luhn and the issuer prefix. |
| `IBAN` | IBANs, checked with mod 97. |
| `IP` | Public IPv4 addresses. Private ranges are off by default. |
| `PII` | Cells in tables where a column is mostly emails or phones. |
| `PERSON`, `ADDRESS`, `ORG`, `DOB` | Names, addresses, organisations and dates of birth found by NER. |

In a table where a column is mostly emails or phones, every cell in that row is redacted except numeric IDs, dates, booleans and enum-like values. Tables can be CSV, TSV, Markdown, SQL client output or JSON arrays of objects.

NER uses the GLiNER model `knowledgator/gliner-pii-base-v1.0` (Apache-2.0, quantised ONNX, about 205 MB). It is on by default in builds that include it. The model downloads on the first run that uses it (pass `--no-ner` to skip it) into the `models` folder in the data directory, and its SHA-256 is checked. After that, it runs offline. Only prose is sent to the model: user messages, assistant text and tool output. Code blocks and code-looking text are skipped. If the model cannot load, the run continues without it, and the report says so. NER is English-centric.

Each redacted value becomes a token such as `[EMAIL:3f9a1c2e]`. The eight hex characters are the start of an HMAC-SHA256 of the value, keyed with a random key stored as `hmac.key` in the data directory. The same value gets the same token on one machine, and the token cannot be reversed.

## What gets touched

The tables below show where sesscrub looks. Exact globs are in `src/discovery.rs`, and [docs/FORMATS.md](docs/FORMATS.md) lists the formats and their upstream sources.

| Tool | Where it looks | What it reads |
|---|---|---|
| VS Code Copilot Chat | `Code/User` and `Code - Insiders/User` under the user data directory | Chat sessions in `workspaceStorage` and `globalStorage`, chat editing sessions, and chat-related rows of `state.vscdb` |
| Copilot CLI | `~/.copilot`, `$COPILOT_HOME`, or `$XDG_STATE_HOME/.copilot` | `session-state` (events, plans, workspace files, checkpoints) and `history-session-state` |
| OpenCode | `~/.local/share/opencode` on every OS, or `$XDG_DATA_HOME/opencode`, or the file in `$OPENCODE_DB` | `opencode*.db` (SQLite) and the older `storage/**/*.json` tree |
| omp (oh-my-pi) | `~/.omp/agent`, `$PI_CODING_AGENT_DIR`, `$XDG_DATA_HOME/omp`, and named profiles under `~/.omp` | `sessions/**/*.jsonl` |

The user data directory is `~/Library/Application Support` on macOS, `~/.config` (or `$XDG_CONFIG_HOME`) on Linux, and `%APPDATA%` on Windows. VS Code's `VSCODE_PORTABLE` and `VSCODE_APPDATA` are honoured.

`scan` reads files and writes nothing except the report. `clean` edits only the files that contain something to redact. Inside a JSON file, only string values are changed. Keys and the rest of the file stay byte-identical.

sesscrub keeps its own files in the data directory:

| OS | Data directory |
|---|---|
| macOS | `~/Library/Application Support/sesscrub` |
| Linux | `~/.local/share/sesscrub` |
| Windows | `%LOCALAPPDATA%\sesscrub` |

It holds `archives/` (backups), `reports/`, `models/` (the NER model) and `hmac.key`. Set `SESSCRUB_DATA_DIR` to use another location.

## Safety model

- Every file that will change is copied into an encrypted backup first. The backup is decrypted and every hash is checked before any session file is touched.
- Each file is checked again just before it is written. If it changed since the backup, it is left alone.
- Restore does not overwrite a file that changed since cleaning unless you confirm it or pass `--force`.
- Reports contain counts, types and file paths. They never contain the values.

The details are in [docs/SAFETY.md](docs/SAFETY.md).

## Testing on a copy

You can try the whole flow on a copy of your session folders before touching the real ones. Copy with `-p` so the timestamps survive. Otherwise every copied file looks freshly modified, and `clean` skips it for two minutes (or pass `--min-age 0` when cleaning a copy).

```sh
mkdir -p ~/scrub-test/.local/share
cp -Rp ~/.local/share/opencode ~/scrub-test/.local/share/
cp -Rp ~/.omp ~/scrub-test/

mkdir -p "$HOME/scrub-test/Library/Application Support/Code/User"
cp -Rp "$HOME/Library/Application Support/Code/User/workspaceStorage" \
       "$HOME/Library/Application Support/Code/User/globalStorage" \
       "$HOME/scrub-test/Library/Application Support/Code/User/"

sesscrub list --root ~/scrub-test
sesscrub scan --root ~/scrub-test
sesscrub clean --root ~/scrub-test
sesscrub restore <NAME>
```

With `--root`, sesscrub checks all three OS layouts under that directory, and environment variable overrides are ignored. Project directories named in the sessions are still read, read-only, for `.env` values if they exist on this machine. Backups and reports still go to the real data directory, so `sesscrub restore` lists them from there.

## Configuration

sesscrub works without a config file. To change the defaults, such as the tools included, the number of backups kept, the allowlist, custom patterns or the NER threshold, see [docs/CONFIG.md](docs/CONFIG.md).

## Limitations

- On macOS and Linux, a file that another program has open, but has not locked, cannot be detected. Close the agent first.
- Copies outside the files sesscrub edits are out of reach. This includes filesystem snapshots and backups such as Time Machine, SSD remnants, and SQLite rollback journals that were already deleted.
- Detection is based on patterns and the model. Review the report before you rely on a clean run.
- NER is English-centric.
- IPv6 addresses are not detected.
- JSON keys are not redacted.
- SQLite full-text index tables are skipped, and the report notes it.
- In VS Code's `state.vscdb`, only chat-related rows are touched.
- Formats were researched on 2026-11-09. When a file does not match the expected layout, sesscrub falls back to generic handling and lists the file under "format drift" in the report.

## Development

`cargo test --workspace` runs the unit tests and the end-to-end tests. The end-to-end tests build fixture trees with the `crates/fixturegen` crate. They check recall for each type, confirm that no planted value remains in raw bytes (including SQLite and WAL files), validate all output, confirm that clean followed by restore is byte-identical, and cover password sources, a wrong password, insecure password files, active and locked files, and format drift.

The NER test needs the model in a local directory:

```sh
SESSCRUB_MODEL_DIR=/some/dir sesscrub model fetch
SESSCRUB_TEST_MODEL_DIR=/some/dir cargo test --release --test ner
```

## Benchmarks

`scripts/bench.sh [BYTES]` generates a synthetic tree (1 GB by default), then times a scan with NER, a scan without NER, and a clean without NER. The NER run needs the model, so fetch it first.

BENCHMARK_RESULTS_PLACEHOLDER

## Licence

MIT. See [LICENSE](LICENSE). Third-party components: the gitleaks rules are MIT licensed, and the GLiNER model is Apache-2.0, published by knowledgator.
