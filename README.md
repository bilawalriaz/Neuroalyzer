# Neuralyzer

[![CI](https://github.com/bilawalriaz/neuralyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/bilawalriaz/neuralyzer/actions/workflows/ci.yml)

<img src="assets/neuralyzer.png" alt="Agent J holding the neuralyzer in Men in Black" width="640">

The neuralyzer from *Men in Black*: flash it, and the memory is gone.

Neuralyzer finds the session data that AI coding agents keep on disk: Claude Code, OpenAI Codex CLI, Gemini CLI, GitHub Copilot (VS Code chat history and Copilot CLI), OpenCode, Hermes Agent, OpenClaw, Factory Droid, pi and omp (oh-my-pi). It copies every file it is about to change into an encrypted backup, redacts secrets and personal data in place, and prints a report. `neuralyzer restore` puts the files back from a backup.

It is a single binary for Windows, macOS and Linux. It makes no network calls, apart from the optional one-time download of the NER model.

## Quick start

```sh
neuralyzer list                  # what was found, where, and past backups
neuralyzer scan                  # report what would change, change nothing
neuralyzer clean                 # back up (encrypted), then redact in place
neuralyzer restore               # pick a backup and put the files back
neuralyzer restore <NAME>        # restore a specific backup
```

Close your agents before running `clean`. Files modified in the last 120 seconds are skipped, which catches most active sessions but not all of them. `clean` asks for a backup password, then asks you to confirm before it changes anything. The password rules are in [docs/SAFETY.md](docs/SAFETY.md).

## Install

### Prebuilt binaries

Download from the [latest release](https://github.com/bilawalriaz/neuralyzer/releases/latest). Every release has a `SHA256SUMS.txt` file to check the download against.

Linux builds are published as a portable tarball, a `.deb` and an `.rpm`, all containing the same binary. It needs glibc 2.35 or newer, so it runs on Ubuntu 22.04 and later, Fedora 36 and later, Debian 12 and later, and their derivatives.

Ubuntu and Debian:

```sh
gh release download --repo bilawalriaz/neuralyzer --pattern '*.deb'
sudo apt install ./neuralyzer_*_amd64.deb
```

Fedora and RHEL:

```sh
gh release download --repo bilawalriaz/neuralyzer --pattern '*.rpm'
sudo dnf install ./neuralyzer-*.x86_64.rpm
```

Portable tarball (Linux x86_64 shown; macOS users get a `-darwin.tar.gz` and Windows a `.zip`):

```sh
gh release download --repo bilawalriaz/neuralyzer --pattern '*x86_64-unknown-linux-gnu.tar.gz' --pattern SHA256SUMS.txt
sha256sum --ignore-missing -c SHA256SUMS.txt
tar -xzf neuralyzer-*-x86_64-unknown-linux-gnu.tar.gz neuralyzer && sudo mv neuralyzer /usr/local/bin/
```

Targets: `x86_64-unknown-linux-gnu` (`.tar.gz`, `.deb`, `.rpm`), `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-pc-windows-msvc` (a `.zip`).

### Upgrading from an older name

The project has been renamed twice. Each rename moves the binary, the environment variables, the config file and the data directory, and creates a fresh HMAC key, so tokens from older runs no longer match:

| Version | Name | Binary | Config and data directory |
|---|---|---|---|
| 1.x | sesscrub | `sesscrub` | `sesscrub` |
| 2.x | neuroalyzer | `neuroalyzer` | `neuroalyzer` |
| 3.x | neuralyzer | `neuralyzer` | `neuralyzer` |

Older backups keep their old names and stay in the old data directory, so the new binary does not list or restore them, and a password saved in the OS keychain under the old name is not found. Keep the old binary until you no longer need those backups, or point `NEURALYZER_DATA_DIR` at the old directory to restore from it.

### Build from source

You need Rust 1.89 or newer. Run `rustup update` if your version is older.

```sh
git clone https://github.com/bilawalriaz/neuralyzer
cd neuralyzer
cargo build --release
```

The binary is at `target/release/neuralyzer`, or `neuralyzer.exe` on Windows.

The default build includes the `ner` feature, which pulls in ONNX Runtime. The `ort` crate downloads a prebuilt ONNX Runtime library (from pyke's CDN, `parcel.pyke.io`) during the build. If that download is blocked by a locked-down network or proxy, build without the feature:

```sh
cargo build --release --no-default-features
```

Everything works except NER, which finds names, addresses and organisations.

## Commands

| Command | What it does |
|---|---|
| `neuralyzer list` | Shows the tools found, where they are, how much data there is, and past backups. |
| `neuralyzer scan` | Reports what would be redacted. Writes report files and changes nothing else. |
| `neuralyzer clean` | Backs up the affected files, then redacts them in place. |
| `neuralyzer restore [ARCHIVE] [--force]` | Restores files from a backup. With no name, lists the backups newest first and asks which one to restore. |
| `neuralyzer key save` / `key clear` | Stores or removes the backup password in the OS keychain. |
| `neuralyzer model fetch` | Downloads the NER model now, so later runs work offline. |

Exit codes are 0 for a clean result, 1 when `scan` finds something, and 2 for an error. `restore` also exits with 2 when it skipped any file.

Flags for `scan` and `clean`:

| Flag | Effect |
|---|---|
| `--only claude,codex,...` | Only the listed tools: `copilot`, `opencode`, `omp`, `claude`, `codex`, `gemini`, `hermes`, `openclaw`, `droid`, `pi`. |
| `--root DIR` | Look for session data under DIR instead of your home directory. Use it to test on a copy. |
| `--also PATH` | Also scan a file or directory. Repeatable. |
| `--ner` / `--no-ner` | Enable or disable experimental NER. Off by default. |
| `--json` | Print the report as JSON on stdout instead of writing report files. |
| `--ner-sessions N` | Parallel NER workers. Default: one per physical core. |
| `--ner-threads N` | Threads per NER worker. Default: 1. |
| `--ner-batch N` | Chunks per NER model call. Default: 1. |
| `--ner-device DEVICE` | `auto`, `cpu`, `coreml`, `cuda` or `directml`. The last three need a build with the cargo feature of the same name. Default: `auto` (CPU in standard builds). |

Flags for every command:

| Flag | Effect |
|---|---|
| `-j N`, `--threads N` | CPU threads for scanning: a number, `max`, `half` or `p-cores`. Default: every logical CPU. |
| `--low-priority` | Run at low priority so the machine stays usable: background QoS on macOS (efficiency cores, throttled I/O), nice 10 on Linux, below-normal priority on Windows. |
| `-v` | With NER on, also prints the CPU layout and the plan it chose: scan threads, NER workers, threads, batch and device. |

Each of these has an environment variable and a config key. See [docs/CONFIG.md](docs/CONFIG.md).

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

Neuralyzer uses three detection layers.

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

NER uses the GLiNER model `knowledgator/gliner-pii-base-v1.0` (Apache-2.0, quantised ONNX, about 205 MB). The model downloads on the first run with NER enabled into the `models` folder in the data directory, and its SHA-256 is checked. After that, it runs offline. Only prose is sent to the model: user messages, assistant text and tool output. Code blocks and code-looking text are skipped. If the model cannot load, the run continues without it, and the report says so. NER is English-centric.

Each redacted value becomes a token such as `[EMAIL:3f9a1c2e]`. The eight hex characters are the start of an HMAC-SHA256 of the value, keyed with a random key stored as `hmac.key` in the data directory. The same value gets the same token on one machine, and the token cannot be reversed.

## What gets touched

The tables below show where Neuralyzer looks. Exact globs are in `src/discovery.rs`, and [docs/FORMATS.md](docs/FORMATS.md) lists the formats and their upstream sources.

| Tool | Where it looks | What it reads |
|---|---|---|
| VS Code Copilot Chat | `Code/User` and `Code - Insiders/User` under the user data directory | Chat sessions in `workspaceStorage` and `globalStorage`, chat editing sessions, and chat-related rows of `state.vscdb` |
| Copilot CLI | `~/.copilot`, `$COPILOT_HOME`, or `$XDG_STATE_HOME/.copilot` | `session-state` (events, plans, workspace files, checkpoints) and `history-session-state` |
| OpenCode | `~/.local/share/opencode` on every OS, or `$XDG_DATA_HOME/opencode`, or the file in `$OPENCODE_DB` | `opencode*.db` (SQLite) and the older `storage/**/*.json` tree |
| omp (oh-my-pi) | `~/.omp/agent`, `$PI_CODING_AGENT_DIR`, `$XDG_DATA_HOME/omp`, and named profiles under `~/.omp` | `sessions/**/*.jsonl` |
| Claude Code | `~/.claude` or `$CLAUDE_CONFIG_DIR` | `projects/*/*.jsonl` transcripts and subagent transcripts, `tool-results/`, project `memory/*.md`, `history.jsonl`, `plans/`, `todos/`, `paste-cache/`, and `file-history/` (rewind snapshots of edited files) |
| Codex CLI | `~/.codex` or `$CODEX_HOME` | `sessions/**/rollout-*.jsonl`, `archived_sessions/` (plain and zstd-compressed `.jsonl.zst`), `history.jsonl`, `session_index.jsonl`, and the `state_*`, `thread_history_*` and `memories_*` SQLite databases |
| Gemini CLI | `~/.gemini` (or `$GEMINI_CLI_HOME/.gemini`) | `tmp/<project hash>/chats/*.json`, `logs.json` and checkpoints |
| Hermes Agent | `~/.hermes`, `$HERMES_HOME`, or `%LOCALAPPDATA%\hermes` on Windows | `state.db` (SQLite) and `sessions/*.json(l)`, for the default profile and every `profiles/<name>/` |
| OpenClaw | `~/.openclaw`, `$OPENCLAW_STATE_DIR`, legacy `~/.clawdbot` and `~/.moltbot` | `agents/*/sessions/*.jsonl` and `agents/*/agent/openclaw-agent.sqlite`. Credential and gateway databases are not touched. |
| Factory Droid | `~/.factory` | `sessions/*/*.jsonl` |
| pi | `~/.pi/agent` | `sessions/**/*.jsonl` |

Credential files (`auth.json`, OAuth tokens, keychains, `.env` in the agent's home) are never in these globs, so cleaning cannot log you out of an agent.

The user data directory is `~/Library/Application Support` on macOS, `~/.config` (or `$XDG_CONFIG_HOME`) on Linux, and `%APPDATA%` on Windows. VS Code's `VSCODE_PORTABLE` and `VSCODE_APPDATA` are honoured.

`scan` reads files and writes nothing except the report. `clean` edits only the files that contain something to redact. Inside a JSON file, only string values are changed. Keys and the rest of the file stay byte-identical.

Neuralyzer keeps its own files in the data directory:

| OS | Data directory |
|---|---|
| macOS | `~/Library/Application Support/neuralyzer` |
| Linux | `~/.local/share/neuralyzer` |
| Windows | `%LOCALAPPDATA%\neuralyzer` |

It holds `archives/` (backups), `reports/`, `models/` (the NER model) and `hmac.key`. Set `NEURALYZER_DATA_DIR` to use another location.

## Safety model

- Every file that will change is copied into an encrypted backup first. The backup is decrypted and every hash is checked before any session file is touched.
- Each file is checked again just before it is written. If it changed since the backup, or another process has locked it, it is left alone.
- An interrupted `clean` can still be restored. Each file's after-redaction hash is journalled before the file is replaced.
- Restore does not overwrite a file that changed since cleaning unless you confirm it or pass `--force`. It never overwrites a file another process has locked.
- Only one `clean` or `restore` runs at a time.
- Reports contain counts, types and file paths. They never contain the values.

The details are in [docs/SAFETY.md](docs/SAFETY.md). The states, invariants and transitions behind them are in [docs/STATE_MACHINES.md](docs/STATE_MACHINES.md).

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

neuralyzer list --root ~/scrub-test
neuralyzer scan --root ~/scrub-test
neuralyzer clean --root ~/scrub-test
neuralyzer restore <NAME>
```

With `--root`, Neuralyzer checks all three OS layouts under that directory, and environment variable overrides are ignored. Project directories named in the sessions are still read, read-only, for `.env` values if they exist on this machine. Backups and reports still go to the real data directory, so `neuralyzer restore` lists them from there.

## Configuration

Neuralyzer works without a config file. To change the defaults, such as the tools included, the number of backups kept, the allowlist, custom patterns or the NER threshold, see [docs/CONFIG.md](docs/CONFIG.md).

## Limitations

- On macOS and Linux, a file that another program has open, but has not locked, cannot be detected. Close the agent first.
- Copies outside the files Neuralyzer edits are out of reach. This includes filesystem snapshots and backups such as Time Machine, SSD remnants, and SQLite rollback journals that were already deleted.
- Detection is based on patterns and the model. Review the report before you rely on a clean run.
- NER is English-centric.
- IPv6 addresses are not detected.
- JSON keys are not redacted.
- SQLite full-text index tables are skipped, and the report notes it.
- In VS Code's `state.vscdb`, only chat-related rows are touched.
- Zstd-compressed Codex rollouts are rewritten at compression level 3, so a cleaned `.jsonl.zst` is not byte-identical to one Codex would write. `restore` puts the original bytes back.
- Formats were researched on 2026-11-09. When a file does not match the expected layout, Neuralyzer falls back to generic handling and lists the file under "format drift" in the report.

## Development

See [AGENTS.md](AGENTS.md) for the layout, how to add a new agent, and how releases work.

`cargo test --workspace` runs the unit tests and the end-to-end tests. The end-to-end tests build fixture trees with the `crates/fixturegen` crate. They check recall for each type, confirm that no planted value remains in raw bytes (including SQLite and WAL files), validate all output, confirm that clean followed by restore is byte-identical, and cover password sources, a wrong password, insecure password files, active and locked files, and format drift.

The NER test needs the model in a local directory:

```sh
NEURALYZER_MODEL_DIR=/some/dir neuralyzer model fetch
NEURALYZER_TEST_MODEL_DIR=/some/dir cargo test --release --test ner
```

## Speed

Without NER, scanning spreads over every core, with the biggest files started first, and the PII patterns stay on the fast regex engine even for non-ASCII text. On an M3 Pro, `scan` reads 6.1 GB of real agent sessions in about 39 seconds (151 MB/s).

NER is experimental and off by default. Use `neuralyzer scan --ner` or `neuralyzer clean --ner` to enable it for one run. Set `ner = true` under `[defaults]` in the config to enable it for future runs. Each run reads all files, deduplicates the prose chunks, and sends the unique chunks to the model. The default is one model worker per physical core. The same M3 Pro does about 60 chunks per second, so a large first run takes hours. `-v` prints how many unique chunks a run has to infer. Use `--low-priority` for a long NER run in the background. [docs/NER_PERFORMANCE.md](docs/NER_PERFORMANCE.md) has the measurements and what is left to speed up.

To see the numbers for your own data, time `neuralyzer scan --root` on a copy (see "Testing on a copy"), or run `bench/bench.py`, which also records CPU use, peak memory and NER chunk rates.

## Licence

MIT. See [LICENSE](LICENSE). Third-party components: the gitleaks rules are MIT licensed, and the GLiNER model is Apache-2.0, published by knowledgator. The README image is a still from *Men in Black* (1997), used for identification only; it is not covered by the MIT licence.
