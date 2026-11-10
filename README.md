# Neuralyzer

[![CI](https://github.com/bilawalriaz/neuralyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/bilawalriaz/neuralyzer/actions/workflows/ci.yml)

<img src="assets/neuralyzer.png" alt="Agent J holding the neuralyzer in Men in Black" width="640">

Neuralyzer finds and redacts secrets and personal data in local AI coding sessions. It makes an encrypted backup before editing session files. Use `restore` to put the original files back.

Supports Claude Code, Codex CLI, Gemini CLI, GitHub Copilot for VS Code and CLI, OpenCode, Hermes Agent, OpenClaw, Factory Droid, pi and oh-my-pi. [Supported files and locations](docs/FORMATS.md)

## Install

Download the binary for your system and check it against `SHA256SUMS.txt`. [Latest release](https://github.com/bilawalriaz/neuralyzer/releases/latest)

- **Linux x86-64** uses glibc 2.35 or newer. Install the `.deb` with `sudo apt install ./neuralyzer_*_amd64.deb`, install the `.rpm` with `sudo dnf install ./neuralyzer-*.x86_64.rpm`, or extract the portable tarball.
- **macOS** has separate tarballs for Apple silicon and Intel.
- **Windows x86-64** comes as a ZIP containing `neuralyzer.exe`.

To build from source with Rust 1.89 or newer:

```sh
git clone https://github.com/bilawalriaz/neuralyzer
cd neuralyzer
cargo build --release --locked
```

The binary is in `target/release/`. To build without ONNX Runtime or experimental NER support, add `--no-default-features`.

## Quick start

```sh
neuralyzer list                # Show detected sessions and existing backups
neuralyzer scan                # Preview findings without editing session files
neuralyzer clean               # Back up and redact matching files
neuralyzer restore             # Choose a backup to restore
```

Close your agents before running `clean`. It skips files modified in the last 120 seconds and asks for a backup password and confirmation. Use `neuralyzer restore <NAME>` to restore a specific backup. [Backup and restore behaviour](docs/SAFETY.md)

Neuralyzer detects secrets such as API keys, tokens and passwords, plus personal data such as emails, phone numbers and payment card numbers. It replaces matches with tokens such as `[EMAIL:3f9a1c2e]`. Reports include counts, types and file paths.

## Common options

| Option | Use |
| --- | --- |
| `scan --only claude,codex` | Scan selected agents. |
| `scan --root ~/scrub-test` | Scan a copy of your session folders. Preserve their home-relative paths and copy with `cp -Rp` to keep timestamps. Use the same root for `clean`. |
| `scan --also PATH` | Include an extra file or directory. Repeat the flag for more paths. |
| `scan --json` | Write the report to stdout as JSON. |
| `-j half scan` | Use half the logical CPUs. Also accepts a thread count, `max` or `p-cores`. |
| `--low-priority scan` | Run the scan at lower OS scheduling priority. |

Use `neuralyzer <command> --help` for command options. `scan` exits with 0 for no findings, 1 for findings and 2 for an error. Set `NEURALYZER_DATA_DIR` to put backups and reports in a separate directory when testing on a copy. [Configuration reference](docs/CONFIG.md)

## Experimental NER

Named entity recognition (NER) is off by default. Pass `--ner` to `scan` or `clean` to look for names, addresses, organisations and dates of birth in prose. Set `ner = true` under `[defaults]` to opt in persistently. Use `--no-ner` to override that setting for one run.

The first NER run downloads a model of about 205 MB. Run `neuralyzer model fetch` to download it ahead of time. Inference runs locally and can take much longer than a standard scan. [NER performance and tuning](docs/NER_PERFORMANCE.md)

## Development and licence

Run `cargo test --workspace --locked` for the test suite. [Development guide](AGENTS.md)

MIT. The README image is a still from *Men in Black* and is used for identification. [Licence](LICENSE)
