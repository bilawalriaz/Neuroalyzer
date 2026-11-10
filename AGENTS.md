# AGENTS.md

A guide for people and coding agents who use or work on neuroalyzer. Read it before you change code. The user docs are [README.md](README.md). The safety design is in [docs/SAFETY.md](docs/SAFETY.md) and [docs/STATE_MACHINES.md](docs/STATE_MACHINES.md).

## What Neuroalyzer is

Neuroalyzer is a single Rust binary. It finds the session data that AI coding agents keep on disk, makes an encrypted backup of every file it is about to change, then redacts secrets and personal data in place. `restore` puts the original bytes back.

Supported tools (`--only` names): `claude`, `codex`, `gemini`, `copilot`, `opencode`, `hermes`, `openclaw`, `droid`, `pi`, `omp`.

## Using it

### Get a binary. Don't build unless you need to.

A release build compiles ONNX Runtime bindings and LTO, which takes several minutes. Download a release instead:

```sh
# Pick one target: aarch64-apple-darwin, x86_64-apple-darwin,
# x86_64-unknown-linux-gnu, x86_64-pc-windows-msvc (.zip)
T=aarch64-apple-darwin
gh release download --repo bilawalriaz/neuroalyzer --pattern "*-$T.tar.gz" --pattern SHA256SUMS.txt --dir /tmp/neuroalyzer
cd /tmp/neuroalyzer && shasum -a 256 --ignore-missing -c SHA256SUMS.txt
tar -xzf neuroalyzer-*-$T.tar.gz neuroalyzer && ./neuroalyzer --version
```

Without `gh`, use `https://github.com/bilawalriaz/neuroalyzer/releases/latest/download/neuroalyzer-vX.Y.Z-<target>.tar.gz`. The file name includes the version, so check `releases/latest` for the current one.

To compare with a dev build: `cargo build --release` gives `target/release/neuroalyzer`. Use `--no-default-features` if the ONNX Runtime download (`parcel.pyke.io`) is blocked. You lose only NER.

### Safe workflow

```sh
neuroalyzer list                         # what exists, per tool
neuroalyzer scan --no-ner                # read-only report, exit 1 if anything found
neuroalyzer scan --only claude,codex     # limit to some tools
neuroalyzer clean                        # backup (asks for a password) -> redact
neuroalyzer restore                      # list backups; restore <NAME> to undo
```

- Close the agents first. Files modified in the last 120 s are skipped (`--min-age`).
- Try it on a copy: `cp -Rp` the agent dirs into `~/scrub-test`, then pass `--root ~/scrub-test` to every command. `-p` keeps mtimes, or pass `--min-age 0`.
- For automation: `--json`, `-y`, `--password-file FILE` (mode 0600) or `--password-stdin`. A non-interactive `restore` needs the archive name. It is printed by `clean` and is `archive` in `clean --json`.
- `NEUROALYZER_DATA_DIR` moves backups, reports, the model and `hmac.key`. Set `NEUROALYZER_NO_KEYRING=1` in CI and on headless machines.
- NER (names, addresses, orgs) downloads a 205 MB model on first use. Pass `--no-ner` for fast runs, or run `neuroalyzer model fetch` once.

## Developing

### Commands (the same ones CI runs)

```sh
cargo build --workspace --locked
NEUROALYZER_NO_KEYRING=1 cargo test --workspace --locked
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --locked --no-default-features -- -D warnings
```

CI (`.github/workflows/ci.yml`) runs these on Linux, macOS and Windows. It also runs `cargo audit` and a gitleaks scan of the git history. Never commit real session data or real secrets, including in test fixtures. Build test values at runtime, as `tests/agents.rs` does.

Dev builds compile dependencies at `opt-level = 2`, so tests run at a usable speed. The first build is slow, and later builds are incremental.

### Layout

| Path | What it does |
|---|---|
| `src/discovery.rs` | Registry of tools → base dirs (per OS, env overrides) → glob patterns → `Format` + `Schema`. **Start here to add an agent.** |
| `src/engine.rs` | Per-file processing: JSON/JSONL/text splicing, zstd wrap, schema drift checks. |
| `src/sqlite.rs` | SQLite scan and in-place update. Skips FTS and WITHOUT ROWID tables. Uses secure_delete, VACUUM and WAL truncate. |
| `src/known.rs` | Finds project dirs from session metadata (`cwd`) and pulls secret values from their `.env` files. |
| `src/detect/` | Detectors: vendored gitleaks rules, PII validators (Luhn, mod 97, mod 11, ...), tabular heuristic. |
| `src/ner.rs`, `src/prose.rs` | GLiNER NER (feature `ner`) and the decision about which strings count as prose. |
| `src/jsonscan.rs` | Byte-preserving JSON string scanner. Only string values change, and every other byte stays identical. |
| `src/backup.rs`, `src/password.rs` | age-encrypted tar.zst archives, after-hash sidecar, journal, restore. |
| `src/run.rs` | Orchestrates `scan` / `clean` / `restore`: locking, active-file checks, check-then-act writes. |
| `src/report.rs`, `src/token.rs` | Reports, and HMAC tokens such as `[EMAIL:3f9a1c2e]`. |
| `rules/` | Vendored gitleaks config. |
| `crates/fixturegen` | Synthetic fixture trees for e2e tests (copilot, opencode and omp only). |
| `tests/e2e.rs` | Round trip, recall, leak search, passwords, locking, fault injection (`NEUROALYZER_TEST_FAULT`, debug builds). |
| `tests/agents.rs` | Discovery and a clean/restore round trip for claude, codex (incl. `.jsonl.zst`), gemini, hermes, openclaw, droid and pi. |
| `docs/FORMATS.md` | Per-tool storage research with upstream permalinks. Keep it in sync with `discovery.rs`. |
| `scripts/package-linux.sh` | Builds the Linux tarball, `.deb` and `.rpm` from the release binary and enforces the glibc 2.35 floor. |
| `scripts/verify-linux.sh` | Installs and runs the Linux artifacts on Ubuntu and Fedora in Docker. Run by CI and by the release workflow. |
| `packaging/nfpm.yaml` | nfpm config for the `.deb` and `.rpm`. |

### Adding a new agent

1. **Research the storage** from upstream source where you can, and pin a commit. Record the paths, the env overrides, the file formats and the files that hold credentials. Add a section to `docs/FORMATS.md`.
2. **Register it** in `src/discovery.rs`:
   - Add `("name", "Display name")` to `TOOLS`. The name is what `--only` takes.
   - Add a `Base` variant and its arm in `Env::bases`. Push the default home-relative dir. Put env-var overrides inside `if !self.rooted`, because `--root` must ignore the environment.
   - Add `loc(...)` entries to `REGISTRY`. Use a precise glob for each kind of file. **Never glob credential stores** (`auth.json`, OAuth files, `credentials.sqlite`, `.env` in the agent home). Redacting a token there logs the user out.
   - Reuse `Schema::Generic` unless you need a drift check or project-dir hints. If you add a `Schema` variant, handle it in `Schema::name`, `engine::schema_drift`, and optionally in `known::project_dirs` (extract `cwd`) and the `expected_ok` check in `sqlite.rs`.
3. **New on-disk encodings** need a `Format` variant. `JsonlZst` is the example: it decodes in `Engine::process_zst`, reuses the JSONL path and re-encodes. `run::fmt_name` and `sniff_format` (for `--also`) need entries too. The backup always stores the raw on-disk bytes, so restore stays byte-identical.
4. **SQLite**: FTS virtual tables and their shadow tables are skipped. Check that the app keeps its FTS in sync with triggers or rebuilds it. External-content FTS without triggers would go stale.
5. **Test**: add the tool to `tests/agents.rs`. Plant a value, `clean`, assert it is gone from the raw bytes and the file still parses, `restore`, and assert byte-identical. Then do a quick real check: `cargo build --release && ./target/release/neuroalyzer scan --only <tool> --no-ner`, and look at the "format drift" section.
6. **Docs**: update the README ("What gets touched" and the intro list), `--only` help and `ABOUT` in `src/main.rs`, env vars in `docs/CONFIG.md`, and the tool list in this file.

### Invariants: don't break these

- Back up first, verify the backup, then write. The backup is decrypted and every hash checked before any session file changes.
- Check then act: a file is re-hashed under lock just before it is written, and skipped if it changed. SQLite writes happen inside `BEGIN IMMEDIATE`, after the precheck.
- Only JSON string values change. Keys and structure stay byte-identical, and rewritten records are re-parsed before commit.
- Reports never contain the matched values, only counts, types and paths.
- No network calls apart from the opt-in model download.
- `scan` writes nothing except the report. Read-only SQLite opens use `immutable=1` when there is no WAL.

See `docs/STATE_MACHINES.md` before you touch `run.rs` or `backup.rs`.

## Releasing

Releases come from the `version` in `Cargo.toml`. `.github/workflows/release.yml` runs on every push to `main`:

1. The `check version` job reads `version` and looks for a GitHub release named `v<version>`.
2. If there is none, it builds the four targets and publishes release `v<version>` as **latest**: a `.tar.gz` per target, plus a `.deb` and an `.rpm` for Linux, with `.sha256` files and a combined `SHA256SUMS.txt`. The tag is created at the merged commit, and release notes are generated from the PRs.
3. A `verify` job downloads the published Linux assets, checks they are not stubs, installs the `.deb` and `.rpm` and runs the binary on Ubuntu 22.04/24.04 and Fedora 41/latest.
4. If the release already exists, the workflow does nothing.

Linux is built on `ubuntu-22.04` so `scripts/package-linux.sh` can enforce a glibc 2.35 floor; that single binary is shipped three ways. Never move the Linux build to `ubuntu-latest`: its newer glibc produces a binary that fails with `GLIBC_2.xx not found` on every supported distribution. `scripts/package-linux.sh` and `scripts/verify-linux.sh` are also run by the `linux-packages` CI job.

So, to ship:

```sh
# in your PR
sed -i '' 's/^version = ".*"/version = "1.3.0"/' Cargo.toml   # GNU sed: drop the ''
cargo build                                                  # updates Cargo.lock
git commit -am "Release 1.3.0"
# merge the PR -> release v1.3.0 appears in a few minutes
gh run list --repo bilawalriaz/neuroalyzer --workflow release.yml --limit 3
gh release view --repo bilawalriaz/neuroalyzer
```

Pushing a tag by hand (`git tag v1.3.0 && git push origin v1.3.0`) also works. The tag must match `Cargo.toml`, or the run fails. Use semver: bump the minor version for new agents or features, and the patch version for fixes. To retry a failed release, delete the partial release if one exists and run `gh workflow run release.yml --repo bilawalriaz/neuroalyzer`.
