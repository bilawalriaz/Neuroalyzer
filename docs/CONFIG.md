# Configuration

Neuralyzer reads an optional TOML file. Without one, it uses the defaults. Command-line flags override the config where both set the same thing, as the reference below notes.

## Where the file lives

| OS | Default path |
|---|---|
| macOS | `~/Library/Application Support/neuralyzer/config.toml` |
| Linux | `~/.config/neuralyzer/config.toml` |
| Windows | `%APPDATA%\neuralyzer\config.toml` |

To use another file, pass `--config FILE` or set `NEURALYZER_CONFIG`. The flag takes precedence over the variable. `--config` must point at an existing file, and Neuralyzer stops with an error if it does not. A missing file at the default path, or at the path in `NEURALYZER_CONFIG`, means the defaults are used. Run with `-v` to see which file was loaded.

The file is strict. An unknown key or section is an error, and the message names the file. Check spelling when a run fails after you edit the config.

TOML does not expand `~`, so write full paths in `also`.

## Example

This example lists every key. Delete the ones you do not need.

```toml
[defaults]
# Tools to include when --only is not given.
only = ["copilot", "opencode", "omp"]
# Extra files or directories to scan, as with --also.
also = ["/Users/me/notes"]
# Run the NER model. Only has an effect in builds with the ner feature.
ner = true
# Number of backups to keep.
keep = 5
# CPU threads for scanning, as with -j: a number, "max", "half" or "p-cores".
threads = "max"
# Run at low priority, as with --low-priority.
low_priority = false

[allowlist]
# Values that are never redacted. Exact match.
exact = ["support@example.com"]
# Regexes. A finding whose value matches any of them is not redacted.
regex = ['^build-[0-9]+$']

[[patterns]]
# Redacts every match. Shows up in the report as custom:customer-id.
name = "customer-id"
type = "CUSTOMER_ID"
regex = 'CUST-[0-9]{6}'
group = 0

[[patterns]]
# Redacts only the first capture group, so the key name stays in place.
name = "customer-ref"
type = "SECRET"
regex = 'customer_ref=([A-Za-z0-9]{12})'
group = 1

[ner]
threshold = 0.5
labels = ["person", "address", "organization", "date of birth"]
# Model workers, threads per worker, chunks per call and device. Leave them
# out for defaults picked from your CPU (one single-threaded worker per core).
sessions = 12
threads = 1
batch = 1
device = "auto"

[ip]
enabled = true
include_private = false
```

Write regexes as TOML literal strings (single quotes), so backslashes need no escaping. Custom patterns use Rust regex syntax, which has no look-around or backreferences. A pattern that does not compile stops the run with an error that names the pattern.

## Reference

| Section | Key | Type | Default | Notes |
|---|---|---|---|---|
| `[defaults]` | `only` | list of strings | all tools | Used when `--only` is not given. The flag replaces the list. |
| `[defaults]` | `also` | list of paths | empty | Added to any `--also` paths. |
| `[defaults]` | `ner` | boolean | `true` in default builds | `--ner` and `--no-ner` override it. |
| `[defaults]` | `keep` | integer | `5` | `--keep` overrides it. Values below 1 keep one backup. |
| `[defaults]` | `threads` | string | `auto` (every logical CPU) | Scan threads: a number, `max`, `half` or `p-cores`. `-j` and `NEURALYZER_THREADS` override it. |
| `[defaults]` | `low_priority` | boolean | `false` | Background QoS on macOS, nice 10 on Linux, below-normal on Windows. `--low-priority` and `NEURALYZER_LOW_PRIORITY` override it. |
| `[allowlist]` | `exact` | list of strings | empty | Values that are never redacted. |
| `[allowlist]` | `regex` | list of strings | empty | Findings whose value matches any regex are kept as they are. |
| `[[patterns]]` | `name` | string | required | Shown in the report as `custom:<name>`. |
| `[[patterns]]` | `type` | string | `SECRET` | Token label. Converted to upper case, with other characters replaced by `_`, so `customer-id` becomes `CUSTOMER_ID`. |
| `[[patterns]]` | `regex` | string | required | Rust regex syntax. |
| `[[patterns]]` | `group` | integer | `0` | Capture group to redact. `0` redacts the whole match. |
| `[ner]` | `threshold` | float | `0.5` | Minimum confidence for an NER finding. |
| `[ner]` | `sessions` | integer | one per physical core, within `threads` | Parallel model workers. `--ner-sessions` overrides it. |
| `[ner]` | `threads` | integer | `1` | Threads per worker. With more, the default worker count shrinks to match. `--ner-threads` overrides it. |
| `[ner]` | `batch` | integer | `1` | Chunks per model call. Larger batches measured slower with this model. `--ner-batch` overrides it. |
| `[ner]` | `device` | string | `auto` | `auto`, `cpu`, `coreml`, `cuda` or `directml`. All but `auto` and `cpu` need a build with that cargo feature. `auto` uses CUDA or DirectML when built in and working, otherwise the CPU. CoreML is never picked automatically: it measured slower than the CPU for this model. `--ner-device` overrides it. |
| `[ner]` | `labels` | list of strings | person, address, organization, date of birth | Labels asked of the model. Labels map to `PERSON`, `ADDRESS`, `ORG` and `DOB`, and any other label becomes its own upper-case token type. |
| `[ip]` | `enabled` | boolean | `true` | Detect public IPv4 addresses. |
| `[ip]` | `include_private` | boolean | `false` | Also redact private IPv4 ranges. |

Each section is optional, and so is every key within it. Where a flag, a variable and a key all set the same thing, the flag wins, then the variable, then the key.

## Environment variables

| Variable | Effect |
|---|---|
| `NEURALYZER_CONFIG` | Config file to use instead of the default path. |
| `NEURALYZER_DATA_DIR` | Data directory for backups, reports, the model and `hmac.key`. |
| `NEURALYZER_MODEL_DIR` | Directory for the NER model. |
| `NEURALYZER_NO_DOWNLOAD` | Never download the NER model. |
| `NEURALYZER_THREADS` | Scan threads, like `-j`. |
| `NEURALYZER_LOW_PRIORITY` | `true` to run at low priority, like `--low-priority`. |
| `NEURALYZER_NER_SESSIONS`, `NEURALYZER_NER_THREADS`, `NEURALYZER_NER_BATCH`, `NEURALYZER_NER_DEVICE` | Like the `--ner-*` flags. |
| `NEURALYZER_NO_KEYRING` | Skip the OS keychain when looking for the backup password. |
| `NEURALYZER_PASSWORD` | Backup password. Neuralyzer prints a warning when it is used. See [SAFETY.md](SAFETY.md). |
| `NO_COLOR` | Turn off coloured output. |

These variables change where Neuralyzer looks for session data. They are ignored when `--root` is set.

| Variable | Location it affects |
|---|---|
| `VSCODE_PORTABLE` | Portable VS Code user data, read from `user-data/User`. |
| `VSCODE_APPDATA` | Folder that contains the VS Code `Code` and `Code - Insiders` folders. |
| `XDG_CONFIG_HOME` | VS Code user data on Linux, in addition to `~/.config`. |
| `COPILOT_HOME` | Copilot CLI home directory. |
| `XDG_STATE_HOME` | Adds `$XDG_STATE_HOME/.copilot` for Copilot CLI. |
| `XDG_DATA_HOME` | Adds OpenCode and omp data directories. |
| `OPENCODE_DB` | Exact OpenCode database file. |
| `PI_CODING_AGENT_DIR` | omp/pi agent directory. |
| `CLAUDE_CONFIG_DIR` | Claude Code config directory (default `~/.claude`). |
| `CODEX_HOME` | Codex CLI home (default `~/.codex`). |
| `GEMINI_CLI_HOME` | Adds `$GEMINI_CLI_HOME/.gemini` for Gemini CLI. |
| `HERMES_HOME` | Hermes Agent home (default `~/.hermes`, or `%LOCALAPPDATA%\hermes` on Windows). |
| `OPENCLAW_STATE_DIR` | OpenClaw state directory (default `~/.openclaw`; legacy `~/.clawdbot` and `~/.moltbot` are also checked). |
