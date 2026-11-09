# Configuration

sesscrub reads an optional TOML file. Without one, it uses the defaults. Command-line flags override the config where both set the same thing, as the reference below notes.

## Where the file lives

| OS | Default path |
|---|---|
| macOS | `~/Library/Application Support/sesscrub/config.toml` |
| Linux | `~/.config/sesscrub/config.toml` |
| Windows | `%APPDATA%\sesscrub\config.toml` |

To use another file, pass `--config FILE` or set `SESSCRUB_CONFIG`. The flag takes precedence over the variable. `--config` must point at an existing file, and sesscrub stops with an error if it does not. A missing file at the default path, or at the path in `SESSCRUB_CONFIG`, means the defaults are used. Run with `-v` to see which file was loaded.

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
| `[allowlist]` | `exact` | list of strings | empty | Values that are never redacted. |
| `[allowlist]` | `regex` | list of strings | empty | Findings whose value matches any regex are kept as they are. |
| `[[patterns]]` | `name` | string | required | Shown in the report as `custom:<name>`. |
| `[[patterns]]` | `type` | string | `SECRET` | Token label. Converted to upper case, with other characters replaced by `_`, so `customer-id` becomes `CUSTOMER_ID`. |
| `[[patterns]]` | `regex` | string | required | Rust regex syntax. |
| `[[patterns]]` | `group` | integer | `0` | Capture group to redact. `0` redacts the whole match. |
| `[ner]` | `threshold` | float | `0.5` | Minimum confidence for an NER finding. |
| `[ner]` | `labels` | list of strings | person, address, organization, date of birth | Labels asked of the model. Labels map to `PERSON`, `ADDRESS`, `ORG` and `DOB`, and any other label becomes its own upper-case token type. |
| `[ip]` | `enabled` | boolean | `true` | Detect public IPv4 addresses. |
| `[ip]` | `include_private` | boolean | `false` | Also redact private IPv4 ranges. |

Each section is optional, and so is every key within it.

## Environment variables

| Variable | Effect |
|---|---|
| `SESSCRUB_CONFIG` | Config file to use instead of the default path. |
| `SESSCRUB_DATA_DIR` | Data directory for backups, reports, the model and `hmac.key`. |
| `SESSCRUB_MODEL_DIR` | Directory for the NER model. |
| `SESSCRUB_NO_DOWNLOAD` | Never download the NER model. |
| `SESSCRUB_NO_KEYRING` | Skip the OS keychain when looking for the backup password. |
| `SESSCRUB_PASSWORD` | Backup password. sesscrub prints a warning when it is used. See [SAFETY.md](SAFETY.md). |
| `NO_COLOR` | Turn off coloured output. |

These variables change where sesscrub looks for session data. They are ignored when `--root` is set.

| Variable | Location it affects |
|---|---|
| `VSCODE_PORTABLE` | Portable VS Code user data, read from `user-data/User`. |
| `VSCODE_APPDATA` | Folder that contains the VS Code `Code` and `Code - Insiders` folders. |
| `XDG_CONFIG_HOME` | VS Code user data on Linux, in addition to `~/.config`. |
| `COPILOT_HOME` | Copilot CLI home directory. |
| `XDG_STATE_HOME` | Adds `$XDG_STATE_HOME/.copilot` for Copilot CLI. |
| `XDG_DATA_HOME` | Adds OpenCode and omp data directories. |
| `OPENCODE_DB` | Exact OpenCode database file. |
| `PI_CODING_AGENT_DIR` | omp agent directory. |
