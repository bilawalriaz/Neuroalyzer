# Progress

Working notes so the build can resume if interrupted.

| Milestone | State |
|---|---|
| 1. Repo, CI skeleton, format research, discovery, `list` | done |
| 2. Fixture generator, `scan`, secrets, structured PII, known values, report | done |
| 3. Passwords, encrypted backup, `clean`, `restore`, round-trip tests | done |
| 4. Tabular heuristic, generic-format fallback | done |
| 5. GLiNER NER, feature flag, dedupe, batching, `model fetch`, benchmarks | done (bench numbers pending) |
| 6. Config, allowlist, keychain, prose pass, README, v0.1.0 | in progress: docs written, awaiting green CI and tag |

## Decisions

- Redaction splices tokens into the original bytes of each JSON string value instead of re-serialising the document, so untouched bytes stay identical. Rewritten records are re-parsed before commit.
- After-hashes live in an encrypted sidecar (`*.after.age`) so the archive itself is write-once and verified before any session file changes.
- SQLite: secure_delete, one transaction, then VACUUM and `wal_checkpoint(TRUNCATE)`. VACUUM was needed: the app's own earlier updates leave old plaintext in free pages.
- Read-only scans open SQLite with `immutable=1` when no WAL exists, so scan creates no -wal/-shm files.
- gitleaks rules: the common terminator `(?:[\x60'"\s;]|\\[nr]|$)` is widened to also accept `.,)]}>`, since in prose a token often ends a sentence.
- VS Code `state.vscdb`: only ItemTable rows whose key mentions chat/copilot/interactive are touched.

## Test status

`cargo test --workspace`: unit tests plus tests/e2e.rs (scan, clean, raw-byte leak search, validity, byte-identical restore, wrong password, password sources, insecure password file, active and locked files, format drift).
