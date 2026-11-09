# Session storage formats

What sesscrub knows about each tool's local storage, with links to the upstream source it was read from. The research was done on 2026-11-09 against the commits pinned below. Formats change: sesscrub treats this knowledge as a fast path and falls back to generic handling (every JSON string, every SQLite TEXT cell, every text line) when a file doesn't match, noting it as "format drift" in the report.

Anything marked UNVERIFIED was not confirmed from source.

## GitHub Copilot

Source pins (shallow clones, HEAD at research time, 2026-11-09):
- microsoft/vscode-copilot-chat `5863f5a7088958050792b5dccbe8b46c6e13eccc`
- microsoft/vscode `b779fd6892995e708354d32b822e5287b699d8cd`
- github/copilot-cli `2e935d3612dcfac71c3a76842794e8c7d93c5fd3` (repo holds only README, changelog, install.sh, container/; CLI source is not in it)
- npm `@github/copilot@1.0.107` (native Bun-style binary, 191 MB; no readable storage-path literals found)

Permalinks below use `blob/<sha>/<path>#L<n>`.

### 1. VS Code Copilot Chat (chat history lives in VS Code core, not the extension)

- **Copilot Chat extension stores no session history itself.** Searching vscode-copilot-chat for `chatSessions`, `state.vscdb`, `workspaceStorage`, `interactive.sessions` finds only the CLI paths below. The chat panel history is written by VS Code core's `ChatSessionStore`:
  https://github.com/microsoft/vscode/blob/b779fd6892995e708354d32b822e5287b699d8cd/src/vs/workbench/contrib/chat/common/model/chatSessionStore.ts#L39-L40 (index key `chat.ChatSessionStore.index`, transfer key `ChatSessionStore.transferIndex`)
- **Storage roots** (`chatSessionStore.ts#L66-L79`):
  - Workspace window: `<workspaceStorageHome>/<workspaceId>/chatSessions/`
  - Empty window: `<globalStorageHome>/emptyWindowChatSessions/` (legacy `<workspaceStorageHome>/no-workspace/chatSessions/`)
  - Transfers: `<globalStorageHome>/transferredChatSessions/`
- **Per-session files:** `<sessionId>.jsonl` (current) and `<sessionId>.json` (pre-1.109 flat format). The store writes `.jsonl` unless setting `chat.useLogSessionStorage` is false (`chatSessionStore.ts#L738-L740`, writes at `#L353-L394`). Reads accept both, and migration copies only `.json`/`.jsonl` files (`#L152`).
- **Path roots** (`src/vs/platform/environment/common/environmentService.ts`):
  - `appSettingsHome = <userDataPath>/User` (https://github.com/microsoft/vscode/blob/b779fd6892995e708354d32b822e5287b699d8cd/src/vs/platform/environment/common/environmentService.ts#L56)
  - `workspaceStorageHome = <appSettingsHome>/workspaceStorage` (same file, `#L86`)
  - `globalStorage` sits beside `storage.json` under `User/` (`#L65`). That `User/globalStorage` location is inferred from `#L65`, not a direct read of `globalStorageHome`.
- **userDataPath resolution** (`src/vs/platform/environment/node/userDataPath.ts`):
  - Precedence (`doGetUserDataPath`): `VSCODE_PORTABLE` → `<portable>/user-data`; `VSCODE_APPDATA` → `<appdata>/<productName>`; `--user-data-dir` CLI flag; then per-OS default.
  - Per-OS default: macOS `~/Library/Application Support/<nameShort>` (`#L95`); Linux `$XDG_CONFIG_HOME` or `~/.config`, then `/<nameShort>` (`#L98`); Windows `%APPDATA%\<nameShort>` (fallback `%USERPROFILE%\AppData\Roaming`, `#L84`).
  - `<nameShort>` comes from `productService.nameShort`. Stable is "Code". The OSS `product.json` sets `dataFolderName: ".vscode-oss"` (https://github.com/microsoft/vscode/blob/b779fd6892995e708354d32b822e5287b699d8cd/product.json#L5), not the Microsoft build.
  - Insiders: `<nameShort>` = "Code - Insiders" (UNVERIFIED: the string is not in the OSS repo; check the Insiders product.json).
- **Resulting paths** (stable; swap in Insiders' `<nameShort>` and its user-data root):
  - macOS: `~/Library/Application Support/Code/User/workspaceStorage/<wsId>/chatSessions/<sid>.jsonl`
  - Linux: `~/.config/Code/User/workspaceStorage/<wsId>/chatSessions/<sid>.jsonl`
  - Windows: `%APPDATA%\Code\User\workspaceStorage\<wsId>\chatSessions\<sid>.jsonl`
  - Empty window: `.../User/globalStorage/emptyWindowChatSessions/<sid>.jsonl`
- **Index (`chat.ChatSessionStore.index`):** stored with `storageService.store()`, so it lives in SQLite `state.vscdb` (table name not checked).
  - Workspace scope → `workspaceStorage/<wsId>/state.vscdb` (`storageMain.ts#L424-L429`, https://github.com/microsoft/vscode/blob/b779fd6892995e708354d32b822e5287b699d8cd/src/vs/platform/storage/electron-main/storageMain.ts#L424-L429)
  - Application scope (empty window) → `globalStorage/state.vscdb` (`storageMain.ts#L294-L298`)
  - Scope selection: `chatSessionStore.ts#L432-L436`. Index shape: `{version:1, entries:{[sid]: metadata}}`, validated at `#L845-L846`, read at `#L547-L560`.
- **Format of `.jsonl`** (object-mutation log, one JSON value per line, `\n` terminated):
  - Entry kinds (`objectMutationLog.ts#L195-L215`): `0`=Initial `{kind:0,v:<whole ISerializableChatData>}`; `1`=Set `{kind:1,k:[path],v}`; `2`=Push `{kind:2,k,v?:[...],i?}`; `3`=Delete `{kind:3,k}`. Lines are appended with `\n` (`#L339`, `#L419`, `#L448`).
  - Schema is `chatSessionOperationLog.ts#L206-L222`. Top-level keys: `version` (=3), `creationDate`, `customTitle`, `initialLocation`, `inputState`, `responderUsername`, `sessionId`, `requests`, `hasPendingEdits`, `repoData`, `pendingRequests`, `workingDirectory`, `sessionCostInfo`.
  - Flat `.json` payload is the same `ISerializableChatData` (`chatModel.ts#L2380-L2387` for v3, alias at `#L2574`).
- **Field locations:**
  - `requests[]` items are `ISerializableChatRequestData` (`chatModel.ts#L2229`).
  - User text: `requests[i].message` is `IParsedChatRequest` = `{text, parts[]}` (`src/vs/workbench/contrib/chat/common/requestParser/chatParserTypes.ts#L21-L24`). Old format is a bare string.
  - Attached context: `requests[i].variableData.variables[]` (`chatModel.ts#L122-L124`).
  - Response: `requests[i].response` is an array of parts. Markdown parts are stored as plain strings (`content`), not `{value}` (`chatSessionOperationLog.ts#L44-L45`). Other parts serialize by `kind` (tool invocations, etc.).
  - `result` (agent metadata) is `requests[i].result`, typed `IChatAgentResult` (`chatModel.ts#L2197-L2226` `ISerializableChatResponseData`).
  - The `response[].value` form in older notes is not current.
  - Tool output is inside serialized tool-invocation parts (not separately audited in this pass).
- **Not present in current upstream (treat as legacy, UNVERIFIED):** ItemTable keys `interactive.sessions` and `memento/interactive-session`. Searches of `src/` found no live use.
- **Chat editing sessions:** `workspaceStorage/<wsId>/chatEditingSessions/<key>/state.json` plus `contents/<hash>` blobs (`src/vs/workbench/contrib/chat/browser/chatEditing/chatEditingSessionStorage.ts#L23`, `#L45-L46`, `#L95`, `#L199`).

### 2. Copilot CLI (`copilot`, npm `@github/copilot`)

- **Home directory:** `~/.copilot` by default.
  - Changelog: "New sessions are stored in `~/.copilot/session-state`. Legacy sessions are stored in `~/.copilot/history-session-state`" (https://github.com/github/copilot-cli/blob/2e935d3612dcfac71c3a76842794e8c7d93c5fd3/changelog.md#L4707-L4708).
  - Legacy `$XDG_CONFIG_HOME/.copilot` is migrated into `~/.copilot` (`changelog.md#L158`).
  - `COPILOT_HOME` is documented as "where the CLI stores its configuration and state" (`container/README.md#L60`, https://github.com/github/copilot-cli/blob/2e935d3612dcfac71c3a76842794e8c7d93c5fd3/container/README.md#L60). Also honored for `--config-dir` and discovery registry (`changelog.md#L2815`, `#L3145`).
- **Conflict:** copilot-chat resolves session-state as `$XDG_STATE_HOME/.copilot/session-state` if set, else `~/.copilot/session-state` (https://github.com/microsoft/vscode-copilot-chat/blob/5863f5a7088958050792b5dccbe8b46c6e13eccc/src/extension/chatSessions/copilotcli/node/cliHelpers.ts#L13-L26). VS Code core resolves it under `<COPILOT_HOME>/session-state/<rawId>/events.jsonl` (`src/vs/workbench/contrib/chat/browser/copilotCliEventsUri.ts#L26-L33`, copilot home from `src/vs/platform/environment/common/copilotHome.ts#L20-L21`: `COPILOT_HOME || ~/.copilot`). Behavior with both variables set is UNVERIFIED.
- **Layout per session:** `~/.copilot/session-state/<sessionId>/`
  - `events.jsonl`: event log (see below).
  - `workspace.yaml`: copilot-chat copies it on fork and rewrites the session id (`copilotcliSessionService.ts#L1313-L1318`). Its field names are UNVERIFIED.
  - `plan.md`, `files/`, `checkpoints/`: referenced in copilot-chat (`copilotCLITerminalLinkProvider.ts#L407`) and in a GitHub docs page (https://docs.github.com/en/enterprise-cloud@latest/copilot/how-tos/copilot-cli/cli-best-practices), which describes `events.jsonl`, `workspace.yaml`, `plan.md`, `checkpoints/`.
- **Other paths (changelog):** user settings in `~/.copilot/settings.json` (`changelog.md#L3213`); `config.json` holds internal state and `trustedFolders` (`changelog.md#L1484`); logs in `~/.copilot/logs/` (`#L2935`); usage metrics appended to `events.jsonl` at session end (`#L3844`).
- **Env overrides:** `COPILOT_HOME` (above). `XDG_STATE_HOME` affects copilot-chat's path resolution only. No `COPILOT_SESSION_*` storage override was found.
- **events.jsonl format** (JSON Lines, one object per line):
  - Envelope: `{id, type, timestamp, parentId, data}`. Shown by the test fixture at `src/extension/chatSessions/copilotcli/node/test/copilotCliSessionService.spec.ts#L318-L322` (test data, not production).
  - Read loop: `readSessionEventsFile` in `copilotcliSessionService.ts#L1093-L1113`. Blank lines skipped, each line JSON-parsed.
  - `session.start`: `data` has `sessionId, startTime, selectedModel, version, producer, copilotVersion, context:{cwd, gitRoot, repository}` (fixture; field list from `copilotcliSessionService.ts#L948`).
  - `user.message`: `data.content` (user text), `data.attachments[]` with `type` in {selection, github_reference, blob, file, directory} (`src/extension/chatSessions/copilotcli/common/copilotCLITools.ts#L565-L622`).
  - `assistant.message`: `data.content`, `data.messageId`, `data.parentToolCallId` (sub-agent markdown when set). See `copilotCLITools.ts#L680-L684`.
  - `assistant.message_delta`: `data.deltaContent`, `data.messageId` (`copilotCLITools.ts#L666-L674`).
  - `tool.execution_start` / `tool.execution_complete`: tool call and result (`copilotCLITools.ts#L687`, `#L708`). Terminal output is in `data.result.contents[]` with `type:'terminal'`, `text` (`copilotCLITools.ts#L1272`).
  - `subagent.started`, `subagent.completed`, `subagent.failed`: `copilotCLITools.ts#L694-L706`.
  - `session.error`: `data.errorType`, `data.message` (`copilotCLITools.ts#L676-L678`).
  - Full type union is in `@github/copilot/sdk` (not in these repos; the npm bundle did not expose the names as plain strings, so it is UNVERIFIED beyond the above).
- **Forking:** `copilotcliSessionService.ts#L1252-L1268` copies the directory minus `events.jsonl`, `workspace.yaml`, and the metadata file.

### Unverified / open
- VS Code Insiders `nameShort` string and its user-data folder name.
- Table name inside `state.vscdb` for ItemTable.
- Full `workspace.yaml` schema.
- Complete `events.jsonl` event-type list and field shapes beyond those listed.
- Precedence between `COPILOT_HOME` and `XDG_STATE_HOME` for session-state in the CLI itself (the two upstream consumers disagree).
- Legacy `interactive.sessions` / `memento/interactive-session` keys (not in current upstream).
- Exact tool-output shape inside VS Code `.jsonl` tool-invocation parts (not audited).

---

### Follow-up (resolved open items)

- **state.vscdb table name: RESOLVED.** The table is `ItemTable` with schema `CREATE TABLE IF NOT EXISTS ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB);` (https://github.com/microsoft/vscode/blob/b779fd6892995e708354d32b822e5287b699d8cd/src/vs/base/parts/storage/node/storage.ts#L343). Reads use `SELECT * FROM ItemTable` (`storage.ts#L73`). The chat index row is therefore `SELECT value FROM ItemTable WHERE key = 'chat.ChatSessionStore.index'`.
- **Insiders nameShort: still UNVERIFIED.** The OSS repo's `src/vs/platform/product/common/product.ts#L40-L60` only derives a `" Dev"` variant for local dev builds. Insiders' `nameShort` ("Code - Insiders") is not defined in the OSS repo, so it could not be confirmed from source in this pass.


Pinned sources (read from shallow clones of current default branches):
- OpenCode: `anomalyco/opencode` @ `be6b87e` (branch `dev`). Base: https://github.com/anomalyco/opencode/blob/be6b87ef489c12bda9687c41977fc321b5407fc8/
- OpenCode Go (archived): `opencode-ai/opencode` @ `73ee493`. Base: https://github.com/opencode-ai/opencode/blob/73ee493265acf15fcd8caab2bc8cd3bd375b63cb/
- omp: `can1357/oh-my-pi` @ `38be738` (branch `main`). Base: https://github.com/can1357/oh-my-pi/blob/38be7382c55c44e51c88f0c9833bbd5214c6456e/
- Legacy JSON tree: `sst/opencode` tag `v0.3.0` (commit `53bb6b4`). Base: https://github.com/sst/opencode/blob/53bb6b4c4f63d9336dfea1a76fe0f0f9c62b88e7/

Abbreviations below: OC, GO, OMP, OLD = the bases above.

## OpenCode (current, TypeScript monorepo)

### Data dir and overrides
- Data root is `$XDG_DATA_HOME/opencode` when `XDG_DATA_HOME` is set, else `<home>/.local/share/opencode`. The code has no per-OS branch, so macOS, Linux and Windows all get `~/.local/share/opencode`. [OC packages/util/src/global-roots.ts#L5, #L11-L19]
- `Global.Path.data` is that dir; `log` = `data/log`, `repos` = `data/repos`, `bin` = `cache/bin`. [OC packages/util/src/global.ts#L12, and the `paths` object]
- Test-only home override `OPENCODE_TEST_HOME`; config dir override `OPENCODE_CONFIG_DIR`. [OC packages/util/src/global.ts, `paths.home` and `layer`]
- Database file: `OPENCODE_DB` if set (`:memory:` allowed). Otherwise `opencode.db` when the channel is latest/dev/beta/next/prod or `OPENCODE_DISABLE_CHANNEL_DB` is `1`/`true`. Otherwise `opencode-<channel>.db`. [OC packages/cli/src/database-path.ts#L4-L13]
- `opencode debug paths` prints the resolved `db` path. [OC packages/cli/src/commands/handlers/debug/paths.ts]
- Windows path: UNVERIFIED at runtime (read from code only).

### Current storage: one SQLite file, Drizzle schema, no JSON tree
- Session tables (v2): `session_v2` [OC packages/core/src/session/sql.ts#L28], `session_message` [#L86], `session_part` [#L107], `session_inbox` [#L130]. Also `project`, `blob`, `blob_ref`, `event`, `kv`, `instruction_*`, `permission`, `schedule`, `job`, `worktree` (under packages/core/src).
- Legacy `session` was renamed to `session_v2` in migration `20260804233008_loose_psylocke.ts` [OC packages/core/src/database/migration/20260804233008_loose_psylocke.ts#L28].
- `session_message`: `id`, `session_id`, `type` (e.g. `user`, `assistant`, `compaction`, `idle`), `seq` (unique per session), `time_created`, `time_updated`, `data` (JSON, type-specific fields without `type`/`id`).
- `session_part`: `message_id`, `session_id`, `ordinal` (PK with message_id), `type` (`text` | `reasoning` | `tool`), `call_id`, `data` (JSON).
- Message and content schema [OC packages/schema/src/session-message.ts]:
  - User message (`type:"user"`): `text`, `files`, `agents`, `skills`. User prose is in `data.text`. [#L77]
  - Assistant text part `{type:"text", text}` [#L186]. Reasoning part `{type:"reasoning", text, time}` [#L193]. Tool part `{type:"tool", id, name, state, time}` [#L171].
  - Tool `state.status`: `streaming` (`input` is a string), `running` (`input`, `metadata`), `completed` (`input`, `content[]`, `metadata`), `error` (`input`, `error`, optional `content`). [#L136-L165]
  - Tool output is in `state.content` of the tool part in `session_part.data`.
- Union of message types: AgentSelected, ModelSelected, LocationSwitched, User, Synthetic, System, Skill, Shell, Assistant, Compaction, Idle [#L304].

### Legacy v1 tables (same DB file; still read by the importer)
- DDL: `project`, `message`, `part`, `session`, `todo`, `session_share` created in `20260127222353_familiar_lady_ursula.ts` [OC packages/core/src/database/migration/20260127222353_familiar_lady_ursula.ts#L9-L90].
  - `message(id, session_id, time_created, time_updated, data TEXT JSON)` [#L23]
  - `part(id, message_id, session_id, time_created, time_updated, data TEXT JSON)` [#L33]
  - `session(id, project_id, parent_id, slug, directory, title, version, share_url, summary_*, revert, permission, time_*)` [#L53]
- Importer reads `message` and `part` by `session_id` [OC packages/core/src/database/v1-migration.bun.ts#L695-L698]. A separate `opencode-next.db` in the data dir is an alternate import source [#L799-L802].
- v1 part union (`data` JSON): `text`, `subtask`, `reasoning`, `file`, `tool`, `step-start`, `step-finish`, `snapshot`, `patch`, `agent`, `retry`, `compaction` [OC packages/schema/src/v1/session.ts#L357].
  - `text`: `text`, optional `synthetic`, `ignored`, `time` [#L102]
  - `tool`: `callID`, `tool`, `state`, optional `metadata` [#L315]
  - `snapshot`: `snapshot` string [#L87]; `patch`: `hash`, `files[]` [#L94]
- v1 tool state (`state.status`): `pending` (`input`, `raw`), `running` (`input`, `title?`, `metadata?`, `time.start`), `completed` (`input`, `output` string, `title`, `metadata`, `time`, `attachments?`), `error` (`input`, `error`, `time`) [#L259-L313].
- v1 user message: `role:"user"`, `agent`, `model{providerID, modelID}`, optional `summary`, `system`, `tools` [#L332]. v1 assistant: `role:"assistant"`, `parentID`, `modelID`, `providerID`, `mode`, `agent`, `path`, `tokens`, `cost` [#L453].

### Older JSON tree (legacy; verified at tag v0.3.0 only)
- Root: `<data>/storage` [OLD packages/opencode/src/storage/storage.ts#L79]. Generic key API writes `<root>/<key>.json` [#L97-L115].
- Session info: `session/info/<sessionID>.json` [OLD packages/opencode/src/session/index.ts#L147]. Keyed by session ID only, not by project.
- Messages: `session/message/<sessionID>/<messageID>.json` [OLD storage.ts#L49-L61 and session/index.ts#L196].
- Parts: `session/part/<sessionID>/<messageID>/<partID>.json` [OLD storage.ts#L61 and session/index.ts#L198].
- Part types at v0.3.0: `text`, `tool`, `file`, `step-start`, `step-finish` [OLD packages/opencode/src/session/message-v2.ts#L83-L125]. Roles `user` and `assistant` [#L147, #L164].
- The layout `storage/session/<projectID>/<sessionID>.json` from the task brief: NOT found in any checked source. UNVERIFIED for any intermediate version.
- `session_diff/`, `snapshot/` directories: not present in current source (grep of packages/ finds no writer). UNVERIFIED for older versions.

### OpenCode Go (opencode-ai/opencode, archived; Go + SQLite)
- Data dir: `data.directory` config key, default `.opencode` (relative to CWD). [GO internal/config/config.go#L101, #L231]
- DB file: `<dataDir>/opencode.db` (go-sqlite3 driver, goose migrations). [GO internal/db/connect.go#L19-L26]
- Initial schema [GO internal/db/migrations/20250424200609_initial.sql]:
  - `sessions(id, parent_session_id, title, message_count, prompt_tokens, completion_tokens, cost, updated_at, created_at)` [#L4]
  - `files(id, session_id, path, content, version, created_at, updated_at)` [#L24]
  - `messages(id, session_id, role, parts TEXT default '[]', model, created_at, updated_at, finished_at)` [#L47]
- Second migration adds `sessions.summary_message_id` [GO internal/db/migrations/20250515105448_add_summary_message_id.sql].
- `messages.parts` is a JSON array of wrappers `{"type": <t>, "data": {...}}` [GO internal/message/message.go#L166-L172, #L175-L178, marshallParts/unmarshallParts #L180-L280].
  - `text` `{text}`; `reasoning` `{thinking}`; `image_url`; `binary`
  - `tool_call` `{id, name, input (string), type, finished}` [GO internal/message/content.go#L84-L91]
  - `tool_result` `{tool_call_id, name, content (string), metadata, is_error}` [#L94-L100]
  - `finish` `{reason, time}` [#L104-L107]
- User prose: `text` part of a `role="user"` message. Tool output: `tool_result.content`.

## omp (oh-my-pi) (TypeScript on Bun; package `@oh-my-pi/coding-agent`)

- Relation to badlogic/pi-mono: UNVERIFIED (not checked).

### Directories and overrides
- Config root: `~/.omp` (dirname overridable by `PI_CONFIG_DIR`). [OMP packages/utils/src/dirs.ts#L116-L118, #L332-L334]
- Agent dir: `~/.omp/agent`. Overridable by `PI_CODING_AGENT_DIR` for the default profile only. [OMP dirs.ts#L371-L373, #L644-L646; docs/settings.md L26]
- Named profiles: selected by `OMP_PROFILE` or `PI_PROFILE`; config root becomes a profile subtree. [OMP dirs.ts#L44, #L96, getConfigAgentDirName around #L336-L341]
- Sessions root: `<agentDir>/sessions`. [OMP packages/utils/src/dirs.ts#L1010-L1012]
- XDG: applies only on linux or darwin (`xdgPlatform`, dirs.ts#L391-L392). It needs `$XDG_DATA_HOME/omp` to exist, which `omp config init-xdg` creates. Then the sessions root becomes `$XDG_DATA_HOME/omp/sessions`. [OMP dirs.ts#L433-L441] Default layout is still `~/.omp/agent/sessions`.
- Windows: no special-case seen in dirs.ts; uses `%USERPROFILE%\.omp\agent\sessions`. Runtime path UNVERIFIED.

### Per-project subdirectory name
- `sessionDirForCwd(cwd) = <sessionsRoot>/<encodedDirName>` [OMP packages/coding-agent/src/session/session-paths.ts#L222-L224]
- `encodedDirName` [session-paths.ts#L46-L56, #L78-L118]:
  - cwd inside `$HOME`: `-` + relative path with `/`, `\`, `:` replaced by `-`. Example: `~/proj/app` gives `-proj-app`.
  - cwd inside OS temp dir: `-tmp-<relative>`.
  - otherwise: `--<absolute path, separators to ->--`.
- Hashed variants (`home-…-<sha256>`) exist only for migrating older names.

### Session files (JSONL)
- File name: `<timestamp with ":" and "." replaced by "-">_<sessionId>.jsonl` [session-manager.ts#L169-L171, #L2119]
- Header is the first entry, `{"type":"session","version":3,"id","timestamp","cwd", ...}`. `CURRENT_SESSION_VERSION = 3`. Optional `title`, `titleSource`, `parentSession`, `additionalDirectories`, `previousSessionFiles`. [OMP packages/coding-agent/src/session/session-entries.ts#L17, #L42-L76; header write at session-manager.ts#L2079-L2085]
- Title slot: a `{"type":"title","v":1,"title","source"?,"updatedAt","pad"}` line padded to `SESSION_TITLE_SLOT_BYTES = 256` bytes. Parsers must skip it. [session-entries.ts#L19; packages/coding-agent/src/session/session-title-slot.ts]. Exact file position of this line: UNVERIFIED.
- Every entry has `{type, id, parentId, timestamp, runtime?, activeLeafId?}`. [session-entries.ts#L93-L111]
- Entry types (`SessionEntry` union) [session-entries.ts#L355-L398]: `message`, `model_usage`, `thinking_level_change`, `model_change`, `service_tier_change`, `compaction`, `branch_summary`, `custom`, `custom_message`, `label`, `title`, `ttsr_injection`, `session_init`, `mode_change`, `credential_pin`, `reset_boundary`.
- Conversation turns are `{"type":"message", "id", "parentId", "timestamp", "message": AgentMessage}` [session-entries.ts#L113-L117].
- `AgentMessage` union includes `user`, `developer`, `assistant`, `toolResult`, `bashExecution`, `pythonExecution`, `custom`, `hook`, `branchSummary`, `compactionSummary`, `fileMention` [OMP packages/coding-agent/src/modes/rpc/wire/rpc-wire.generated.ts#L238; agent/src/types.ts#L1029].

### Message and content shapes (packages/ai/src/types.ts)
- Text block: `{type:"text", text, textSignature?}` [OMP packages/ai/src/types.ts#L906-L910]
- Thinking block: `{type:"thinking", thinking, thinkingSignature?}` [#L912]
- Image block: `{type:"image", data (base64), mimeType}` [#L988]
- Tool call block: `{type:"toolCall", id, name, arguments: object, intent?}`. `arguments` is an object, not a string [#L1056].
- User message: `{role:"user", content: string | (TextContent|ImageContent)[], synthetic?, steering?}` [#L1229]
- Assistant message: `{role:"assistant", content: (Text|Thinking|RedactedThinking|ImageContent|ToolCall)[], api, provider, model, responseId?, ...}` [#L1311]
- Tool result: `{role:"toolResult", toolCallId, toolName, content: (TextContent|ImageContent)[], details?, isError, prunedAt?}` [#L1401]
- Tool output text lives in `toolResult.content`, linked to the call by `toolCallId`.

### SQLite in omp
- Session transcripts are JSONL. `FileSessionStorage` is constructed in main.ts [OMP packages/coding-agent/src/main.ts#L229].
- A `Bun.SQL`-backed session store (postgres/mysql/sqlite adapters) exists in packages/coding-agent/src/session/sql-session-storage.ts. Whether any user config selects it: UNVERIFIED.
- Other SQLite files in the agent dir: `agent.db` (credential store, docs/providers.md#L67), `stats.db` (gc-cli.ts#L1741), model cache `models.db` (model-registry.ts#L643). Blob store: `<agentDir>/blobs` (dirs.ts `getBlobsDir`).
