//! Discovery: a registry mapping each tool to per-OS base directories and
//! glob patterns, each with a format handler. See docs/FORMATS.md.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Format {
    Json,
    Jsonl,
    Sqlite,
    Text,
    /// Zstandard-compressed JSON lines (Codex archived rollouts). Decompressed
    /// in memory, redacted as JSONL, then recompressed.
    JsonlZst,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Schema {
    Generic,
    VscodeChat,
    CopilotEvents,
    OmpSession,
    OpencodeJson,
    VscodeState,
    OpencodeDb,
    ClaudeSession,
    CodexRollout,
    GeminiChat,
    DroidSession,
    HermesDb,
}

impl Schema {
    pub fn name(self) -> &'static str {
        match self {
            Schema::Generic => "generic",
            Schema::VscodeChat => "VS Code chat session",
            Schema::CopilotEvents => "Copilot CLI events",
            Schema::OmpSession => "pi-style session",
            Schema::OpencodeJson => "OpenCode storage JSON",
            Schema::VscodeState => "VS Code state.vscdb",
            Schema::OpencodeDb => "OpenCode database",
            Schema::ClaudeSession => "Claude Code transcript",
            Schema::CodexRollout => "Codex rollout",
            Schema::GeminiChat => "Gemini CLI chat",
            Schema::DroidSession => "Factory Droid session",
            Schema::HermesDb => "Hermes state.db",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Job {
    pub tool: &'static str,
    pub path: PathBuf,
    pub format: Format,
    pub schema: Schema,
    pub size: u64,
}

pub const TOOLS: &[(&str, &str)] = &[
    ("copilot", "GitHub Copilot (VS Code chat and Copilot CLI)"),
    ("opencode", "OpenCode"),
    ("omp", "omp (oh-my-pi)"),
    ("claude", "Claude Code"),
    ("codex", "OpenAI Codex CLI"),
    ("gemini", "Gemini CLI"),
    ("hermes", "Hermes Agent"),
    ("openclaw", "OpenClaw"),
    ("droid", "Factory Droid"),
    ("pi", "pi coding agent"),
];

#[derive(Clone, Copy)]
enum Base {
    VscodeUser,
    CopilotHome,
    OpencodeData,
    OmpAgent,
    ClaudeHome,
    CodexHome,
    GeminiHome,
    HermesHome,
    OpenclawState,
    FactoryHome,
    PiAgent,
}

struct Loc {
    tool: &'static str,
    base: Base,
    pattern: &'static str,
    format: Format,
    schema: Schema,
}

const fn loc(tool: &'static str, base: Base, pattern: &'static str, format: Format, schema: Schema) -> Loc {
    Loc {
        tool,
        base,
        pattern,
        format,
        schema,
    }
}

use Base::*;
use Format::*;

const REGISTRY: &[Loc] = &[
    // VS Code core writes Copilot Chat history (stable and Insiders).
    loc(
        "copilot",
        VscodeUser,
        "workspaceStorage/*/chatSessions/*.jsonl",
        Jsonl,
        Schema::VscodeChat,
    ),
    loc(
        "copilot",
        VscodeUser,
        "workspaceStorage/*/chatSessions/*.json",
        Json,
        Schema::VscodeChat,
    ),
    loc(
        "copilot",
        VscodeUser,
        "globalStorage/emptyWindowChatSessions/*.jsonl",
        Jsonl,
        Schema::VscodeChat,
    ),
    loc(
        "copilot",
        VscodeUser,
        "globalStorage/emptyWindowChatSessions/*.json",
        Json,
        Schema::VscodeChat,
    ),
    loc(
        "copilot",
        VscodeUser,
        "globalStorage/transferredChatSessions/*.jsonl",
        Jsonl,
        Schema::VscodeChat,
    ),
    loc(
        "copilot",
        VscodeUser,
        "globalStorage/transferredChatSessions/*.json",
        Json,
        Schema::VscodeChat,
    ),
    loc(
        "copilot",
        VscodeUser,
        "workspaceStorage/no-workspace/chatSessions/*.json",
        Json,
        Schema::VscodeChat,
    ),
    loc(
        "copilot",
        VscodeUser,
        "workspaceStorage/*/chatEditingSessions/*/state.json",
        Json,
        Schema::Generic,
    ),
    loc(
        "copilot",
        VscodeUser,
        "workspaceStorage/*/chatEditingSessions/*/contents/*",
        Text,
        Schema::Generic,
    ),
    loc(
        "copilot",
        VscodeUser,
        "workspaceStorage/*/state.vscdb",
        Sqlite,
        Schema::VscodeState,
    ),
    loc(
        "copilot",
        VscodeUser,
        "workspaceStorage/*/state.vscdb.backup",
        Sqlite,
        Schema::VscodeState,
    ),
    loc(
        "copilot",
        VscodeUser,
        "globalStorage/state.vscdb",
        Sqlite,
        Schema::VscodeState,
    ),
    loc(
        "copilot",
        VscodeUser,
        "globalStorage/state.vscdb.backup",
        Sqlite,
        Schema::VscodeState,
    ),
    // Copilot CLI.
    loc(
        "copilot",
        CopilotHome,
        "session-state/*/events.jsonl",
        Jsonl,
        Schema::CopilotEvents,
    ),
    loc(
        "copilot",
        CopilotHome,
        "session-state/*.jsonl",
        Jsonl,
        Schema::CopilotEvents,
    ),
    loc("copilot", CopilotHome, "session-state/*/*.md", Text, Schema::Generic),
    loc(
        "copilot",
        CopilotHome,
        "session-state/*/workspace.yaml",
        Text,
        Schema::Generic,
    ),
    loc(
        "copilot",
        CopilotHome,
        "session-state/*/checkpoints/**/*.md",
        Text,
        Schema::Generic,
    ),
    loc(
        "copilot",
        CopilotHome,
        "history-session-state/**/*.json",
        Json,
        Schema::Generic,
    ),
    loc(
        "copilot",
        CopilotHome,
        "history-session-state/**/*.jsonl",
        Jsonl,
        Schema::Generic,
    ),
    loc(
        "copilot",
        CopilotHome,
        "command-history-state.json",
        Json,
        Schema::Generic,
    ),
    // OpenCode: SQLite in current versions, JSON tree in older ones.
    loc("opencode", OpencodeData, "opencode*.db", Sqlite, Schema::OpencodeDb),
    loc(
        "opencode",
        OpencodeData,
        "storage/**/*.json",
        Json,
        Schema::OpencodeJson,
    ),
    // omp.
    loc("omp", OmpAgent, "sessions/**/*.jsonl", Jsonl, Schema::OmpSession),
    // Named profiles: ~/.omp/<...>/agent/sessions.
    loc(
        "omp",
        OmpAgent,
        "*/*/agent/sessions/**/*.jsonl",
        Jsonl,
        Schema::OmpSession,
    ),
    // Claude Code: one JSONL transcript per session, per project.
    loc("claude", ClaudeHome, "projects/*/*.jsonl", Jsonl, Schema::ClaudeSession),
    loc(
        "claude",
        ClaudeHome,
        "projects/*/*/subagents/*.jsonl",
        Jsonl,
        Schema::ClaudeSession,
    ),
    loc(
        "claude",
        ClaudeHome,
        "projects/*/*/tool-results/*",
        Text,
        Schema::Generic,
    ),
    loc("claude", ClaudeHome, "projects/*/memory/*.md", Text, Schema::Generic),
    loc("claude", ClaudeHome, "history.jsonl", Jsonl, Schema::Generic),
    loc("claude", ClaudeHome, "plans/*.md", Text, Schema::Generic),
    loc("claude", ClaudeHome, "todos/*.json", Json, Schema::Generic),
    loc("claude", ClaudeHome, "paste-cache/*", Text, Schema::Generic),
    // Snapshots of files Claude edited, kept for rewind.
    loc("claude", ClaudeHome, "file-history/*/*", Text, Schema::Generic),
    // Codex: rollouts by date, archived rollouts (often zstd), SQLite state.
    loc("codex", CodexHome, "sessions/**/*.jsonl", Jsonl, Schema::CodexRollout),
    loc(
        "codex",
        CodexHome,
        "sessions/**/*.jsonl.zst",
        JsonlZst,
        Schema::CodexRollout,
    ),
    loc(
        "codex",
        CodexHome,
        "archived_sessions/*.jsonl",
        Jsonl,
        Schema::CodexRollout,
    ),
    loc(
        "codex",
        CodexHome,
        "archived_sessions/*.jsonl.zst",
        JsonlZst,
        Schema::CodexRollout,
    ),
    loc("codex", CodexHome, "history.jsonl", Jsonl, Schema::Generic),
    loc("codex", CodexHome, "session_index.jsonl", Jsonl, Schema::Generic),
    loc("codex", CodexHome, "state_*.sqlite", Sqlite, Schema::Generic),
    loc("codex", CodexHome, "thread_history_*.sqlite", Sqlite, Schema::Generic),
    loc("codex", CodexHome, "memories_*.sqlite", Sqlite, Schema::Generic),
    // Gemini CLI: per-project chats and prompt logs under tmp/<project hash>.
    loc("gemini", GeminiHome, "tmp/*/chats/*.json", Json, Schema::GeminiChat),
    loc("gemini", GeminiHome, "tmp/*/logs.json", Json, Schema::Generic),
    loc("gemini", GeminiHome, "tmp/*/checkpoint*.json", Json, Schema::Generic),
    // Hermes Agent: SQLite session store plus JSON/JSONL session logs, per profile.
    loc("hermes", HermesHome, "state.db", Sqlite, Schema::HermesDb),
    loc("hermes", HermesHome, "sessions/*.json", Json, Schema::Generic),
    loc("hermes", HermesHome, "sessions/*.jsonl", Jsonl, Schema::Generic),
    loc("hermes", HermesHome, "profiles/*/state.db", Sqlite, Schema::HermesDb),
    loc(
        "hermes",
        HermesHome,
        "profiles/*/sessions/*.json",
        Json,
        Schema::Generic,
    ),
    loc(
        "hermes",
        HermesHome,
        "profiles/*/sessions/*.jsonl",
        Jsonl,
        Schema::Generic,
    ),
    // OpenClaw: per-agent transcripts and the per-agent SQLite store. The
    // credentials and gateway databases are deliberately left alone.
    loc(
        "openclaw",
        OpenclawState,
        "agents/*/sessions/*.jsonl",
        Jsonl,
        Schema::OmpSession,
    ),
    loc(
        "openclaw",
        OpenclawState,
        "agents/*/agent/openclaw-agent.sqlite",
        Sqlite,
        Schema::Generic,
    ),
    // Factory Droid.
    loc("droid", FactoryHome, "sessions/*/*.jsonl", Jsonl, Schema::DroidSession),
    // pi (badlogic/pi-mono), the agent omp was forked from.
    loc("pi", PiAgent, "sessions/**/*.jsonl", Jsonl, Schema::OmpSession),
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Os {
    Mac,
    Linux,
    Windows,
}

fn current_os() -> Os {
    if cfg!(target_os = "macos") {
        Os::Mac
    } else if cfg!(windows) {
        Os::Windows
    } else {
        Os::Linux
    }
}

fn user_data_root(home: &Path, os: Os) -> PathBuf {
    match os {
        Os::Mac => home.join("Library").join("Application Support"),
        Os::Linux => home.join(".config"),
        Os::Windows => home.join("AppData").join("Roaming"),
    }
}

const VSCODE_NAMES: &[&str] = &["Code", "Code - Insiders"];

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from)
}

/// Where to look. With `root`, every OS layout is tried under that dir and
/// environment overrides are ignored.
pub struct Env {
    pub home: PathBuf,
    pub rooted: bool,
}

impl Env {
    pub fn new(root: Option<&Path>) -> Self {
        match root {
            Some(r) => Env {
                home: r.to_path_buf(),
                rooted: true,
            },
            None => Env {
                home: dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")),
                rooted: false,
            },
        }
    }

    fn bases(&self, base: Base) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = vec![];
        let oses: Vec<Os> = if self.rooted {
            vec![Os::Mac, Os::Linux, Os::Windows]
        } else {
            vec![current_os()]
        };
        match base {
            VscodeUser => {
                let mut roots: Vec<PathBuf> = oses.iter().map(|&os| user_data_root(&self.home, os)).collect();
                if !self.rooted {
                    if let Some(p) = env_path("VSCODE_PORTABLE") {
                        v.push(p.join("user-data").join("User"));
                    }
                    for var in ["VSCODE_APPDATA", "XDG_CONFIG_HOME", "APPDATA"] {
                        if let Some(p) = env_path(var) {
                            roots.push(p);
                        }
                    }
                    if let Some(p) = dirs::config_dir() {
                        roots.push(p);
                    }
                }
                for r in roots {
                    for n in VSCODE_NAMES {
                        v.push(r.join(n).join("User"));
                    }
                }
            }
            CopilotHome => {
                v.push(self.home.join(".copilot"));
                if !self.rooted {
                    if let Some(p) = env_path("COPILOT_HOME") {
                        v.push(p);
                    }
                    if let Some(p) = env_path("XDG_STATE_HOME") {
                        v.push(p.join(".copilot"));
                    }
                }
            }
            OpencodeData => {
                v.push(self.home.join(".local").join("share").join("opencode"));
                if !self.rooted
                    && let Some(p) = env_path("XDG_DATA_HOME")
                {
                    v.push(p.join("opencode"));
                }
            }
            OmpAgent => {
                v.push(self.home.join(".omp").join("agent"));
                // Named profiles keep their own agent dirs under ~/.omp.
                v.push(self.home.join(".omp"));
                v.push(self.home.join(".local").join("share").join("omp"));
                if !self.rooted {
                    if let Some(p) = env_path("PI_CODING_AGENT_DIR") {
                        v.push(p);
                    }
                    if let Some(p) = env_path("XDG_DATA_HOME") {
                        v.push(p.join("omp"));
                    }
                }
            }
            ClaudeHome => {
                v.push(self.home.join(".claude"));
                if !self.rooted
                    && let Some(p) = env_path("CLAUDE_CONFIG_DIR")
                {
                    v.push(p);
                }
            }
            CodexHome => {
                v.push(self.home.join(".codex"));
                if !self.rooted
                    && let Some(p) = env_path("CODEX_HOME")
                {
                    v.push(p);
                }
            }
            GeminiHome => {
                v.push(self.home.join(".gemini"));
                if !self.rooted
                    && let Some(p) = env_path("GEMINI_CLI_HOME")
                {
                    v.push(p.join(".gemini"));
                }
            }
            HermesHome => {
                v.push(self.home.join(".hermes"));
                if self.rooted || current_os() == Os::Windows {
                    v.push(self.home.join("AppData").join("Local").join("hermes"));
                }
                if !self.rooted {
                    if let Some(p) = env_path("HERMES_HOME") {
                        v.push(p);
                    }
                    if current_os() == Os::Windows
                        && let Some(p) = env_path("LOCALAPPDATA")
                    {
                        v.push(p.join("hermes"));
                    }
                }
            }
            OpenclawState => {
                // Older releases were named clawdbot and moltbot.
                for n in [".openclaw", ".clawdbot", ".moltbot"] {
                    v.push(self.home.join(n));
                }
                if !self.rooted
                    && let Some(p) = env_path("OPENCLAW_STATE_DIR")
                {
                    v.push(p);
                }
            }
            FactoryHome => v.push(self.home.join(".factory")),
            PiAgent => v.push(self.home.join(".pi").join("agent")),
        }
        v
    }
}

fn glob_under(base: &Path, pattern: &str) -> Vec<PathBuf> {
    let full = format!("{}/{}", glob::Pattern::escape(&base.to_string_lossy()), pattern);
    let opts = glob::MatchOptions {
        case_sensitive: true,
        require_literal_separator: true,
        require_literal_leading_dot: false,
    };
    match glob::glob_with(&full, opts) {
        Ok(paths) => paths.filter_map(Result::ok).filter(|p| p.is_file()).collect(),
        Err(_) => vec![],
    }
}

fn sniff_format(p: &Path) -> Format {
    let ext = p
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "jsonl" | "ndjson" => Format::Jsonl,
        "json" => Format::Json,
        "zst" if p.to_string_lossy().to_ascii_lowercase().ends_with(".jsonl.zst") => Format::JsonlZst,
        _ => {
            if is_sqlite(p) {
                Format::Sqlite
            } else {
                Format::Text
            }
        }
    }
}

pub fn is_sqlite(p: &Path) -> bool {
    use std::io::Read;
    let mut b = [0u8; 16];
    std::fs::File::open(p).and_then(|mut f| f.read_exact(&mut b)).is_ok() && &b == b"SQLite format 3\0"
}

fn is_binary(p: &Path) -> bool {
    use std::io::Read;
    let mut b = vec![0u8; 8192];
    match std::fs::File::open(p).and_then(|mut f| f.read(&mut b)) {
        Ok(n) => b[..n].contains(&0),
        Err(_) => false,
    }
}

const ALSO_EXTS: &[&str] = &[
    "json", "jsonl", "ndjson", "md", "txt", "log", "yaml", "yml", "db", "sqlite", "sqlite3", "vscdb", "zst",
];

pub struct Discovered {
    pub jobs: Vec<Job>,
    /// Base directories that exist, per tool.
    pub roots: Vec<(&'static str, PathBuf)>,
    pub notes: Vec<String>,
}

pub fn discover(env: &Env, only: &[String], also: &[PathBuf]) -> Discovered {
    let wanted = |t: &str| only.is_empty() || only.iter().any(|o| o.eq_ignore_ascii_case(t)) || t == "custom";
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    let mut jobs = vec![];
    let mut roots: Vec<(&'static str, PathBuf)> = vec![];
    let mut notes = vec![];
    for l in REGISTRY {
        if !wanted(l.tool) {
            continue;
        }
        for base in env.bases(l.base) {
            if !base.is_dir() {
                continue;
            }
            if !roots.iter().any(|(t, b)| *t == l.tool && *b == base) {
                roots.push((l.tool, base.clone()));
            }
            for p in glob_under(&base, l.pattern) {
                let canon = std::fs::canonicalize(&p).unwrap_or(p.clone());
                if !seen.insert(canon) {
                    continue;
                }
                let mut format = l.format;
                if format == Format::Text && is_binary(&p) {
                    continue;
                }
                if format == Format::Sqlite && !is_sqlite(&p) {
                    notes.push(format!(
                        "{}: expected SQLite, found something else; scanned it as text",
                        p.display()
                    ));
                    format = Format::Text;
                    if is_binary(&p) {
                        continue;
                    }
                }
                let size = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
                jobs.push(Job {
                    tool: l.tool,
                    path: p,
                    format,
                    schema: l.schema,
                    size,
                });
            }
        }
    }
    if !env.rooted
        && wanted("opencode")
        && let Some(p) = env_path("OPENCODE_DB").filter(|p| p.is_file())
    {
        let canon = std::fs::canonicalize(&p).unwrap_or(p.clone());
        if seen.insert(canon) {
            let size = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            jobs.push(Job {
                tool: "opencode",
                path: p,
                format: Format::Sqlite,
                schema: Schema::OpencodeDb,
                size,
            });
        }
    }
    for a in also {
        let files: Vec<PathBuf> = if a.is_dir() {
            walkdir::WalkDir::new(a)
                .into_iter()
                .filter_map(Result::ok)
                .filter(|e| e.file_type().is_file())
                .map(|e| e.into_path())
                .filter(|p| {
                    let ext = p
                        .extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    ALSO_EXTS.contains(&ext.as_str())
                })
                .collect()
        } else if a.is_file() {
            vec![a.clone()]
        } else {
            notes.push(format!("--also {}: not found", a.display()));
            vec![]
        };
        if a.exists() {
            roots.push(("custom", a.clone()));
        }
        for p in files {
            let canon = std::fs::canonicalize(&p).unwrap_or(p.clone());
            if !seen.insert(canon) {
                continue;
            }
            let format = sniff_format(&p);
            if format == Format::Text && is_binary(&p) {
                continue;
            }
            let size = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            jobs.push(Job {
                tool: "custom",
                path: p,
                format,
                schema: Schema::Generic,
                size,
            });
        }
    }
    jobs.sort_by_key(|j| std::cmp::Reverse(j.size));
    Discovered { jobs, roots, notes }
}
