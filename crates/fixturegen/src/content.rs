//! Synthetic conversation content.
//!
//! Every planted value and decoy is recorded in [`Gen`] at the moment it is placed into a
//! session, so the manifest always matches what the writers put on disk.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::Planted;
use crate::rng::{ALNUM, HEX, Rng};
use crate::values;

const FIRST_NAMES: &[&str] = &[
    "Priya", "Oliver", "Amelia", "Harry", "Sofia", "George", "Aisha", "Noah", "Chloe", "Ravi", "Isla", "Mateo",
    "Freya", "Kwame", "Ellie", "Jack", "Maya", "Ethan", "Leah", "Tomasz", "Hannah", "Dev", "Olivia", "Samir", "Grace",
    "Lucas", "Zara", "Mohammed", "Ruby", "Felix", "Nadia", "Declan", "Yasmin", "Owen", "Eleanor", "Ivan", "Keira",
    "Arjun", "Sienna", "Theo", "Imani", "Callum", "Megan", "Rohan", "Bethany", "Wei",
];
const LAST_NAMES: &[&str] = &[
    "Sharma",
    "Patel",
    "Okafor",
    "Whitfield",
    "Murphy",
    "Kowalski",
    "Hughes",
    "Reid",
    "Chaudhry",
    "Brennan",
    "Ferreira",
    "Lindqvist",
    "Adeyemi",
    "Donnelly",
    "Fraser",
    "Gallagher",
    "Hassan",
    "Ingram",
    "Jarvis",
    "Kellett",
    "Lowe",
    "Marsh",
    "Nkosi",
    "Oduya",
    "Pryce",
    "Quayle",
    "Rahman",
    "Stanton",
    "Tierney",
    "Underwood",
    "Vance",
    "Wren",
    "Yates",
    "Ziegler",
    "Abbott",
    "Bello",
    "Cairns",
    "Dunmore",
    "Eccles",
    "Farrow",
    "Greaves",
    "Holt",
    "Tan",
];
const STREETS: &[&str] = &[
    "Elm Grove",
    "Mill Lane",
    "Station Road",
    "Church Street",
    "Harbour View",
    "Fernhill Road",
    "Oak Avenue",
    "Bridge Street",
    "Kingsway",
    "Ashdown Close",
    "Willow Way",
    "Park Terrace",
    "Queens Road",
    "Victoria Gardens",
    "Hawthorn Drive",
    "Manor Court",
    "Greenfield Crescent",
    "Canal Walk",
    "Abbey Road",
    "Riverside Mews",
];
const TOWNS: &[&str] = &[
    "Leeds",
    "Bristol",
    "Sheffield",
    "Norwich",
    "Cardiff",
    "Exeter",
    "Derby",
    "York",
    "Bath",
    "Preston",
    "Luton",
    "Reading",
    "Oxford",
    "Swansea",
    "Dundee",
    "Ipswich",
    "Wigan",
    "Bolton",
    "Croydon",
    "Stockport",
    "Harrogate",
    "Chester",
    "Durham",
    "Lincoln",
    "Wakefield",
];
const ORGS: &[&str] = &[
    "Brindle Freight Ltd",
    "Halvorsen Dental Group",
    "Crestline Analytics Ltd",
    "Marrowby Foods plc",
    "Tallow Finch Architects",
    "Quillon Software Ltd",
    "Ashgrove Housing Trust",
    "Pennywhistle Logistics Ltd",
    "Vantage Harbour Partners LLP",
    "Greystone Veterinary Ltd",
    "Orchard Lane Clinics Ltd",
    "Kestrel Print Works Ltd",
    "Sablewood Legal LLP",
    "Ironbridge Robotics Ltd",
    "Lanternfield Charity",
    "Rookery Bakehouse Ltd",
    "Thistlemere Estates Ltd",
    "Corvane Insurance Ltd",
    "Stellmoor Engineering Ltd",
    "Juniper Row Nurseries Ltd",
];
const FREE_DOMAINS: &[&str] = &["gmail.com", "outlook.com", "hotmail.co.uk", "icloud.com"];
const KNOWN_WORDS: &[&str] = &[
    "maple", "orbit", "quiet", "ember", "cobalt", "lantern", "harbor", "velvet", "pixel", "saffron", "tundra",
    "glimmer", "juniper", "copper", "drift", "falcon", "granite", "hollow", "indigo", "jasper", "kettle", "lumen",
    "meadow", "nickel", "opal", "parsley", "quartz", "riddle", "sable", "thistle", "umber", "vortex", "willow",
    "zephyr",
];
const FILLER_WORDS: &[&str] = &[
    "queue",
    "worker",
    "retry",
    "backoff",
    "cache",
    "shard",
    "latency",
    "batch",
    "timeout",
    "schema",
    "index",
    "migration",
    "pipeline",
    "replica",
    "buffer",
    "handler",
    "compaction",
    "snapshot",
    "checkpoint",
    "metric",
    "throughput",
    "scheduler",
    "lease",
    "heartbeat",
];
const CODE_SNIPPETS: &[&str] = &[
    "const token = await getToken();",
    "fn main() { let x = 42; }",
    "def password_reset(user):",
];
const IP_DECOYS: &[&str] = &["127.0.0.1", "192.168.1.20"];
const LOCAL_HOST: &str = "localhost:3000";
const PORTS: &[&str] = &["3000", "5432", "8080"];
const PROJECT_NAMES: &[&str] = &["billing-api", "web-dashboard", "ops-tools"];
const TABLE_HEADER: [&str; 7] = ["id", "name", "email", "phone", "city", "created_at", "active"];
const TABLE_COMMANDS: [&str; 4] = [
    "cat customers.csv",
    "cat customers.md",
    "psql -c 'select * from customers'",
    "node export.js",
];

/// Size of one filler tool output, in bytes.
const FILLER_CHUNK: usize = 64 * 1024;
/// Number of filler turns appended to each extra (size-target) session.
pub const FILLER_TURNS: usize = 4;
/// 2026-01-01T00:00:00Z in milliseconds.
const BASE_MS: i64 = 1_767_225_600_000;

/// Recorder for planted values and decoys. Values are deduplicated on insertion.
pub struct Gen {
    pub rng: Rng,
    planted: Vec<Planted>,
    seen_planted: HashSet<String>,
    decoys: Vec<String>,
    seen_decoys: HashSet<String>,
}

#[derive(Clone)]
struct Person {
    first: &'static str,
    last: &'static str,
}

impl Person {
    fn full(&self) -> String {
        format!("{} {}", self.first, self.last)
    }
}

struct Org {
    name: String,
    slug: String,
}

impl Gen {
    pub fn new(seed: u64) -> Self {
        Self {
            rng: Rng::new(seed),
            planted: Vec::new(),
            seen_planted: HashSet::new(),
            decoys: Vec::new(),
            seen_decoys: HashSet::new(),
        }
    }

    pub fn plant(&mut self, kind: &str, value: String) -> String {
        if self.seen_planted.insert(value.clone()) {
            self.planted.push(Planted {
                kind: kind.to_string(),
                value: value.clone(),
            });
        }
        value
    }

    pub fn make_planted(&mut self, kind: &str, make: fn(&mut Rng) -> String) -> String {
        let value = make(&mut self.rng);
        self.plant(kind, value)
    }

    pub fn decoy(&mut self, value: String) -> String {
        if self.seen_decoys.insert(value.clone()) {
            self.decoys.push(value.clone());
        }
        value
    }

    pub fn make_decoy(&mut self, make: fn(&mut Rng) -> String) -> String {
        let value = make(&mut self.rng);
        self.decoy(value)
    }

    pub fn finish(self) -> (Vec<Planted>, Vec<String>) {
        (self.planted, self.decoys)
    }

    fn person(&mut self) -> Person {
        Person {
            first: self.rng.pick(FIRST_NAMES),
            last: self.rng.pick(LAST_NAMES),
        }
    }

    fn org(&mut self) -> Org {
        let name = (*self.rng.pick(ORGS)).to_string();
        let slug = name.split_whitespace().next().unwrap_or("org").to_lowercase();
        Org { name, slug }
    }

    fn email_for(&mut self, person: &Person, org_slug: &str) -> String {
        let domain = if self.rng.chance(60) {
            (*self.rng.pick(FREE_DOMAINS)).to_string()
        } else {
            format!("{org_slug}.co.uk")
        };
        let local = format!("{}.{}", person.first.to_lowercase(), person.last.to_lowercase());
        self.plant("EMAIL", format!("{local}@{domain}"))
    }

    fn address(&mut self) -> String {
        let number = self.rng.range(1, 199);
        let street = *self.rng.pick(STREETS);
        let town = *self.rng.pick(TOWNS);
        self.plant("ADDRESS", format!("{number} {street}, {town}"))
    }
}

/// A project directory under `root/projects/` with known low-entropy credentials in its `.env`.
pub struct Project {
    pub name: &'static str,
    pub dir: PathBuf,
    pub db_password: String,
    pub api_token: String,
}

impl Project {
    pub fn dir_string(&self) -> String {
        self.dir.to_string_lossy().into_owned()
    }

    pub fn env_text(&self) -> String {
        format!(
            "DB_PASSWORD={}\nAPI_TOKEN={}\nAPP_NAME=demo\n",
            self.db_password, self.api_token
        )
    }
}

fn known_value(g: &mut Gen) -> String {
    let a = *g.rng.pick(KNOWN_WORDS);
    let b = *g.rng.pick(KNOWN_WORDS);
    let n = g.rng.range(1000, 9999);
    let c = *g.rng.pick(KNOWN_WORDS);
    g.plant("KNOWN", format!("{a}-{b}-{n}-{c}"))
}

pub fn make_projects(g: &mut Gen, root: &Path) -> Vec<Project> {
    PROJECT_NAMES
        .iter()
        .map(|&name| {
            let db_password = known_value(g);
            let api_token = known_value(g);
            Project {
                name,
                dir: root.join("projects").join(name),
                db_password,
                api_token,
            }
        })
        .collect()
}

/// One request/response exchange in a session.
pub struct Turn {
    pub request_id: String,
    pub user: String,
    pub assistant: String,
    pub tools: Vec<ToolCall>,
}

pub struct ToolCall {
    pub call_id: String,
    pub command: String,
    pub output: String,
}

/// A complete synthetic session, rendered by every tool writer.
pub struct Session {
    pub id: String,
    pub ws_id: String,
    pub legacy_id: String,
    pub project: usize,
    pub title: String,
    pub created_ms: i64,
    pub turns: Vec<Turn>,
    pub plan_md: String,
    pub panel_json: String,
}

fn tool_call(g: &mut Gen, command: &str, output: String) -> ToolCall {
    let call_id = format!("call_{}", g.rng.chars(ALNUM, 24));
    ToolCall {
        call_id,
        command: command.to_string(),
        output,
    }
}

/// Builds a session whose content touches every planted kind and carries decoys.
///
/// `vscode` says whether the session is rendered into VS Code, the only tool that stores the
/// workbench panel state. Only values that some writer actually outputs may be recorded.
pub fn build_session(g: &mut Gen, projects: &[Project], index: usize, filler_turns: usize, vscode: bool) -> Session {
    let project = index % projects.len();
    let proj = &projects[project];
    let id = values::uuid(&mut g.rng);
    let ws_id = g.rng.chars(HEX, 32);
    let legacy_id = values::uuid(&mut g.rng);
    let created_ms = BASE_MS + index as i64 * 3_600_000 + g.rng.range(0, 3_000_000) as i64;

    // Turn 1: contact details, repository decoys, project .env.
    let p1 = g.person();
    let org1 = g.org();
    let name1 = g.plant("PERSON", p1.full());
    let org1_name = g.plant("ORG", org1.name.clone());
    let addr1 = g.address();
    let email1 = g.email_for(&p1, &org1.slug);
    let phone1 = g.make_planted("PHONE", values::uk_mobile);
    let phone2 = g.make_planted("PHONE", values::uk_mobile_intl);
    let phone3 = g.make_planted("PHONE", values::us_number);
    let sha1 = g.make_decoy(values::git_sha);
    let digest = g.make_decoy(values::sha256);
    let ver1 = g.make_decoy(values::semver);
    let ts1 = g.make_decoy(values::iso_timestamp);
    let uuid1 = g.make_decoy(values::uuid);
    let local = g.decoy(LOCAL_HOST.to_string());
    let ip1 = g.decoy(IP_DECOYS[0].to_string());
    let turn1 = Turn {
        request_id: values::uuid(&mut g.rng),
        user: format!(
            "Can you check the invoice for {name1} at {org1_name} ({addr1})? Reply to {email1} or call {phone1}. Office line is {phone3}, mobile on file is {phone2}."
        ),
        assistant: format!(
            "I will read the project first. Commit {sha1} is HEAD, the image digest is {digest}, and the release is {ver1}. The dev server listens on {local} and the health probe uses {ip1}. Build {ts1} ran as {uuid1}."
        ),
        tools: vec![tool_call(g, "cat .env", proj.env_text())],
    };

    // Turn 2: identifiers, known credentials in prose, secrets in grep output.
    let nino = g.make_planted("NINO", values::nino);
    let nhs = g.make_planted("NHS", values::nhs_number);
    let card = g.make_planted("CARD", values::card_number);
    let iban = g.make_planted("IBAN", values::iban_gb);
    let postcode = g.make_planted("POSTCODE", values::postcode);
    let code1 = g.decoy(CODE_SNIPPETS[index % CODE_SNIPPETS.len()].to_string());
    let code2 = g.decoy(CODE_SNIPPETS[(index + 1) % CODE_SNIPPETS.len()].to_string());
    let ticket = g.make_decoy(values::numeric_id);
    let ticket_uuid = g.make_decoy(values::uuid);
    let preview = g.make_decoy(values::png_base64);
    let secrets = secret_lines(g);
    let turn2 = Turn {
        request_id: values::uuid(&mut g.rng),
        user: format!(
            "For the form for {org1_name}: NINO {nino}, NHS number {nhs}, card {card}, IBAN {iban}, postcode {postcode}. Our API token is {} and the db password is {}.",
            proj.api_token, proj.db_password
        ),
        assistant: format!(
            "Noted. Use `{code1}` in the handler and `{code2}` in the tests. Ticket {ticket} is tracked as {ticket_uuid}. Screenshot preview: {preview}"
        ),
        tools: vec![tool_call(g, "grep -rn \"key\\|token\\|secret\" config src", secrets)],
    };

    // Turn 3: database URL, JWT, nested JSON, a table and a PEM key.
    let pg_password = g.make_planted("SECRET", values::pg_password);
    let jwt = g.make_planted("SECRET", values::jwt);
    let pg_port = g.decoy(PORTS[1].to_string());
    let p2 = g.person();
    let name2 = g.plant("PERSON", p2.full());
    let email2 = g.email_for(&p2, &org1.slug);
    let deploy_ts = g.make_decoy(values::iso_timestamp);
    let job = g.make_decoy(values::numeric_id);
    let port_a = g.decoy(PORTS[2].to_string());
    let port_b = g.decoy(PORTS[0].to_string());
    let nested = nested_config(g);
    let table3 = table_tool(g, index % 4);
    let pem = pem_block(g);
    let turn3 = Turn {
        request_id: values::uuid(&mut g.rng),
        user: format!(
            "Database URL is postgres://appuser:{pg_password}@db.internal:{pg_port}/app and the session token is {jwt}. Send the summary to {name2} at {email2}."
        ),
        assistant: format!("Stored. Deploy finished at {deploy_ts}, job {job}, ports {port_a} and {port_b}."),
        tools: vec![
            tool_call(g, "cat config/app.json", nested),
            table3,
            tool_call(g, "cat keys/server.pem", pem),
        ],
    };

    // Turn 4: follow-up draft, a second table, versions and a snippet.
    let p3 = g.person();
    let org3 = g.org();
    let name3 = g.plant("PERSON", p3.full());
    let org3_name = g.plant("ORG", org3.name.clone());
    let addr3 = g.address();
    let phone4 = g.make_planted("PHONE", values::uk_mobile);
    let email3 = g.email_for(&p3, &org3.slug);
    let ver2 = g.make_decoy(values::semver_beta);
    let build = g.make_decoy(values::numeric_id);
    let code3 = g.decoy(CODE_SNIPPETS[2].to_string());
    let ip2 = g.decoy(IP_DECOYS[1].to_string());
    let turn4 = Turn {
        request_id: values::uuid(&mut g.rng),
        user: format!(
            "Write a short follow-up for {name3} at {org3_name}. Reply with {email3}, mention {addr3} and call {phone4}."
        ),
        assistant: format!(
            "Draft below.\n\nHi team, thanks for the call. Version {ver2} is in staging on {ip2}, build {build}. Snippet: `{code3}`."
        ),
        tools: vec![table_tool(g, (index + 2) % 4)],
    };

    let mut turns = vec![turn1, turn2, turn3, turn4];
    for _ in 0..filler_turns {
        let text = filler(&mut g.rng, FILLER_CHUNK);
        let call = tool_call(g, "tail -n 2000 build.log", text);
        turns.push(Turn {
            request_id: values::uuid(&mut g.rng),
            user: "Summarize the last build log.".to_string(),
            assistant: "Here is the tail of the log.".to_string(),
            tools: vec![call],
        });
    }

    let title = format!("Invoice follow-up for {email1}");
    let plan_md = format!("# Plan\n\n- Reply to {name3} on {phone4}\n- Check {ip2} after the release\n");
    // The workbench panel state only exists in VS Code's state database, so its decoy is only
    // recorded for VS Code sessions.
    let panel_json = if vscode {
        let panel_sha = g.make_decoy(values::git_sha);
        json!({
            "lastCommit": panel_sha,
            "version": ver1,
            "ports": [PORTS[2], PORTS[0]],
        })
        .to_string()
    } else {
        String::new()
    };

    Session {
        id,
        ws_id,
        legacy_id,
        project,
        title,
        created_ms,
        turns,
        plan_md,
        panel_json,
    }
}

/// Plausible `grep` output containing synthetic credentials of each provider shape.
fn secret_lines(g: &mut Gen) -> String {
    let aws = g.make_planted("SECRET", values::aws_access_key);
    let github = g.make_planted("SECRET", values::github_pat);
    let fine = g.make_planted("SECRET", values::github_fine_pat);
    let slack = g.make_planted("SECRET", values::slack_bot_token);
    let openai = g.make_planted("SECRET", values::openai_key);
    let anthropic = g.make_planted("SECRET", values::anthropic_key);
    let stripe = g.make_planted("SECRET", values::stripe_live_key);
    let key = g.make_planted("SECRET", values::api_key);
    [
        format!("config/aws.env:1:AWS_ACCESS_KEY_ID={aws}"),
        format!("config/ci.env:2:GITHUB_TOKEN={github}"),
        format!("config/ci.env:3:GH_FINE_TOKEN={fine}"),
        format!("config/slack.env:1:SLACK_BOT_TOKEN={slack}"),
        format!("config/llm.env:1:OPENAI_API_KEY={openai}"),
        format!("config/llm.env:2:ANTHROPIC_API_KEY={anthropic}"),
        format!("config/billing.env:4:STRIPE_SECRET={stripe}"),
        format!("config/app.json:7:  \"api_key\": \"{key}\""),
    ]
    .join("\n")
}

/// Outer JSON whose `body` field is itself serialised JSON, so the inner secrets are escaped.
fn nested_config(g: &mut Gen) -> String {
    let key = g.make_planted("SECRET", values::api_key);
    let password = g.make_planted("SECRET", values::password);
    let inner = json!({"config": {"api_key": key, "password": password}}).to_string();
    json!({"status": "ok", "body": inner}).to_string()
}

fn pem_block(g: &mut Gen) -> String {
    let (block, body) = values::pem_key(&mut g.rng);
    g.plant("SECRET", body);
    block
}

struct Row {
    id: String,
    name: String,
    email: String,
    phone: String,
    city: String,
    created: String,
    active: bool,
}

fn table_rows(g: &mut Gen) -> Vec<Row> {
    let count = g.rng.range(5, 15) as usize;
    let mut rows = Vec::with_capacity(count);
    for _ in 0..count {
        let person = g.person();
        let org = g.org();
        let name = g.plant("TABULAR", person.full());
        let town = *g.rng.pick(TOWNS);
        let city = g.plant("TABULAR", town.to_string());
        let email = g.email_for(&person, &org.slug);
        let phone = g.make_planted("PHONE", values::uk_mobile);
        let id = g.make_decoy(values::numeric_id);
        let created = g.make_decoy(values::iso_date);
        let active = g.rng.chance(70);
        g.decoy(active.to_string());
        rows.push(Row {
            id,
            name,
            email,
            phone,
            city,
            created,
            active,
        });
    }
    rows
}

fn row_cells(r: &Row) -> [String; 7] {
    [
        r.id.clone(),
        r.name.clone(),
        r.email.clone(),
        r.phone.clone(),
        r.city.clone(),
        r.created.clone(),
        r.active.to_string(),
    ]
}

fn csv_table(rows: &[Row]) -> String {
    let mut lines = vec![TABLE_HEADER.join(",")];
    lines.extend(rows.iter().map(|r| row_cells(r).join(",")));
    lines.join("\n")
}

fn markdown_table(rows: &[Row]) -> String {
    let mut lines = vec![
        format!("| {} |", TABLE_HEADER.join(" | ")),
        format!("|{}|", ["---"; 7].join("|")),
    ];
    lines.extend(rows.iter().map(|r| format!("| {} |", row_cells(r).join(" | "))));
    lines.join("\n")
}

fn psql_table(rows: &[Row]) -> String {
    let mut all: Vec<[String; 7]> = vec![TABLE_HEADER.map(String::from)];
    all.extend(rows.iter().map(row_cells));
    let widths: Vec<usize> = (0..7)
        .map(|c| all.iter().map(|r| r[c].chars().count()).max().unwrap_or(0))
        .collect();
    let line = |row: &[String; 7]| {
        row.iter()
            .enumerate()
            .map(|(c, v)| format!("{:<w$}", v, w = widths[c]))
            .collect::<Vec<_>>()
            .join(" | ")
    };
    let rule = widths.iter().map(|w| "-".repeat(w + 2)).collect::<Vec<_>>().join("+");
    let mut lines = vec![format!(" {}", line(&all[0])), rule];
    lines.extend(all[1..].iter().map(|r| format!(" {}", line(r))));
    lines.join("\n")
}

fn json_table(rows: &[Row]) -> String {
    let items: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.id.parse::<u64>().unwrap_or_default(),
                "name": r.name,
                "email": r.email,
                "phone": r.phone,
                "city": r.city,
                "created_at": r.created,
                "active": r.active,
            })
        })
        .collect();
    Value::Array(items).to_string()
}

/// Tool call whose output is a table in one of four shapes, selected by `kind % 4`.
fn table_tool(g: &mut Gen, kind: usize) -> ToolCall {
    let rows = table_rows(g);
    let output = match kind % 4 {
        0 => csv_table(&rows),
        1 => markdown_table(&rows),
        2 => psql_table(&rows),
        _ => json_table(&rows),
    };
    tool_call(g, TABLE_COMMANDS[kind % 4], output)
}

/// Lorem-like technical text with code and log lines, containing no planted values.
pub fn filler(rng: &mut Rng, bytes: usize) -> String {
    let mut out = String::with_capacity(bytes + 256);
    while out.len() < bytes {
        match rng.below(3) {
            0 => {
                let words = rng.range(8, 16);
                for i in 0..words {
                    if i > 0 {
                        out.push(' ');
                    }
                    out.push_str(rng.pick(FILLER_WORDS));
                }
                out.push_str(".\n");
            }
            1 => {
                let n = rng.below(1000);
                let w = rng.pick(FILLER_WORDS);
                let _ = writeln!(out, "fn {w}_{n}(x: u32) -> u32 {{ x * {n} }}");
            }
            _ => {
                let batch = rng.range(100, 9999);
                let ms = rng.range(1, 500);
                let worker = rng.below(8);
                let _ = writeln!(out, "[worker-{worker}] processed batch {batch} in {ms}ms");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_plants_every_kind() {
        let mut g = Gen::new(1);
        let projects = make_projects(&mut g, Path::new("/tmp/fixture-root"));
        let _ = build_session(&mut g, &projects, 0, 0, true);
        let (planted, decoys) = g.finish();
        for kind in [
            "SECRET", "EMAIL", "PHONE", "POSTCODE", "NINO", "NHS", "CARD", "IBAN", "KNOWN", "TABULAR", "PERSON",
            "ADDRESS", "ORG",
        ] {
            assert!(planted.iter().any(|p| p.kind == kind), "missing {kind}");
        }
        assert!(!decoys.is_empty());
    }
}
