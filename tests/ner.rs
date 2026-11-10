//! NER recall on the fixture tree. Opt-in: set NEUROALYZER_TEST_MODEL_DIR to a
//! directory that already holds the model (`NEUROALYZER_MODEL_DIR=... neuroalyzer model fetch`).

mod common;
use common::*;
use std::collections::BTreeMap;

#[test]
fn ner_recall() {
    let Some(models) = std::env::var_os("NEUROALYZER_TEST_MODEL_DIR") else {
        eprintln!("skipping: NEUROALYZER_TEST_MODEL_DIR not set");
        return;
    };
    if !cfg!(feature = "ner") {
        return;
    }
    let fx = fixture();
    let o = fx
        .cmd()
        .args([
            "clean",
            "--root",
            &fx.root_s(),
            "--ner",
            "--yes",
            "--password-file",
            &fx.pw_s(),
            "--json",
        ])
        .env("NEUROALYZER_MODEL_DIR", &models)
        .env("NEUROALYZER_NO_DOWNLOAD", "1")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let rep: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(rep["engines"]["ner"], true, "{}", rep["engines"]);
    let projects = fx.root.join("projects");
    let files: Vec<Vec<u8>> = walkdir(&fx.root)
        .into_iter()
        .filter(|p| !p.starts_with(&projects))
        .map(|p| std::fs::read(p).unwrap())
        .collect();
    let mut table: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for p in &fx.manifest.planted {
        let e = table.entry(p.kind.clone()).or_default();
        e.0 += 1;
        if !files.iter().any(|b| forms(&p.value).iter().any(|f| contains(b, f))) {
            e.1 += 1;
        }
    }
    let mut decoys_lost = 0;
    for d in &fx.manifest.decoys {
        if !files.iter().any(|b| forms(d).iter().any(|f| contains(b, f))) {
            decoys_lost += 1;
        }
    }
    eprintln!("\n{:<10} {:>8} {:>8} {:>8}", "kind", "planted", "removed", "recall");
    for (k, (n, ok)) in &table {
        eprintln!("{k:<10} {n:>8} {ok:>8} {:>8.3}", *ok as f64 / *n as f64);
    }
    eprintln!("decoys lost: {decoys_lost}/{}", fx.manifest.decoys.len());
    eprintln!("ner: {}", rep["engines"]);
    let recall = |k: &str| table.get(k).map_or(1.0, |(n, ok)| *ok as f64 / *n as f64);
    assert!(recall("PERSON") >= 0.85, "PERSON recall {}", recall("PERSON"));
    assert!(recall("ORG") >= 0.6, "ORG recall {}", recall("ORG"));
    assert!(recall("ADDRESS") >= 0.6, "ADDRESS recall {}", recall("ADDRESS"));
    assert!(recall("TABULAR") >= 0.95);
    assert_eq!(decoys_lost, 0, "NER must not redact decoys");
}
