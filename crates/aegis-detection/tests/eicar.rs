//! Validation Lot 2 : EICAR détecté par le moteur YARA avec le bon verdict.

use std::fs;

use aegis_core::{Engine, Severity};
use aegis_detection::YaraEngine;

/// Chaîne EICAR construite à l'exécution pour ne pas déposer de fichier de test
/// antivirus dans le dépôt (les AV flaggeraient le source).
fn eicar_string() -> String {
    format!(
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}}${}-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        "EICAR"
    )
}

fn rules_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../rules")
}

#[test]
fn detecte_eicar_dans_un_fichier() {
    let engine = YaraEngine::from_dir(rules_dir()).expect("compilation des règles");

    let tmp = std::env::temp_dir().join(format!("aegis_eicar_{}.txt", std::process::id()));
    fs::write(&tmp, eicar_string()).unwrap();

    let verdicts = engine.scan_file(&tmp, 0).expect("scan");
    fs::remove_file(&tmp).ok();

    let eicar = verdicts
        .iter()
        .find(|v| v.title.contains("eicar_test_file"))
        .expect("EICAR doit matcher");
    assert_eq!(eicar.engine, Engine::Yara);
    assert_eq!(eicar.severity, Severity::High);
    assert!(eicar.mitre.contains(&"T1204".to_string()));
}

#[test]
fn fichier_sain_ne_matche_pas() {
    let engine = YaraEngine::from_dir(rules_dir()).expect("compilation des règles");
    let tmp = std::env::temp_dir().join(format!("aegis_clean_{}.txt", std::process::id()));
    fs::write(&tmp, b"contenu totalement benin\n").unwrap();
    let verdicts = engine.scan_file(&tmp, 0).expect("scan");
    fs::remove_file(&tmp).ok();
    assert!(verdicts.is_empty(), "aucun verdict attendu sur fichier sain");
}
