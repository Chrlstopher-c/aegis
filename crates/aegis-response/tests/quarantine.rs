//! Validation Lot 2 : quarantaine puis restauration d'un fichier (round-trip).

use std::fs;
use std::os::unix::fs::PermissionsExt;

use aegis_response::Quarantine;

#[test]
fn quarantine_puis_restore_preserve_contenu_et_mode() {
    let base = std::env::temp_dir().join(format!("aegis_qtest_{}", std::process::id()));
    fs::create_dir_all(&base).unwrap();
    let store = base.join("store");
    let victim = base.join("malware.sh");

    fs::write(&victim, b"#!/bin/sh\necho pwned\n").unwrap();
    fs::set_permissions(&victim, fs::Permissions::from_mode(0o755)).unwrap();

    let q = Quarantine::open(&store).unwrap();
    let entry = q.quarantine(&victim, "test eicar").unwrap();

    // Le fichier d'origine a disparu, une entrée est listée.
    assert!(!victim.exists(), "l'original doit être déplacé");
    assert_eq!(q.list().unwrap().len(), 1);

    // Le blob isolé n'est pas exécutable (0o600).
    let blob_mode = fs::metadata(store.join(format!("{}.bin", entry.id)))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(blob_mode, 0o600);

    // Restauration : contenu et mode d'origine retrouvés.
    q.restore(&entry.id).unwrap();
    assert!(victim.exists(), "l'original doit être restauré");
    assert_eq!(fs::read(&victim).unwrap(), b"#!/bin/sh\necho pwned\n");
    assert_eq!(fs::metadata(&victim).unwrap().permissions().mode() & 0o777, 0o755);
    assert!(q.list().unwrap().is_empty(), "plus d'entrée après restauration");

    fs::remove_dir_all(&base).ok();
}
