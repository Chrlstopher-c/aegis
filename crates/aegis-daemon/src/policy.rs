//! Policy engine : traduit un verdict en action effective selon le mode courant
//! (Detection vs Prevention), réglable globalement ou par catégorie. Implémente
//! la table de réponse graduée par sévérité de `docs/policy-model.md`. C'est ici
//! que se décide ce qu'on applique — la détection propose, la policy dispose.

use std::collections::HashMap;
use std::sync::RwLock;

use aegis_core::{Action, ProtectionMode, Severity, ThreatCategory, Verdict};

/// Décision effective de la policy pour un verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Journaliser uniquement.
    Log,
    /// Notifier l'utilisateur (et journaliser).
    Notify,
    /// Laisser passer (ne pas bloquer) mais notifier et inscrire en file de
    /// décisions en attente : l'utilisateur arbitrera (quarantaine/kill/autoriser).
    Defer,
    /// Mettre le fichier en quarantaine.
    Quarantine { path: String },
    /// Geler le process (investigation) sans le tuer.
    Isolate { pid: u32 },
    /// Neutraliser le process immédiatement.
    Kill { pid: u32 },
}

/// État de policy : mode global + surcharges par catégorie. Thread-safe pour être
/// modifiable à chaud par les commandes UI (Lot 5, contrôle bidirectionnel).
pub struct PolicyEngine {
    global: RwLock<ProtectionMode>,
    by_category: RwLock<HashMap<ThreatCategory, ProtectionMode>>,
}

impl PolicyEngine {
    /// Policy par défaut livrée : Detection global, sauf Impact (ransomware) et
    /// PrivilegeEscalation en Prevention — trop dangereux pour laisser passer en
    /// attente d'un arbitrage humain (cf. choix produit : privesc = on bloque).
    pub fn with_defaults() -> Self {
        let mut by_category = HashMap::new();
        by_category.insert(ThreatCategory::Impact, ProtectionMode::Prevention);
        by_category.insert(ThreatCategory::PrivilegeEscalation, ProtectionMode::Prevention);
        Self {
            global: RwLock::new(ProtectionMode::Detection),
            by_category: RwLock::new(by_category),
        }
    }

    /// Mode effectif pour une catégorie (surcharge sinon global).
    pub fn mode_for(&self, category: ThreatCategory) -> ProtectionMode {
        if let Some(mode) = self.by_category.read().unwrap().get(&category) {
            return *mode;
        }
        *self.global.read().unwrap()
    }

    /// Règle le mode global.
    pub fn set_global(&self, mode: ProtectionMode) {
        *self.global.write().unwrap() = mode;
    }

    /// Règle (ou retire) la surcharge d'une catégorie.
    pub fn set_category(&self, category: ThreatCategory, mode: Option<ProtectionMode>) {
        let mut map = self.by_category.write().unwrap();
        match mode {
            Some(m) => { map.insert(category, m); }
            None => { map.remove(&category); }
        }
    }

    /// Décide l'action effective pour un verdict, selon le mode et la sévérité.
    pub fn decide(&self, verdict: &Verdict) -> Decision {
        let mode = self.mode_for(verdict.category);
        match (verdict.severity, mode) {
            (Severity::Info, _) => Decision::Log,
            (Severity::Low, _) => Decision::Notify,
            // Sévérité moyenne en observation : on ne bloque pas, on laisse passer
            // et on défère l'arbitrage à l'utilisateur (choix produit).
            (Severity::Medium, ProtectionMode::Detection) => Decision::Defer,
            // En prévention (ou catégorie forcée : privesc, impact), on gèle/isole.
            (Severity::Medium, ProtectionMode::Prevention) => isolate_or_quarantine(verdict),
            (Severity::High, ProtectionMode::Detection) => quarantine_or_notify(verdict),
            (Severity::High, ProtectionMode::Prevention) => isolate_or_quarantine(verdict),
            (Severity::Critical, ProtectionMode::Detection) => Decision::Notify,
            (Severity::Critical, ProtectionMode::Prevention) => kill_or_quarantine(verdict),
        }
    }
}

/// Quarantaine si l'action recommandée porte un chemin, sinon simple notification.
fn quarantine_or_notify(verdict: &Verdict) -> Decision {
    match &verdict.recommended_action {
        Action::Quarantine { path } => Decision::Quarantine { path: path.clone() },
        _ => Decision::Notify,
    }
}

fn isolate_or_quarantine(verdict: &Verdict) -> Decision {
    match &verdict.recommended_action {
        Action::Quarantine { path } => Decision::Quarantine { path: path.clone() },
        Action::Kill { pid } | Action::Isolate { pid } => Decision::Isolate { pid: *pid },
        _ => Decision::Notify,
    }
}

fn kill_or_quarantine(verdict: &Verdict) -> Decision {
    match &verdict.recommended_action {
        Action::Kill { pid } | Action::Isolate { pid } => Decision::Kill { pid: *pid },
        Action::Quarantine { path } => Decision::Quarantine { path: path.clone() },
        _ => Decision::Notify,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::{Engine, SCHEMA_VERSION};

    fn verdict(severity: Severity, category: ThreatCategory, action: Action) -> Verdict {
        Verdict {
            schema_version: SCHEMA_VERSION,
            event_id: 1,
            engine: Engine::Behavioral,
            severity,
            category,
            mitre: vec![],
            confidence: 1.0,
            title: "t".into(),
            detail: "d".into(),
            recommended_action: action,
        }
    }

    #[test]
    fn ransomware_critical_tue_par_defaut() {
        // Impact est en Prevention par défaut.
        let policy = PolicyEngine::with_defaults();
        let v = verdict(Severity::Critical, ThreatCategory::Impact, Action::Kill { pid: 42 });
        assert_eq!(policy.decide(&v), Decision::Kill { pid: 42 });
    }

    #[test]
    fn c2_critical_en_detection_ne_tue_pas() {
        // CommandAndControl suit le global (Detection) → pas de kill auto.
        let policy = PolicyEngine::with_defaults();
        let v = verdict(Severity::Critical, ThreatCategory::CommandAndControl, Action::Kill { pid: 7 });
        assert_eq!(policy.decide(&v), Decision::Notify);
    }

    #[test]
    fn passage_global_en_prevention_active_le_kill() {
        let policy = PolicyEngine::with_defaults();
        policy.set_global(ProtectionMode::Prevention);
        let v = verdict(Severity::Critical, ThreatCategory::CommandAndControl, Action::Kill { pid: 7 });
        assert_eq!(policy.decide(&v), Decision::Kill { pid: 7 });
    }

    #[test]
    fn medium_en_detection_est_defere() {
        // Sévérité moyenne en Detection : laisser passer + arbitrage utilisateur.
        let policy = PolicyEngine::with_defaults();
        let v = verdict(Severity::Medium, ThreatCategory::CredentialAccess, Action::Notify);
        assert_eq!(policy.decide(&v), Decision::Defer);
    }

    #[test]
    fn medium_privilege_escalation_est_isole() {
        // Privesc forcé en Prevention par défaut → on gèle même en sévérité moyenne.
        let policy = PolicyEngine::with_defaults();
        let v = verdict(Severity::Medium, ThreatCategory::PrivilegeEscalation, Action::Kill { pid: 9 });
        assert_eq!(policy.decide(&v), Decision::Isolate { pid: 9 });
    }

    #[test]
    fn high_signature_met_en_quarantaine() {
        let policy = PolicyEngine::with_defaults();
        let v = verdict(
            Severity::High,
            ThreatCategory::Signature,
            Action::Quarantine { path: "/tmp/x".into() },
        );
        assert_eq!(policy.decide(&v), Decision::Quarantine { path: "/tmp/x".into() });
    }
}
