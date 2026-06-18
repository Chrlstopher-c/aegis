//! Harnais de validation : attribue chaque pid passé en argument à son
//! application racine. `cargo run --example attribute -p aegis-probes -- <pid>...`

fn main() {
    for arg in std::env::args().skip(1) {
        let Ok(pid) = arg.parse::<u32>() else { continue };
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .unwrap_or_default()
            .trim()
            .to_string();
        match aegis_probes::attribute_app(pid) {
            Some(a) => println!("{pid:>7} {comm:<16} → {} [{:?}] (root {})", a.name, a.kind, a.root_pid),
            None => println!("{pid:>7} {comm:<16} → (aucune attribution)"),
        }
    }
}
