// Dérive les actions manuelles offertes par une détection à partir de son
// `recommended_action`. Le daemon reste l'arbitre : l'UI ne fait qu'émettre la
// commande correspondante. Seules les commandes réellement câblées côté daemon
// sont exposées (quarantaine, kill).

import type { Action, Command } from "../types";

export interface VerdictAction {
  label: string;
  command: Command;
  danger: boolean;
}

export function actionsFor(recommended: Action): VerdictAction[] {
  if (recommended === "Log" || recommended === "Notify") {
    return [];
  }
  if ("Quarantine" in recommended) {
    return [
      {
        label: "Mettre en quarantaine",
        command: { Quarantine: { path: recommended.Quarantine.path } },
        danger: false,
      },
    ];
  }
  // Kill comme Isolate : le pid est connu, on offre la neutralisation dure
  // (la commande Isolate n'est pas câblée côté daemon).
  const pid = "Kill" in recommended ? recommended.Kill.pid : recommended.Isolate.pid;
  return [{ label: "Tuer le process", command: { KillProcess: { pid } }, danger: true }];
}
