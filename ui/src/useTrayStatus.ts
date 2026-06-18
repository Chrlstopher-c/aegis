// Reflète l'état de protection dans l'icône du SysTray (vert/rouge + infobulle).
// No-op hors contexte Tauri (dev navigateur) : l'invoke échoue silencieusement.

import { useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { ConnectionState } from "./useAegisStream";

export function useTrayStatus(status: ConnectionState, threats: number): void {
  useEffect(() => {
    if (!(window as { isTauri?: boolean }).isTauri) {
      return; // exécution navigateur : pas de tray à piloter.
    }
    invoke("set_protection_status", { online: status === "online", threats }).catch(() => {
      // tray indisponible : statut non reflété, sans incidence sur l'UI.
    });
  }, [status, threats]);
}
