// Miroir TypeScript du contrat IPC (aegis-core). Le bridge WebSocket sérialise
// StreamMessage avec un champ `type` discriminant ("event" | "verdict").

export type Severity = "Info" | "Low" | "Medium" | "High" | "Critical";

export type ThreatCategory =
  | "Execution"
  | "Persistence"
  | "PrivilegeEscalation"
  | "DefenseEvasion"
  | "CredentialAccess"
  | "CommandAndControl"
  | "Impact"
  | "Signature";

export type AppKind = "Desktop" | "Terminal" | "Service" | "System" | "Unknown";

export interface AppAttribution {
  name: string;
  kind: AppKind;
  root_pid: number;
}

export interface ProcessCtx {
  pid: number;
  ppid: number;
  exe_path: string;
  comm: string;
  cmdline: string;
  uid: number;
  app?: AppAttribution;
}

export interface EventEnvelope {
  event_id: string;
  ts: number;
  source: string;
  process: ProcessCtx;
  payload: Record<string, unknown>;
}

// Action recommandée par le moteur, portée par le verdict. Enum Rust sérialisé
// en externally-tagged : variante simple = chaîne, variante à champ = objet.
export type Action =
  | "Log"
  | "Notify"
  | { Quarantine: { path: string } }
  | { Isolate: { pid: number } }
  | { Kill: { pid: number } };

export interface Verdict {
  event_id: number;
  engine: string;
  severity: Severity;
  category: ThreatCategory;
  mitre: string[];
  confidence: number;
  title: string;
  detail: string;
  recommended_action: Action;
}

export type StreamMessage =
  | ({ type: "event" } & EventEnvelope)
  | ({ type: "verdict" } & Verdict);

// Commandes UI → daemon (sous-ensemble câblé côté daemon). Enum Rust
// externally-tagged : { Quarantine: { path } }, etc.
export type Command =
  | { Quarantine: { path: string } }
  | { Restore: { quarantine_id: string } }
  | { KillProcess: { pid: number } };

export interface CommandResult {
  ok: boolean;
  error?: string;
  data?: unknown;
}
