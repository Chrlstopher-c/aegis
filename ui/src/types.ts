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

export interface ProcessCtx {
  pid: number;
  ppid: number;
  exe_path: string;
  comm: string;
  cmdline: string;
  uid: number;
}

export interface EventEnvelope {
  event_id: string;
  ts: number;
  source: string;
  process: ProcessCtx;
  payload: Record<string, unknown>;
}

export interface Verdict {
  event_id: string;
  engine: string;
  severity: Severity;
  category: ThreatCategory;
  mitre: string[];
  confidence: number;
  title: string;
  detail: string;
}

export type StreamMessage =
  | ({ type: "event" } & EventEnvelope)
  | ({ type: "verdict" } & Verdict);
