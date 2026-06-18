// Hook de connexion au bridge WebSocket du daemon Aegis. Reconnexion auto,
// buffers bornés (flux d'événements + liste de verdicts) pour ne pas exploser
// la mémoire sur un flux continu. Émet aussi les commandes UI → daemon et
// corrèle leur réponse (CommandResult) au prochain message non-flux reçu.

import { useCallback, useEffect, useRef, useState } from "react";
import type { Command, CommandResult, EventEnvelope, StreamMessage, Verdict } from "./types";

const WS_URL = "ws://127.0.0.1:8787";
const MAX_EVENTS = 200;
const MAX_VERDICTS = 100;
const RECONNECT_MS = 2000;
const COMMAND_TIMEOUT_MS = 5000;

export type ConnectionState = "connecting" | "online" | "offline";

interface AegisStream {
  status: ConnectionState;
  events: EventEnvelope[];
  verdicts: Verdict[];
  sendCommand: (cmd: Command) => Promise<CommandResult>;
}

type PendingCommand = {
  resolve: (result: CommandResult) => void;
  reject: (reason: Error) => void;
  timer: ReturnType<typeof setTimeout>;
};

// Discrimine un message de flux (StreamMessage, champ `type`) d'une réponse de
// commande (CommandResult, champ booléen `ok`).
function isStreamMessage(msg: unknown): msg is StreamMessage {
  return typeof msg === "object" && msg !== null && "type" in msg;
}

export function useAegisStream(): AegisStream {
  const [status, setStatus] = useState<ConnectionState>("connecting");
  const [events, setEvents] = useState<EventEnvelope[]>([]);
  const [verdicts, setVerdicts] = useState<Verdict[]>([]);
  const socketRef = useRef<WebSocket | null>(null);
  // File FIFO des commandes en attente de réponse (faible concurrence : clics UI).
  const pendingRef = useRef<PendingCommand[]>([]);

  useEffect(() => {
    let closed = false;
    let timer: ReturnType<typeof setTimeout>;

    const connect = (): void => {
      const ws = new WebSocket(WS_URL);
      socketRef.current = ws;
      setStatus("connecting");

      ws.onopen = () => setStatus("online");
      ws.onmessage = (ev) => dispatch(ev.data as string);
      ws.onclose = () => {
        if (closed) return;
        setStatus("offline");
        failPending(new Error("connexion perdue"));
        timer = setTimeout(connect, RECONNECT_MS);
      };
      ws.onerror = () => ws.close();
    };

    const dispatch = (raw: string): void => {
      let msg: unknown;
      try {
        msg = JSON.parse(raw);
      } catch {
        return; // message non parseable ignoré (résilience flux)
      }
      if (isStreamMessage(msg)) {
        if (msg.type === "event") {
          setEvents((prev) => [msg, ...prev].slice(0, MAX_EVENTS));
        } else {
          setVerdicts((prev) => [msg, ...prev].slice(0, MAX_VERDICTS));
        }
        return;
      }
      // Réponse de commande : résout la plus ancienne en attente.
      const pending = pendingRef.current.shift();
      if (pending) {
        clearTimeout(pending.timer);
        pending.resolve(msg as CommandResult);
      }
    };

    const failPending = (reason: Error): void => {
      for (const p of pendingRef.current) {
        clearTimeout(p.timer);
        p.reject(reason);
      }
      pendingRef.current = [];
    };

    connect();
    return () => {
      closed = true;
      clearTimeout(timer);
      failPending(new Error("hook démonté"));
      socketRef.current?.close();
    };
  }, []);

  const sendCommand = useCallback((cmd: Command): Promise<CommandResult> => {
    const ws = socketRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      return Promise.reject(new Error("daemon hors ligne"));
    }
    return new Promise<CommandResult>((resolve, reject) => {
      const timer = setTimeout(() => {
        pendingRef.current = pendingRef.current.filter((p) => p.timer !== timer);
        reject(new Error("commande sans réponse (timeout)"));
      }, COMMAND_TIMEOUT_MS);
      pendingRef.current.push({ resolve, reject, timer });
      ws.send(JSON.stringify(cmd));
    });
  }, []);

  return { status, events, verdicts, sendCommand };
}
