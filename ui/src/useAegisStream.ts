// Hook de connexion au bridge WebSocket du daemon Aegis. Reconnexion auto,
// buffers bornés (flux d'événements + liste de verdicts) pour ne pas exploser
// la mémoire sur un flux continu.

import { useEffect, useRef, useState } from "react";
import type { EventEnvelope, StreamMessage, Verdict } from "./types";

const WS_URL = "ws://127.0.0.1:8787";
const MAX_EVENTS = 200;
const MAX_VERDICTS = 100;
const RECONNECT_MS = 2000;

export type ConnectionState = "connecting" | "online" | "offline";

interface AegisStream {
  status: ConnectionState;
  events: EventEnvelope[];
  verdicts: Verdict[];
}

export function useAegisStream(): AegisStream {
  const [status, setStatus] = useState<ConnectionState>("connecting");
  const [events, setEvents] = useState<EventEnvelope[]>([]);
  const [verdicts, setVerdicts] = useState<Verdict[]>([]);
  const socketRef = useRef<WebSocket | null>(null);

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
        timer = setTimeout(connect, RECONNECT_MS);
      };
      ws.onerror = () => ws.close();
    };

    const dispatch = (raw: string): void => {
      try {
        const msg = JSON.parse(raw) as StreamMessage;
        if (msg.type === "event") {
          setEvents((prev) => [msg, ...prev].slice(0, MAX_EVENTS));
        } else {
          setVerdicts((prev) => [msg, ...prev].slice(0, MAX_VERDICTS));
        }
      } catch {
        // message non parseable ignoré (résilience flux)
      }
    };

    connect();
    return () => {
      closed = true;
      clearTimeout(timer);
      socketRef.current?.close();
    };
  }, []);

  return { status, events, verdicts };
}
