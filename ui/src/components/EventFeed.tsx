import type { EventEnvelope } from "../types";

interface Props {
  events: EventEnvelope[];
}

// Extrait un chemin lisible du payload File, sinon le type de source.
function describe(event: EventEnvelope): string {
  const payload = event.payload as { File?: { path?: string; op?: string } };
  if (payload.File?.path) {
    return `${payload.File.op ?? "?"} · ${payload.File.path}`;
  }
  return event.source;
}

export function EventFeed({ events }: Props) {
  return (
    <section className="flex flex-col overflow-hidden bg-neutral-950">
      <h2 className="px-6 py-3 text-xs font-medium uppercase tracking-wider text-neutral-500">
        Flux temps réel
      </h2>
      <div className="flex-1 overflow-y-auto px-4 pb-4 font-mono text-xs">
        {events.length === 0 ? (
          <p className="px-2 py-8 text-center text-neutral-600">En attente d'activité…</p>
        ) : (
          <ul className="flex flex-col gap-1">
            {events.map((e, i) => (
              <li
                key={`${e.event_id}-${i}`}
                className="flex items-center gap-3 rounded px-2 py-1.5 hover:bg-neutral-900"
              >
                <span className="shrink-0 tabular-nums text-neutral-600">
                  {e.process.pid}
                </span>
                <span className="shrink-0 text-emerald-500">{e.process.comm}</span>
                <span className="truncate text-neutral-400">{describe(e)}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
