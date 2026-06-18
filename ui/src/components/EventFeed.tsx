import { useMemo } from "react";

import type { EventEnvelope } from "../types";
import { aggregate } from "./eventAggregate";

interface Props {
  events: EventEnvelope[];
}

export function EventFeed({ events }: Props) {
  const rows = useMemo(() => aggregate(events), [events]);

  return (
    <section className="flex flex-col overflow-hidden bg-neutral-950">
      <h2 className="px-6 py-3 text-xs font-medium uppercase tracking-wider text-neutral-500">
        Flux temps réel
      </h2>
      <div className="flex-1 overflow-y-auto px-4 pb-4 font-mono text-xs">
        {rows.length === 0 ? (
          <p className="px-2 py-8 text-center text-neutral-600">En attente d'activité…</p>
        ) : (
          <ul className="flex flex-col gap-1">
            {rows.map((row) => (
              <li
                key={row.key}
                className="flex items-center gap-3 rounded px-2 py-1.5 hover:bg-neutral-900"
              >
                <span className="shrink-0 tabular-nums text-neutral-600">{row.pid}</span>
                <span className="shrink-0 text-emerald-500">{row.comm}</span>
                <span className="truncate text-neutral-400">{row.label}</span>
                {row.count > 1 && (
                  <span className="ml-auto shrink-0 rounded bg-neutral-800 px-1.5 py-0.5 tabular-nums text-neutral-400">
                    ×{row.count}
                  </span>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
