import { useMemo } from "react";

import type { AppKind, EventEnvelope } from "../types";
import { aggregate, type AppGroup } from "./eventAggregate";

interface Props {
  events: EventEnvelope[];
}

// Pastille de nature d'application : registre de lecture (app de bureau, terminal,
// service…). L'activité non attribuée est mise en avant (plus suspecte).
const KIND_BADGE: Record<AppKind | "Unattributed", { label: string; cls: string }> = {
  Desktop: { label: "app", cls: "bg-sky-500/15 text-sky-300" },
  Terminal: { label: "terminal", cls: "bg-violet-500/15 text-violet-300" },
  Service: { label: "service", cls: "bg-neutral-700 text-neutral-300" },
  System: { label: "système", cls: "bg-neutral-700 text-neutral-400" },
  Unknown: { label: "?", cls: "bg-neutral-700 text-neutral-400" },
  Unattributed: { label: "non attribué", cls: "bg-amber-500/15 text-amber-300" },
};

function AppSection({ group }: { group: AppGroup }) {
  const badge = KIND_BADGE[group.kind];
  return (
    <li className="rounded-lg border border-neutral-800/80 bg-neutral-900/30">
      <div className="flex items-center gap-2 px-3 py-2">
        <span className="text-sm font-medium text-neutral-100">{group.name}</span>
        <span className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${badge.cls}`}>
          {badge.label}
        </span>
        {group.rootPid !== null && (
          <span className="font-mono text-[10px] text-neutral-600">pid {group.rootPid}</span>
        )}
        <span className="ml-auto tabular-nums text-[10px] text-neutral-500">
          {group.total} évén.
        </span>
      </div>
      <ul className="flex flex-col gap-px border-t border-neutral-800/60 px-2 py-1.5 font-mono text-xs">
        {group.children.map((row) => (
          <li key={row.key} className="flex items-center gap-3 rounded px-2 py-1 hover:bg-neutral-900">
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
    </li>
  );
}

export function EventFeed({ events }: Props) {
  const groups = useMemo(() => aggregate(events), [events]);

  return (
    <section className="flex flex-col overflow-hidden bg-neutral-950">
      <h2 className="px-6 py-3 text-xs font-medium uppercase tracking-wider text-neutral-500">
        Flux temps réel · par application
      </h2>
      <div className="flex-1 overflow-y-auto px-4 pb-4">
        {groups.length === 0 ? (
          <p className="px-2 py-8 text-center text-neutral-600">En attente d'activité…</p>
        ) : (
          <ul className="flex flex-col gap-2">
            {groups.map((g) => (
              <AppSection key={g.key} group={g} />
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
