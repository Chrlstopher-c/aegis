import { useMemo } from "react";

import type { AppKind, EventEnvelope } from "../types";
import { usePersistentState } from "../usePersistentState";
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

// Groupes considérés comme bruit système (masqués par défaut).
const SYSTEM_KINDS: ReadonlySet<AppKind | "Unattributed"> = new Set(["System", "Service"]);

interface SectionProps {
  group: AppGroup;
  collapsed: boolean;
  onToggle: () => void;
}

function AppSection({ group, collapsed, onToggle }: SectionProps) {
  const badge = KIND_BADGE[group.kind];
  return (
    <li className="rounded-lg border border-neutral-800/80 bg-neutral-900/30">
      <button
        type="button"
        onClick={onToggle}
        className="flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-neutral-900/40"
      >
        <span
          className={`shrink-0 text-neutral-600 transition-transform ${collapsed ? "" : "rotate-90"}`}
        >
          ▸
        </span>
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
      </button>
      {!collapsed && (
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
      )}
    </li>
  );
}

export function EventFeed({ events }: Props) {
  const groups = useMemo(() => aggregate(events), [events]);
  const [collapsedList, setCollapsedList] = usePersistentState<string[]>("aegis.feed.collapsed", []);
  const [showSystem, setShowSystem] = usePersistentState<boolean>("aegis.feed.showSystem", false);
  const collapsed = useMemo(() => new Set(collapsedList), [collapsedList]);

  const hiddenSystem = useMemo(
    () => groups.filter((g) => SYSTEM_KINDS.has(g.kind)).length,
    [groups],
  );
  const visible = showSystem ? groups : groups.filter((g) => !SYSTEM_KINDS.has(g.kind));

  const toggle = (key: string): void =>
    setCollapsedList(
      collapsed.has(key) ? collapsedList.filter((k) => k !== key) : [...collapsedList, key],
    );

  return (
    <section className="flex flex-col overflow-hidden bg-neutral-950">
      <div className="flex items-center justify-between px-6 py-3">
        <h2 className="text-xs font-medium uppercase tracking-wider text-neutral-500">
          Flux temps réel · par application
        </h2>
        {(hiddenSystem > 0 || showSystem) && (
          <button
            type="button"
            onClick={() => setShowSystem(!showSystem)}
            className="rounded px-2 py-0.5 text-[10px] font-medium text-neutral-400 hover:bg-neutral-800 hover:text-neutral-200"
          >
            {showSystem ? "masquer le bruit système" : `afficher le système (${hiddenSystem})`}
          </button>
        )}
      </div>
      <div className="flex-1 overflow-y-auto px-4 pb-4">
        {visible.length === 0 ? (
          <p className="px-2 py-8 text-center text-neutral-600">En attente d'activité…</p>
        ) : (
          <ul className="flex flex-col gap-2">
            {visible.map((g) => (
              <AppSection
                key={g.key}
                group={g}
                collapsed={collapsed.has(g.key)}
                onToggle={() => toggle(g.key)}
              />
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
