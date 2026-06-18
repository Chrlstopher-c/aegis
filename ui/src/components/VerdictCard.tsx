import { useState } from "react";

import type { Command, CommandResult, Verdict } from "../types";
import { SEVERITY_STYLE } from "./severity";
import { actionsFor } from "./verdictActions";

interface Props {
  verdict: Verdict;
  sendCommand: (cmd: Command) => Promise<CommandResult>;
}

type ActionState = { kind: "idle" } | { kind: "pending" } | { kind: "done" } | { kind: "error"; msg: string };

export function VerdictCard({ verdict, sendCommand }: Props) {
  const [state, setState] = useState<ActionState>({ kind: "idle" });
  const actions = actionsFor(verdict.recommended_action);

  const run = async (cmd: Command): Promise<void> => {
    setState({ kind: "pending" });
    try {
      const result = await sendCommand(cmd);
      setState(result.ok ? { kind: "done" } : { kind: "error", msg: result.error ?? "échec" });
    } catch (err) {
      setState({ kind: "error", msg: err instanceof Error ? err.message : "échec" });
    }
  };

  return (
    <li className={`rounded-lg border px-4 py-3 ${SEVERITY_STYLE[verdict.severity]}`}>
      <div className="flex items-center justify-between gap-3">
        <span className="text-sm font-medium text-neutral-100">{verdict.title}</span>
        <span className="shrink-0 text-[10px] font-semibold uppercase tracking-wider">
          {verdict.severity}
        </span>
      </div>
      <p className="mt-1 text-xs text-neutral-400">{verdict.detail}</p>
      <div className="mt-2 flex flex-wrap items-center gap-2 text-[10px] text-neutral-500">
        <span className="rounded bg-neutral-800 px-1.5 py-0.5">{verdict.engine}</span>
        <span className="rounded bg-neutral-800 px-1.5 py-0.5">{verdict.category}</span>
        {verdict.mitre.map((m) => (
          <span key={m} className="rounded bg-neutral-800 px-1.5 py-0.5 font-mono">
            {m}
          </span>
        ))}
      </div>
      {actions.length > 0 && (
        <div className="mt-3 flex flex-wrap items-center gap-2">
          {state.kind === "done" ? (
            <span className="text-xs text-emerald-400">✓ Action appliquée</span>
          ) : (
            actions.map((a) => (
              <button
                key={a.label}
                type="button"
                disabled={state.kind === "pending"}
                onClick={() => run(a.command)}
                className={`rounded px-2.5 py-1 text-xs font-medium transition disabled:opacity-50 ${
                  a.danger
                    ? "bg-red-500/15 text-red-300 hover:bg-red-500/25"
                    : "bg-neutral-700/60 text-neutral-200 hover:bg-neutral-700"
                }`}
              >
                {a.label}
              </button>
            ))
          )}
          {state.kind === "error" && <span className="text-xs text-red-400">{state.msg}</span>}
        </div>
      )}
    </li>
  );
}
