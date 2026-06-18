import type { Verdict } from "../types";
import { SEVERITY_STYLE } from "./severity";

interface Props {
  verdicts: Verdict[];
}

export function VerdictList({ verdicts }: Props) {
  return (
    <section className="flex flex-col overflow-hidden bg-neutral-950">
      <h2 className="px-6 py-3 text-xs font-medium uppercase tracking-wider text-neutral-500">
        Détections
      </h2>
      <div className="flex-1 overflow-y-auto px-4 pb-4">
        {verdicts.length === 0 ? (
          <p className="px-2 py-8 text-center text-sm text-neutral-600">
            Aucune menace détectée.
          </p>
        ) : (
          <ul className="flex flex-col gap-2">
            {verdicts.map((v, i) => (
              <li
                key={`${v.event_id}-${i}`}
                className={`rounded-lg border px-4 py-3 ${SEVERITY_STYLE[v.severity]}`}
              >
                <div className="flex items-center justify-between gap-3">
                  <span className="text-sm font-medium text-neutral-100">{v.title}</span>
                  <span className="shrink-0 text-[10px] font-semibold uppercase tracking-wider">
                    {v.severity}
                  </span>
                </div>
                <p className="mt-1 text-xs text-neutral-400">{v.detail}</p>
                <div className="mt-2 flex flex-wrap items-center gap-2 text-[10px] text-neutral-500">
                  <span className="rounded bg-neutral-800 px-1.5 py-0.5">{v.engine}</span>
                  <span className="rounded bg-neutral-800 px-1.5 py-0.5">{v.category}</span>
                  {v.mitre.map((m) => (
                    <span key={m} className="rounded bg-neutral-800 px-1.5 py-0.5 font-mono">
                      {m}
                    </span>
                  ))}
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
