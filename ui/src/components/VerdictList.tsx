import type { Command, CommandResult, Verdict } from "../types";
import { VerdictCard } from "./VerdictCard";

interface Props {
  verdicts: Verdict[];
  sendCommand: (cmd: Command) => Promise<CommandResult>;
}

export function VerdictList({ verdicts, sendCommand }: Props) {
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
              <VerdictCard key={`${v.event_id}-${i}`} verdict={v} sendCommand={sendCommand} />
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
