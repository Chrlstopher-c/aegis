// Panneau de gestion de la quarantaine : liste les fichiers isolés, permet de
// les restaurer (remise en place + droits d'origine) ou de les supprimer
// définitivement. La suppression est destructive → confirmation en deux temps.

import { useCallback, useEffect, useState } from "react";

import type { Command, CommandResult, QuarantineEntry } from "../types";

interface Props {
  sendCommand: (cmd: Command) => Promise<CommandResult>;
  onClose: () => void;
}

function formatDate(ns: number): string {
  return new Date(ns / 1_000_000).toLocaleString("fr-FR");
}

export function QuarantinePanel({ sendCommand, onClose }: Props) {
  const [entries, setEntries] = useState<QuarantineEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const res = await sendCommand("ListQuarantine");
      if (!res.ok) throw new Error(res.error ?? "échec de la liste");
      setEntries((res.data as QuarantineEntry[]) ?? []);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "daemon injoignable");
    }
  }, [sendCommand]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const act = async (cmd: Command, id: string): Promise<void> => {
    setBusyId(id);
    try {
      const res = await sendCommand(cmd);
      if (!res.ok) throw new Error(res.error ?? "échec de l'action");
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "action impossible");
    } finally {
      setBusyId(null);
      setConfirming(null);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-6" onClick={onClose}>
      <div
        className="flex max-h-[80vh] w-full max-w-3xl flex-col overflow-hidden rounded-xl border border-neutral-800 bg-neutral-950 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <header className="flex items-center justify-between border-b border-neutral-800 px-6 py-4">
          <div className="flex items-center gap-3">
            <span className="text-xs font-medium uppercase tracking-[0.3em] text-emerald-500">
              Quarantaine
            </span>
            <span className="tabular-nums text-sm text-neutral-400">{entries.length}</span>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded px-2 py-1 text-sm text-neutral-400 hover:bg-neutral-800 hover:text-neutral-100"
          >
            Fermer
          </button>
        </header>

        {error && (
          <p className="border-b border-red-900/50 bg-red-950/40 px-6 py-2 text-sm text-red-300">{error}</p>
        )}

        <div className="flex-1 overflow-y-auto px-4 py-3">
          {entries.length === 0 ? (
            <p className="px-2 py-10 text-center text-neutral-600">Aucun fichier en quarantaine.</p>
          ) : (
            <ul className="flex flex-col gap-2">
              {entries.map((e) => (
                <li key={e.id} className="rounded-lg border border-neutral-800/80 bg-neutral-900/30 px-4 py-3">
                  <div className="flex items-start gap-3">
                    <div className="min-w-0 flex-1">
                      <p className="truncate font-mono text-sm text-neutral-200">{e.original_path}</p>
                      <p className="mt-0.5 text-xs text-neutral-500">
                        {formatDate(e.quarantined_at_ns)} · {e.reason}
                      </p>
                    </div>
                    <div className="flex shrink-0 gap-2">
                      <button
                        type="button"
                        disabled={busyId === e.id}
                        onClick={() => act({ Restore: { quarantine_id: e.id } }, e.id)}
                        className="rounded bg-neutral-800 px-2.5 py-1 text-xs text-neutral-200 hover:bg-neutral-700 disabled:opacity-40"
                      >
                        Restaurer
                      </button>
                      {confirming === e.id ? (
                        <button
                          type="button"
                          disabled={busyId === e.id}
                          onClick={() => act({ PurgeQuarantine: { quarantine_id: e.id } }, e.id)}
                          className="rounded bg-red-600 px-2.5 py-1 text-xs font-medium text-white hover:bg-red-500 disabled:opacity-40"
                        >
                          Confirmer
                        </button>
                      ) : (
                        <button
                          type="button"
                          disabled={busyId === e.id}
                          onClick={() => setConfirming(e.id)}
                          className="rounded border border-red-900/60 px-2.5 py-1 text-xs text-red-400 hover:bg-red-950/50 disabled:opacity-40"
                        >
                          Supprimer
                        </button>
                      )}
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
