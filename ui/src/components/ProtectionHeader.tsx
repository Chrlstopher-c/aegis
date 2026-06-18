import type { ConnectionState } from "../useAegisStream";

interface Props {
  status: ConnectionState;
  threatCount: number;
  onOpenQuarantine: () => void;
}

const STATUS_LABEL: Record<ConnectionState, string> = {
  connecting: "Connexion…",
  online: "Protection active",
  offline: "Daemon hors ligne",
};

const STATUS_DOT: Record<ConnectionState, string> = {
  connecting: "bg-amber-400",
  online: "bg-emerald-500",
  offline: "bg-red-500",
};

export function ProtectionHeader({ status, threatCount, onOpenQuarantine }: Props) {
  return (
    <header className="flex items-center justify-between border-b border-neutral-800 px-6 py-4">
      <div className="flex items-center gap-3">
        <span className="text-xs font-medium uppercase tracking-[0.3em] text-emerald-500">
          Aegis
        </span>
        <span className="text-neutral-700">/</span>
        <div className="flex items-center gap-2">
          <span className={`h-2 w-2 rounded-full ${STATUS_DOT[status]}`} />
          <span className="text-sm text-neutral-300">{STATUS_LABEL[status]}</span>
        </div>
      </div>
      <div className="flex items-center gap-5">
        <button
          type="button"
          onClick={onOpenQuarantine}
          className="rounded-md border border-neutral-800 px-3 py-1.5 text-xs font-medium text-neutral-300 hover:border-neutral-700 hover:bg-neutral-900 hover:text-neutral-100"
        >
          Quarantaine
        </button>
        <div className="flex items-baseline gap-2">
          <span className="text-2xl font-semibold tabular-nums">{threatCount}</span>
          <span className="text-xs uppercase tracking-wider text-neutral-500">détections</span>
        </div>
      </div>
    </header>
  );
}
