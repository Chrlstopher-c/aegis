import { useState } from "react";

import { useAegisStream } from "./useAegisStream";
import { useTrayStatus } from "./useTrayStatus";
import { ProtectionHeader } from "./components/ProtectionHeader";
import { VerdictList } from "./components/VerdictList";
import { EventFeed } from "./components/EventFeed";
import { QuarantinePanel } from "./components/QuarantinePanel";

function App() {
  const { status, events, verdicts, sendCommand } = useAegisStream();
  useTrayStatus(status, verdicts.length);
  const [quarantineOpen, setQuarantineOpen] = useState(false);

  return (
    <main className="flex h-full flex-col bg-neutral-950 text-neutral-100">
      <ProtectionHeader
        status={status}
        threatCount={verdicts.length}
        onOpenQuarantine={() => setQuarantineOpen(true)}
      />
      <div className="grid flex-1 grid-cols-1 gap-px overflow-hidden bg-neutral-900 lg:grid-cols-[1.1fr_1fr]">
        <VerdictList verdicts={verdicts} sendCommand={sendCommand} />
        <EventFeed events={events} />
      </div>
      {quarantineOpen && (
        <QuarantinePanel sendCommand={sendCommand} onClose={() => setQuarantineOpen(false)} />
      )}
    </main>
  );
}

export default App;
