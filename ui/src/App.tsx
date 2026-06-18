import { useAegisStream } from "./useAegisStream";
import { useTrayStatus } from "./useTrayStatus";
import { ProtectionHeader } from "./components/ProtectionHeader";
import { VerdictList } from "./components/VerdictList";
import { EventFeed } from "./components/EventFeed";

function App() {
  const { status, events, verdicts, sendCommand } = useAegisStream();
  useTrayStatus(status, verdicts.length);

  return (
    <main className="flex h-full flex-col bg-neutral-950 text-neutral-100">
      <ProtectionHeader status={status} threatCount={verdicts.length} />
      <div className="grid flex-1 grid-cols-1 gap-px overflow-hidden bg-neutral-900 lg:grid-cols-[1.1fr_1fr]">
        <VerdictList verdicts={verdicts} sendCommand={sendCommand} />
        <EventFeed events={events} />
      </div>
    </main>
  );
}

export default App;
