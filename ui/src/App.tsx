import { useAegisStream } from "./useAegisStream";
import { ProtectionHeader } from "./components/ProtectionHeader";
import { VerdictList } from "./components/VerdictList";
import { EventFeed } from "./components/EventFeed";

function App() {
  const { status, events, verdicts } = useAegisStream();

  return (
    <main className="flex h-full flex-col bg-neutral-950 text-neutral-100">
      <ProtectionHeader status={status} threatCount={verdicts.length} />
      <div className="grid flex-1 grid-cols-1 gap-px overflow-hidden bg-neutral-900 lg:grid-cols-[1.1fr_1fr]">
        <VerdictList verdicts={verdicts} />
        <EventFeed events={events} />
      </div>
    </main>
  );
}

export default App;
