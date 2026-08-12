import { MutationComposer } from "../../core/engines/mutation/composer.ts";
import { loadSession, writeSession } from "../../core/runner/session-store.ts";

async function main(): Promise<void> {
  const sessionId = process.argv.find((arg) => arg.startsWith("--session="))?.split("=")[1] ?? "unknown";
  const session = loadSession(sessionId);
  const composer = new MutationComposer(String(session.context || "html_content"));
  const knowledge = session.knowledge || {};
  const blockedFamilies = knowledge.blockedFamilies as Record<string, string[]> | undefined;
  const footholds = knowledge.footholds as Array<{ family: string; value: string }> | undefined;
  const testedPayloads = knowledge.testedPayloads as string[] | undefined;
  if (blockedFamilies) {
    for (const [family, values] of Object.entries(blockedFamilies)) {
      composer.state.blockedFamilies.set(family, new Set(values));
    }
  }
  if (footholds) {
    for (const foothold of footholds) {
      composer.absorbPartialSuccess(foothold.family, foothold.value);
    }
  }
  if (testedPayloads) {
    for (const payload of testedPayloads) {
      composer.state.testedPayloads.add(payload);
    }
  }
  const next = composer.nextCandidates().slice(0, 5);
  session.knowledge = composer.exportState();
  writeSession(session);
  console.log(JSON.stringify({
    sessionId,
    next
  }, null, 2));
}

void main();
