import { loadSession, writeSession } from "../../core/runner/session-store.ts";

async function main(): Promise<void> {
  const sessionId = process.argv.find((arg) => arg.startsWith("--session="))?.split("=")[1] ?? "unknown";
  const status = process.argv.find((arg) => arg.startsWith("--status="))?.split("=")[1] ?? "unknown";
  const payload = process.argv.find((arg) => arg.startsWith("--payload="))?.split("=")[1] ?? "";
  const family = process.argv.find((arg) => arg.startsWith("--family="))?.split("=")[1] ?? "";
  const blocked = process.argv.includes("--blocked");
  const reflected = process.argv.includes("--reflected");
  const executed = process.argv.includes("--executed");
  const session = loadSession(sessionId);
  const knowledge = (session.knowledge || {}) as Record<string, unknown>;
  const blockedFamilies = (knowledge.blockedFamilies as Record<string, string[] | undefined> | undefined) ?? {};
  const footholds = (knowledge.footholds as Array<{ family: string; value: string }> | undefined) ?? [];
  if (blocked && family && payload) {
    blockedFamilies[family] = [...new Set([...(blockedFamilies[family] ?? []), payload])];
  }
  if (reflected && family && payload) {
    footholds.push({ family, value: payload });
  }
  knowledge.blockedFamilies = blockedFamilies;
  knowledge.footholds = footholds;
  session.knowledge = knowledge;
  session.observations.push({
    status,
    payload,
    family,
    blocked,
    reflected,
    executed,
    observedAt: new Date().toISOString()
  });
  writeSession(session);
  console.log(JSON.stringify({
    sessionId,
    status,
    payload,
    family,
    blocked,
    reflected,
    executed,
    observedAt: new Date().toISOString()
  }, null, 2));
}

void main();
