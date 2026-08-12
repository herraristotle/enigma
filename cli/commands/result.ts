import { loadSession } from "../../core/runner/session-store.ts";

async function main(): Promise<void> {
  const sessionId = process.argv.find((arg) => arg.startsWith("--session="))?.split("=")[1] ?? "unknown";
  const session = loadSession(sessionId);
  const knowledge = (session.knowledge || {}) as Record<string, unknown>;
  const observations = session.observations || [];

  const executed = observations.some((obs: any) => obs.executed === true);
  const blockedCount = observations.filter((obs: any) => obs.blocked === true).length;
  const reflectedCount = observations.filter((obs: any) => obs.reflected === true).length;

  console.log(JSON.stringify({
    sessionId: session.sessionId,
    target: session.target,
    parameter: session.parameter,
    context: session.context,
    status: executed ? "VULNERABLE" : "IN_PROGRESS",
    summary: {
      totalObservations: observations.length,
      blocked: blockedCount,
      reflected: reflectedCount,
      executed: executed
    },
    blockedFamilies: knowledge.blockedFamilies ?? {},
    footholds: knowledge.footholds ?? [],
    notes: knowledge.notes ?? [],
    createdAt: session.createdAt,
    updatedAt: session.updatedAt
  }, null, 2));
}

void main();
