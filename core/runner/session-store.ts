import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";

export interface EnigmaSession {
  sessionId: string;
  target: string;
  parameter: string;
  context: string;
  createdAt: string;
  updatedAt: string;
  knowledge: Record<string, unknown>;
  observations: Array<Record<string, unknown>>;
}

function sessionRoot(): string {
  const root = process.env.ENIGMA_SESSION_DIR || join(process.cwd(), ".sessions");
  mkdirSync(root, { recursive: true });
  return root;
}

function sessionPath(sessionId: string): string {
  return join(sessionRoot(), `${sessionId}.json`);
}

export function createSession(target: string, parameter: string, context = "html_content", knowledge: Record<string, unknown> = {}): EnigmaSession {
  const sessionId = `xss-${Date.now().toString(36)}`;
  const now = new Date().toISOString();
  const session: EnigmaSession = {
    sessionId,
    target,
    parameter,
    context,
    createdAt: now,
    updatedAt: now,
    knowledge,
    observations: []
  };
  writeSession(session);
  return session;
}

export function loadSession(sessionId: string): EnigmaSession {
  const path = sessionPath(sessionId);
  if (!existsSync(path)) {
    throw new Error(`session not found: ${sessionId}`);
  }
  return JSON.parse(readFileSync(path, "utf8")) as EnigmaSession;
}

export function writeSession(session: EnigmaSession): EnigmaSession {
  session.updatedAt = new Date().toISOString();
  writeFileSync(sessionPath(session.sessionId), JSON.stringify(session, null, 2));
  return session;
}

