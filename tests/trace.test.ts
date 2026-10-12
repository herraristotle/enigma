import { test } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { execSync } from "node:child_process";
import { TraceSink } from "../core/trace.ts";
import { executeSsrfPlan } from "../core/engines/ssrf/executor.ts";
import { NotificationManager } from "../core/engines/ssrf/canary.ts";

function tmpTrace(): { file: string; dir: string } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "enigma-trace-"));
  return { file: path.join(dir, "run.jsonl"), dir };
}

function readLines(file: string): Array<Record<string, unknown>> {
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
}

test("TraceSink writes NDJSON probe records with runId and stage", () => {
  const { file, dir } = tmpTrace();
  try {
    const sink = new TraceSink(file);
    sink.setStage("ssrf");
    sink.probe({ method: "GET", url: "https://example.com/x", status: 200, latencyMs: 12 });
    const lines = readLines(file);
    const probes = lines.filter((l) => l.event === "probe");
    assert.strictEqual(probes.length, 1);
    assert.strictEqual(probes[0].runId, sink.runId);
    assert.strictEqual(probes[0].stage, "ssrf");
    assert.strictEqual(probes[0].status, 200);
    assert.ok(typeof probes[0].ts === "string");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("TraceSink summary carries duration and request counts", () => {
  const { file, dir } = tmpTrace();
  try {
    const sink = new TraceSink(file);
    sink.probe({ method: "GET", url: "https://a.test/1", status: 200, latencyMs: 1 });
    sink.probe({ method: "GET", url: "https://a.test/2", status: 0, latencyMs: 1, error: "timeout" });
    sink.summary({ findings: 1 });
    const summary = readLines(file).find((l) => l.event === "run.summary");
    assert.ok(summary);
    assert.strictEqual(summary!.requests, 2);
    assert.strictEqual(summary!.errors, 1);
    assert.strictEqual(summary!.findings, 1);
    assert.ok(typeof summary!.durationMs === "number");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("executeSsrfPlan emits one probe record per request when trace is set", async () => {
  const server = http.createServer((_req, res) => {
    res.writeHead(200);
    res.end("benign");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("no port");
  const { file, dir } = tmpTrace();
  try {
    const sink = new TraceSink(file);
    const outcome = await executeSsrfPlan(
      `http://127.0.0.1:${address.port}/fetch`,
      "url",
      [
        { category: "internal service", payload: "http://10.0.0.1/", technique: "direct" },
        { category: "external service", payload: "http://example.com/", technique: "direct" }
      ],
      { notifications: new NotificationManager(), timeoutMs: 3000, trace: sink }
    );
    assert.strictEqual(outcome.results.length, 2);
    const probes = readLines(file).filter((l) => l.event === "probe");
    assert.strictEqual(probes.length, 2);
    assert.strictEqual(probes[0].url, `http://127.0.0.1:${address.port}/fetch`);
    assert.ok(typeof probes[0].latencyMs === "number");
    assert.strictEqual(probes[0].status, 200);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("CLI --trace writes probe records during --execute", async () => {
  const server = http.createServer((_req, res) => {
    res.writeHead(200);
    res.end("benign");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("no port");
  const { file, dir } = tmpTrace();
  try {
    const script = path.resolve(import.meta.dirname, "../cli/commands/ssrf/run.ts");
    const cmd =
      `node --experimental-strip-types "${script}" ` +
      `"http://127.0.0.1:${address.port}/fetch" url ` +
      `--execute --max=2 --timeout=3000 --trace="${file}"`;
    try {
      execSync(cmd, { encoding: "utf8", stdio: "pipe" });
    } catch (e) {
      // confirmed=0 exits non-zero — trace file is what we assert on
      const err = e as { stdout?: string; stderr?: string };
      if (!fs.existsSync(file)) {
        console.error("CLI error:", String(e));
        console.error("CLI cmd:", cmd);
        console.error("CLI stdout:", err.stdout);
        console.error("CLI stderr:", err.stderr);
      }
    }
    const probes = readLines(file).filter((l) => l.event === "probe");
    assert.ok(probes.length >= 1, `expected probe records, got ${probes.length}`);
    assert.ok(typeof probes[0].latencyMs === "number");
    const summary = readLines(file).find((l) => l.event === "run.summary");
    assert.ok(summary, "CLI must write run.summary");
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
