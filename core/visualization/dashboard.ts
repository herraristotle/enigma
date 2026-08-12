/**
 * Real-time web dashboard for engine scan visualization (operator-side telemetry).
 *
 * Extension beyond competitor spec — not part of the core decision-tree engine.
 * Serves a lightweight HTTP dashboard that displays scan progress,
 * payload results, and timing/size analysis in real time via SSE.
 *
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { DecisionTreeLogger, type DecisionLogEntry } from "./logger.ts";

export interface DashboardOptions {
  port?: number;
  host?: string;
}

export class EngineDashboard {
  private clients: Set<ServerResponse> = new Set();
  private entries: DecisionLogEntry[] = [];
  private server: ReturnType<typeof createServer> | null = null;

  constructor(private readonly logger: DecisionTreeLogger, private readonly options: DashboardOptions = {}) {}

  start(): Promise<void> {
    const port = this.options.port ?? 3847;
    const host = this.options.host ?? "127.0.0.1";

    return new Promise((resolve) => {
      this.server = createServer((req, res) => this._handleRequest(req, res));
      this.server.listen(port, host, () => {
        console.log(`[dashboard] http://${host}:${port}`);
        resolve();
      });
    });
  }

  push(entry: DecisionLogEntry): void {
    this.entries.push(entry);
    const data = `data: ${JSON.stringify(entry)}\n\n`;
    for (const client of this.clients) {
      client.write(data);
    }
  }

  async stop(): Promise<void> {
    for (const client of this.clients) {
      client.end();
    }
    this.clients.clear();
    if (this.server) {
      await new Promise<void>((resolve) => this.server!.close(() => resolve()));
      this.server = null;
    }
  }

  private _handleRequest(req: IncomingMessage, res: ServerResponse): void {
    if (req.url === "/events") {
      res.writeHead(200, {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        Connection: "keep-alive",
        "Access-Control-Allow-Origin": "*"
      });
      // Send existing entries as initial state
      for (const entry of this.entries) {
        res.write(`data: ${JSON.stringify(entry)}\n\n`);
      }
      this.clients.add(res);
      req.on("close", () => this.clients.delete(res));
      return;
    }

    // Serve HTML dashboard
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(DASHBOARD_HTML);
  }
}

const DASHBOARD_HTML = `<!DOCTYPE html>
<html><head>
<title>Enigma Engine Dashboard</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0d1117; color: #e6edf3; font-family: monospace; padding: 1rem; }
  h1 { font-size: 1.2rem; margin-bottom: 1rem; color: #58a6ff; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 6px 10px; text-align: left; border-bottom: 1px solid #30363d; font-size: 0.85rem; }
  th { color: #8b949e; }
  .critical { color: #f85149; } .high { color: #d29922; }
  .medium { color: #58a6ff; } .low { color: #8b949e; }
  .phase { color: #a5d6ff; } .technique { color: #d2a8ff; }
  #count { color: #8b949e; font-size: 0.9rem; margin-bottom: 0.5rem; }
</style>
</head><body>
<h1>Enigma &mdash; Live Dashboard</h1>
<div id="count">Payloads: 0</div>
<table><thead><tr><th>Phase</th><th>Technique</th><th>Target</th><th>Result</th><th>Time (ms)</th></tr></thead>
<tbody id="body"></tbody></table>
<script>
const es = new EventSource("/events");
let count = 0;
es.onmessage = (e) => {
  const d = JSON.parse(e.data);
  count++;
  document.getElementById("count").textContent = "Payloads: " + count;
  const tr = document.createElement("tr");
  tr.innerHTML = \`<td class="phase">\${d.phase||""}</td><td class="technique">\${d.technique||""}</td><td>\${d.target||""}</td><td class="\${(d.severity||"").toLowerCase()}">\${d.result||""}</td><td>\${d.timing||""}</td>\`;
  document.getElementById("body").prepend(tr);
};
</script></body></html>`;
