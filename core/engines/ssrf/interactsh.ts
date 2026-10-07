import { randomUUID, createHash } from "node:crypto";

/**
 * Self-hosted interactsh OOB client (projectdiscovery/interactsh).
 *
 * Same protocol as parallax's client: POST {server}/register with a
 * correlation-id, then poll GET {server}/interactions?id&secret&token.
 * Payloads are `{random}.{correlationId}.{domain}` so the server can
 * correlate inbound callbacks to this session.
 *
 * Default transport is global `fetch` (matches executor usage — enigma
 * carries no HTTP dep); injectable so tests never touch the network.
 * Degrades to a disabled no-op when INTERACTSH_SERVER/DOMAIN are unset
 * or register() fails — scans continue without OOB evidence.
 */
export interface OobConfig {
  server: string;
  domain: string;
  token?: string;
}

export interface OobInteraction {
  protocol: string;
  remoteAddress: string;
  fullId?: string;
  rawRequest?: string;
}

/** Minimal fetch shape — injectable so tests never touch the network. */
export type FetchLike = (
  url: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string },
) => Promise<{ ok: boolean; status: number; text(): Promise<string> }>;

export function oobConfigFromEnv(
  env: Record<string, string | undefined> = process.env,
): OobConfig | null {
  const server = (env.INTERACTSH_SERVER || "").trim();
  const domain = (env.INTERACTSH_DOMAIN || "").trim();
  if (!server || !domain) return null;
  const token = (env.INTERACTSH_TOKEN || "").trim();
  return token ? { server, domain, token } : { server, domain };
}

export class InteractshClient {
  private correlationId = randomUUID();
  private secret = createHash("sha256").update(this.correlationId).digest("base64");
  private registered = false;
  private disabled = false;
  private config: OobConfig;
  private fetchFn: FetchLike;

  constructor(config: OobConfig, fetchFn?: FetchLike) {
    this.config = config;
    this.fetchFn = fetchFn ?? (async (url, init) => {
      const res = await fetch(url, init as RequestInit);
      return { ok: res.ok, status: res.status, text: () => res.text() };
    });
  }

  /** POST /register; failure self-disables the client (returns false, no throw). */
  async register(): Promise<boolean> {
    if (this.disabled) return false;
    if (this.registered) return true;
    try {
      const headers: Record<string, string> = { "content-type": "application/json" };
      if (this.config.token) headers["x-interactsh-token"] = this.config.token;
      const res = await this.fetchFn(`${this.config.server}/register`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          "correlation-id": this.correlationId,
          "secret-key": this.secret,
        }),
      });
      if (!res.ok) {
        this.disabled = true;
        return false;
      }
      this.registered = true;
      return true;
    } catch {
      this.disabled = true;
      return false;
    }
  }

  /** `{random13}.{correlationId}.{domain}` — unique label, stable correlation. */
  nextPayload(): string {
    const label = randomUUID().replace(/-/g, "").slice(0, 13);
    return `${label}.${this.correlationId}.${this.config.domain}`;
  }

  isReady(): boolean {
    return this.registered && !this.disabled;
  }

  /** GET /interactions — empty array when disabled/unregistered/on error. */
  async pollOnce(): Promise<OobInteraction[]> {
    if (this.disabled || !this.registered) return [];
    try {
      const params = new URLSearchParams({ id: this.correlationId, secret: this.secret });
      if (this.config.token) params.set("token", this.config.token);
      const headers: Record<string, string> = {};
      if (this.config.token) headers["x-interactsh-token"] = this.config.token;
      const res = await this.fetchFn(
        `${this.config.server}/interactions?${params.toString()}`,
        { method: "GET", headers },
      );
      if (!res.ok) return [];
      const body = await res.text();
      if (!body) return [];
      const parsed = JSON.parse(body) as { interactions?: unknown[] };
      const raw = Array.isArray(parsed.interactions) ? parsed.interactions : [];
      return raw.map((entry): OobInteraction => {
        if (entry && typeof entry === "object") {
          const o = entry as Record<string, unknown>;
          return {
            protocol: String(o.protocol ?? "http"),
            remoteAddress: String(o["remote-address"] ?? o.remoteAddress ?? "unknown"),
            fullId: typeof o["full-id"] === "string" ? o["full-id"] : undefined,
            rawRequest: typeof o["raw-request"] === "string" ? o["raw-request"] : undefined,
          };
        }
        return { protocol: "http", remoteAddress: "unknown", rawRequest: String(entry) };
      });
    } catch {
      return [];
    }
  }

  /** Bounded poll loop; first interaction or null on timeout. */
  async waitForInteraction(
    timeoutMs = 10_000,
    intervalMs = 1_000,
  ): Promise<OobInteraction | null> {
    if (!this.registered || this.disabled) return null;
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const hits = await this.pollOnce();
      if (hits.length > 0) return hits[0];
      const wait = Math.min(intervalMs, Math.max(0, deadline - Date.now()));
      if (wait > 0) await new Promise((r) => setTimeout(r, wait));
    }
    return null;
  }
}
