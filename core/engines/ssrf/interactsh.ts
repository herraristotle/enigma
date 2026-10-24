import {
  randomUUID,
  randomBytes,
  createHash,
  generateKeyPairSync,
  privateDecrypt,
  createDecipheriv,
  constants as cryptoConstants,
} from "node:crypto";

/**
 * Interactsh OOB client (projectdiscovery/interactsh), implemented against the
 * server's real wire protocol.
 *
 * Protocol (see projectdiscovery/interactsh pkg/server/http_server.go):
 *   1. Generate an RSA-2048 keypair. The PRIVATE key stays local.
 *   2. POST {server}/register with
 *        { "correlation-id", "secret-key", "public-key" }
 *      where public-key is base64(PEM(PKIX public key)) — the server decodes it
 *      with storage.ParseB64RSAPublicKeyFromPEM, so a raw base64 DER blob or a
 *      PEM without the extra base64 layer is rejected.
 *   3. Poll GET {server}/poll?id=&secret=. The response is
 *        { data: string[], extra: string[], aes_key: string, tlddata?: string[] }
 *      Each entry in `data` is base64(IV || AES-256-CTR ciphertext), and
 *      `aes_key` is base64(RSA-OAEP-SHA256(AES key)). `extra` and `tlddata` are
 *      plaintext and are parsed directly.
 *   4. Optionally POST {server}/deregister so the server frees the session.
 *
 * The previous implementation got every layer wrong — no public-key on register
 * (server 400s), polling /interactions (404; the route is /poll), and reading a
 * field named `interactions` (it is `data`) — so OOB never worked against a real
 * server. Getting any one of them wrong fails the same silent way.
 *
 * Auth: a protected server requires `Authorization: <token>` on every request
 * (see authMiddleware/checkToken upstream). Plain header, not x-interactsh-token.
 *
 * Payloads are `{correlationId}{nonce}.{domain}` — the correlation ID comes
 * FIRST, with a random nonce appended (see (*Client).URL upstream), and the
 * server slices `uniqueID[:CorrelationIdLength]` off the front to find the
 * session. Putting the nonce first yields a host the server cannot attribute.
 *
 * Default transport is global `fetch` (injectable so tests never touch the
 * network). Degrades to a disabled no-op rather than throwing — a scan without
 * OOB evidence still runs.
 */
export const PUBLIC_INTERACTSH_SERVERS: ReadonlyArray<{ server: string; domain: string }> = [
  { server: "https://oast.pro", domain: "oast.pro" },
  { server: "https://oast.live", domain: "oast.live" },
  { server: "https://oast.site", domain: "oast.site" },
  { server: "https://oast.online", domain: "oast.online" },
  { server: "https://oast.fun", domain: "oast.fun" },
  { server: "https://oast.me", domain: "oast.me" },
];

/** Back-compat single-value aliases (first public server). */
export const PUBLIC_INTERACTSH_SERVER = PUBLIC_INTERACTSH_SERVERS[0].server;
export const PUBLIC_INTERACTSH_DOMAIN = PUBLIC_INTERACTSH_SERVERS[0].domain;

export interface OobConfig {
  server: string;
  domain: string;
  token?: string;
}

/** One interaction. Field names mirror the server's server.Interaction struct. */
export interface OobInteraction {
  /** "dns" | "http" | "https" | "smtp" | "ftp" | "ldap" | "smb" | "responder" */
  protocol: string;
  /** Source IP of the callback — for origin-IP discovery this is the prize. */
  remoteAddress: string;
  /** Subdomain that received the interaction. */
  uniqueId?: string;
  /** Full path/URL of the interaction. */
  fullId?: string;
  /** DNS question type, when protocol is dns. */
  qType?: string;
  rawRequest?: string;
  rawResponse?: string;
  smtpFrom?: string;
  timestamp?: string;
  asnInfo?: Array<Record<string, string>>;
}

/** Minimal fetch shape — injectable so tests never touch the network. */
export type FetchLike = (
  url: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string },
) => Promise<{
  ok: boolean;
  status: number;
  text(): Promise<string>;
  headers?: { get(name: string): string | null };
}>;

/** INTERACTSH_PUBLIC=0 (or false/off/no) — disable the public-server default. */
export function isPublicOobDisabled(
  env: Record<string, string | undefined> = process.env,
): boolean {
  const flag = (env.INTERACTSH_PUBLIC || "").trim().toLowerCase();
  return flag === "0" || flag === "false" || flag === "off" || flag === "no";
}

/** Back-compat: true unless INTERACTSH_PUBLIC explicitly disables it. */
export function isPublicOobEnabled(
  env: Record<string, string | undefined> = process.env,
): boolean {
  return !isPublicOobDisabled(env);
}

/**
 * All OOB endpoints to try, in order. A configured self-hosted server collapses
 * this to one entry; otherwise it is the public rotation list.
 *
 * INTERACTSH_PUBLIC=0 is an OFF SWITCH, not a "switch to self-hosted" switch.
 * Self-hosting means setting INTERACTSH_SERVER + INTERACTSH_DOMAIN, which wins
 * regardless of the flag.
 */
export function oobCandidates(
  env: Record<string, string | undefined> = process.env,
): OobConfig[] {
  const server = (env.INTERACTSH_SERVER || "").trim();
  const domain = (env.INTERACTSH_DOMAIN || "").trim();
  if (server && domain) {
    const token = (env.INTERACTSH_TOKEN || "").trim();
    return [token ? { server, domain, token } : { server, domain }];
  }
  if (isPublicOobDisabled(env)) return [];
  const pick = (env.INTERACTSH_PUBLIC_SERVER || "").trim();
  if (pick) {
    const match = PUBLIC_INTERACTSH_SERVERS.find(
      (s) => s.domain === pick || s.server === pick || s.domain === `oast.${pick}`,
    );
    if (match) return [{ ...match }];
  }
  return PUBLIC_INTERACTSH_SERVERS.map((s) => ({ ...s }));
}

/** Single-source convenience wrapper. null when OOB is disabled entirely. */
export function oobConfigFromEnv(
  env: Record<string, string | undefined> = process.env,
): OobConfig | null {
  return oobCandidates(env)[0] ?? null;
}

// ---------------------------------------------------------------------------
// Crypto helpers (mirror pkg/client/client.go)
// ---------------------------------------------------------------------------

/** base64(PEM(PKIX)) — the exact shape ParseB64RSAPublicKeyFromPEM expects. */
export function pemToB64Pem(pem: string): string {
  return Buffer.from(pem, "utf8").toString("base64");
}

export function b64ToPem(b64: string): string {
  return Buffer.from(b64, "base64").toString("utf8");
}

/**
 * Decrypt one `data` entry: RSA-OAEP(SHA-256) unwraps the AES-256 key, then
 * AES-256-CTR with the IV prepended to the ciphertext. Mirrors
 * (*Client).decryptMessage upstream.
 */
export function decryptInteraction(
  aesKeyB64: string,
  cipherB64: string,
  privateKeyPem: string,
): string {
  const keyPlain = privateDecrypt(
    {
      key: privateKeyPem,
      padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    Buffer.from(aesKeyB64, "base64"),
  );
  const raw = Buffer.from(cipherB64, "base64");
  if (raw.length < 16) throw new Error("ciphertext too short for an IV");
  const iv = raw.subarray(0, 16);
  const body = raw.subarray(16);
  const decipher = createDecipheriv("aes-256-ctr", keyPlain, iv);
  return Buffer.concat([decipher.update(body), decipher.final()]).toString("utf8");
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/** Matches settings.CorrelationIdLengthDefault upstream. */
export const CORRELATION_ID_LEN = 20;
/** Matches settings.CorrelationIdNonceLengthDefault upstream. */
export const NONCE_LEN = 13;

export class InteractshClient {
  /** Correlation ID: the unique label the server slices out of a callback host. */
  private correlationId: string;
  private secret: string;
  private registered = false;
  private disabled = false;
  private config: OobConfig;
  private fetchFn: FetchLike;
  private publicKeyB64Pem = "";
  private privateKeyPem = "";
  /** Set once per instance so repeat polls do not regenerate a keypair. */
  private keysReady = false;
  /** Last register failure detail, for diagnostics. */
  lastError = "";

  constructor(config: OobConfig, fetchFn?: FetchLike) {
    this.config = config;
    // Must equal the server's CorrelationIdLength (default 20): it stores this
    // verbatim, matches it on poll, and slices uniqueID[:len] on callback.
    this.correlationId = randomUUID().replace(/-/g, "").slice(0, CORRELATION_ID_LEN);
    this.secret = createHash("sha256").update(randomBytes(32)).digest("base64");
    this.fetchFn = fetchFn ?? (async (url, init) => {
      const res = await fetch(url, init as RequestInit);
      return {
        ok: res.ok,
        status: res.status,
        text: () => res.text(),
        headers: { get: (n: string) => res.headers.get(n) },
      };
    });
  }

  private ensureKeys(): boolean {
    if (this.keysReady) return true;
    try {
      const { privateKey, publicKey } = generateKeyPairSync("rsa", {
        modulusLength: 2048,
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      });
      // spki PEM is already PKIX; the server wants one extra base64 layer.
      this.publicKeyB64Pem = pemToB64Pem(publicKey as string);
      this.privateKeyPem = privateKey as string;
      this.keysReady = true;
      return true;
    } catch (err) {
      this.lastError = `keygen failed: ${(err as Error).message}`;
      this.disabled = true;
      return false;
    }
  }

  private authHeaders(): Record<string, string> {
    return this.config.token ? { Authorization: this.config.token } : {};
  }

  /** POST /register. Failure self-disables the client (returns false, no throw). */
  async register(): Promise<boolean> {
    if (this.disabled) return false;
    if (this.registered) return true;
    if (!this.ensureKeys()) return false;
    try {
      const res = await this.fetchFn(`${this.config.server}/register`, {
        method: "POST",
        headers: { "content-type": "application/json", ...this.authHeaders() },
        body: JSON.stringify({
          "correlation-id": this.correlationId,
          "secret-key": this.secret,
          "public-key": this.publicKeyB64Pem,
        }),
      });
      if (!res.ok) {
        // Keep the server's explanation; a bare false makes misconfiguration
        // indistinguishable from a dead network.
        let detail = "";
        try { detail = (await res.text()).trim().slice(0, 200); } catch { /* ignore */ }
        this.lastError = `${res.status}${detail ? `: ${detail}` : ""}`;
        this.disabled = true;
        return false;
      }
      this.registered = true;
      return true;
    } catch (err) {
      this.lastError = (err as Error).message ?? String(err);
      this.disabled = true;
      return false;
    }
  }

  /**
   * `{correlationId}{nonce}.{domain}` — correlation ID first (the server takes
   * uniqueID[:CorrelationIdLength]), then a random nonce so each callback host is
   * unique while still attributing to this session.
   */
  nextPayload(): string {
    const nonce = randomUUID().replace(/-/g, "").slice(0, NONCE_LEN);
    return `${this.correlationId}${nonce}.${this.config.domain}`;
  }

  isReady(): boolean {
    return this.registered && !this.disabled;
  }

  /** Correlation ID, for callers that build their own callback host. */
  getCorrelationId(): string {
    return this.correlationId;
  }

  private toInteraction(o: Record<string, unknown>): OobInteraction {
    const str = (v: unknown): string | undefined =>
      typeof v === "string" ? v : undefined;
    return {
      protocol: String(o.protocol ?? "http"),
      remoteAddress: String(o["remote-address"] ?? o.remoteAddress ?? "unknown"),
      uniqueId: str(o["unique-id"]),
      fullId: str(o["full-id"]),
      qType: str(o["q-type"]),
      rawRequest: str(o["raw-request"]),
      rawResponse: str(o["raw-response"]),
      smtpFrom: str(o["smtp-from"]),
      timestamp: str(o.timestamp),
      asnInfo: Array.isArray(o.asninfo)
        ? (o.asninfo as Array<Record<string, string>>)
        : undefined,
    };
  }

  /**
   * GET /poll?id=&secret=. `data` entries are AES-encrypted and are decrypted
   * here; `extra` and `tlddata` are plaintext. Empty array when
   * disabled/unregistered/on error.
   */
  async pollOnce(): Promise<OobInteraction[]> {
    if (this.disabled || !this.registered) return [];
    try {
      const params = new URLSearchParams({ id: this.correlationId, secret: this.secret });
      const res = await this.fetchFn(
        `${this.config.server}/poll?${params.toString()}`,
        { method: "GET", headers: this.authHeaders() },
      );
      if (!res.ok) return [];
      const body = await res.text();
      if (!body) return [];
      const parsed = JSON.parse(body) as {
        data?: string[];
        extra?: string[];
        tlddata?: string[];
        aes_key?: string;
      };
      const out: OobInteraction[] = [];

      // Plaintext channels first — no crypto, always readable.
      for (const group of [parsed.extra, parsed.tlddata]) {
        for (const raw of group ?? []) {
          try {
            out.push(this.toInteraction(JSON.parse(raw) as Record<string, unknown>));
          } catch { /* skip malformed */ }
        }
      }

      // Encrypted channel.
      if (Array.isArray(parsed.data) && parsed.data.length > 0 && parsed.aes_key) {
        if (!this.privateKeyPem) return out;
        for (const cipher of parsed.data) {
          try {
            const plain = decryptInteraction(parsed.aes_key, cipher, this.privateKeyPem);
            out.push(this.toInteraction(JSON.parse(plain) as Record<string, unknown>));
          } catch { /* skip undecryptable */ }
        }
      }
      return out;
    } catch {
      return [];
    }
  }

  /** POST /deregister so the server frees the session slot. Best effort. */
  async deregister(): Promise<void> {
    if (!this.registered || this.disabled) return;
    try {
      await this.fetchFn(`${this.config.server}/deregister`, {
        method: "POST",
        headers: { "content-type": "application/json", ...this.authHeaders() },
        body: JSON.stringify({
          "correlation-id": this.correlationId,
          "secret-key": this.secret,
        }),
      });
    } catch { /* ignore */ }
    this.registered = false;
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

/**
 * Protocols the interactsh server can report. dns/http/https are on by default;
 * smtp, ftp, ldap, smb and responder require the matching server flags.
 */
export const INTERACTSH_PROTOCOLS = [
  "dns",
  "http",
  "https",
  "smtp",
  "ftp",
  "ldap",
  "smb",
  "responder",
] as const;
export type InteractshProtocol = (typeof INTERACTSH_PROTOCOLS)[number];
