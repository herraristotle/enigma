import { randomBytes } from "node:crypto";

/**
 * Server-side prototype-pollution confirmation engine.
 *
 * Scanner-side only: sends harmless unique marker keys through the three
 * merge mechanisms (query / form-body / JSON body), then re-fetches WITHOUT
 * the marker param and checks whether the marker persisted in the response.
 * Two independent markers gate CONFIRMED (DEF CON 34 deterministic
 * validation); one → LIKELY; none → null.
 *
 * Hard safety rule: only marker keys are ever emitted. No NODE_OPTIONS,
 * no --require, no shell gadgets — those stay catalog-only in structures.ts.
 */

export interface PpProbeRequest {
  url: string;
  method: "GET" | "POST";
  headers?: Record<string, string>;
  body?: string;
}

export interface PpProbeResponse {
  status: number;
  body: string;
  headers?: Record<string, string>;
}

/** Injectable HTTP transport (tests pass a fake; callers pass fetch-backed). */
export interface PpProbeAdapter {
  send(req: PpProbeRequest): Promise<PpProbeResponse>;
}

export type PpMechanism = "query" | "form-body" | "json-body";

export interface PpConfirmation {
  mechanism: PpMechanism;
  parameter: string;
  marker: string;
  evidence: string;
  baselineHash: string;
  pollutedHash: string;
  confidence: "CONFIRMED" | "LIKELY";
}

export interface PpConfirmOptions {
  adapter: PpProbeAdapter;
  /** Marker rounds — 2 gives CONFIRMED/LIKELY split; default 2. */
  rounds?: number;
}

function marker(): string {
  return `ppm_${randomBytes(4).toString("hex")}`;
}

function hash(text: string): string {
  // Cheap stable hash — node:crypto only, no deps.
  let h = 5381;
  for (let i = 0; i < text.length; i++) h = ((h << 5) + h + text.charCodeAt(i)) >>> 0;
  return h.toString(16);
}

/** Build the pollution request for one mechanism. Marker key only — nothing else. */
function buildPollutionRequest(
  targetUrl: string,
  parameter: string,
  mechanism: PpMechanism,
  mark: string,
): PpProbeRequest {
  switch (mechanism) {
    case "query": {
      const url = new URL(targetUrl);
      url.searchParams.set(`__proto__[${parameter}]`, mark);
      return { url: url.toString(), method: "GET" };
    }
    case "form-body":
      return {
        url: targetUrl,
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: `__proto__[${parameter}]=${encodeURIComponent(mark)}`,
      };
    case "json-body":
      // Built as a raw string: an object-literal `__proto__` key would set
      // the prototype instead of serializing as an own key.
      return {
        url: targetUrl,
        method: "POST",
        headers: { "content-type": "application/json" },
        body: `{"__proto__":${JSON.stringify({ [parameter]: mark })}}`,
      };
  }
}

/** Markerless follow-up — if the server echoes `mark`, pollution persisted. */
function buildFollowup(targetUrl: string): PpProbeRequest {
  return { url: targetUrl, method: "GET" };
}

function markerSeen(res: PpProbeResponse, mark: string): boolean {
  if (res.body.includes(mark)) return true;
  const headers = res.headers ?? {};
  return Object.values(headers).some((v) => String(v).includes(mark));
}

/**
 * Confirm pollution for one mechanism. Returns null when neither marker
 * round lands (ignored), or the adapter throws (never crashes the scan).
 */
export async function confirmPrototypePollution(
  targetUrl: string,
  parameter: string,
  adapter: PpProbeAdapter,
  mechanism: PpMechanism,
  rounds = 2,
): Promise<PpConfirmation | null> {
  try {
    // Baseline: markerless fetch for evidence hashes.
    const baseline = await adapter.send(buildFollowup(targetUrl));
    const baselineHash = hash(baseline.body);

    const evidence: string[] = [];
    let landedMarker = "";
    let pollutedHash = baselineHash;
    let landed = 0;

    for (let i = 0; i < rounds; i++) {
      const mark = marker();
      const pollution = buildPollutionRequest(targetUrl, parameter, mechanism, mark);
      await adapter.send(pollution);
      const followup = await adapter.send(buildFollowup(targetUrl));
      if (markerSeen(followup, mark)) {
        landed++;
        landedMarker = mark;
        evidence.push(`round ${i + 1}: marker ${mark} persisted after markerless GET`);
        pollutedHash = hash(followup.body);
      }
    }

    if (landed === 0) return null;

    return {
      mechanism,
      parameter,
      marker: landedMarker,
      evidence: evidence.join("; "),
      baselineHash,
      pollutedHash,
      confidence: landed >= rounds ? "CONFIRMED" : "LIKELY",
    };
  } catch {
    return null;
  }
}

/** Adapter backed by global fetch — default for real scans. */
export function fetchAdapter(): PpProbeAdapter {
  return {
    async send(req) {
      const res = await fetch(req.url, {
        method: req.method,
        headers: req.headers,
        body: req.body,
      });
      const headers: Record<string, string> = {};
      res.headers.forEach((v, k) => { headers[k] = v; });
      return { status: res.status, body: await res.text(), headers };
    },
  };
}
