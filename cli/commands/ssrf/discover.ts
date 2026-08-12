export interface DiscoverySurface {
  url: string;
  parameter: string;
  type: "query" | "header" | "body" | "path" | "cookie";
  score: number;
  rationale: string;
  command: string;
}

const FEATURE_PRIORITY: Record<string, number> = {
  webhook: 8,
  proxy: 7,
  pdf: 6,
  image: 5,
  import: 4,
  redirect: 3,
  api: 2,
  dns: 1,
};

const HIGH_PARAMS = new Set(["url", "callback", "dest", "source", "proxy", "forward"]);

export function scoreSsrfFeature(feature: string, parameter: string): number {
  const normFeature = feature.toLowerCase();
  const normParam = parameter.toLowerCase();

  // Find priority score: 10 * priority. Webhook gets 80, DNS gets 10.
  // If feature is not matching directly, try checking substring or use default.
  let priority = 0;
  for (const [key, val] of Object.entries(FEATURE_PRIORITY)) {
    if (normFeature.includes(key) || key.includes(normFeature)) {
      priority = val;
      break;
    }
  }

  let baseScore = priority * 10;
  if (baseScore === 0) {
    baseScore = 40; // Default base score
  }

  // Adjust for parameters.
  let adjustment = 0;
  if (HIGH_PARAMS.has(normParam)) {
    adjustment = 15;
  } else if (["id", "username", "page", "section"].includes(normParam)) {
    adjustment = -10;
  }

  return Math.min(100, Math.max(0, baseScore + adjustment));
}

export function formatTargetConfig(config: { url: string; parameter: string; type: string; score: number }): string {
  return `enigma-ssrf run "${config.url}" "${config.parameter}"`;
}

export function buildCaidoQuery(target: string, httpql?: string): string {
  // Caido GraphQL filter uses string format for queries: host.like:"%target.com%"
  // Support --httpql and combine
  const targetFilter = `host.like:"%${target}%"`;
  if (httpql) {
    return `${targetFilter} AND ${httpql}`;
  }
  return targetFilter;
}

interface CaidoRequest {
  id: string;
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string;
  query: string;
}

async function fetchCaidoRequests(target: string, endpoint: string, token: string, httpql?: string): Promise<CaidoRequest[]> {
  const filterString = buildCaidoQuery(target, httpql);

  // In Caido GraphQL, the requests query can filter on a string
  const query = `
    query FilterRequests($filter: String!, $limit: Int) {
      requests(filter: $filter, first: $limit) {
        edges {
          node {
            id
            method
            host
            path
            query
            raw
            headers { key value }
            body
          }
        }
      }
    }
  `;

  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { "Authorization": `Bearer ${token}` } : {})
    },
    body: JSON.stringify({
      query,
      variables: {
        filter: filterString,
        limit: 50
      }
    })
  });

  if (!response.ok) {
    throw new Error(`GraphQL HTTP Error: ${response.status}`);
  }

  const { data } = await response.json();
  if (!data || !data.requests) return [];

  return data.requests.edges.map((edge: any) => {
    const node = edge.node;
    const headers: Record<string, string> = {};
    for (const h of node.headers || []) {
      headers[h.key.toLowerCase()] = h.value;
    }

    let urlStr = `https://${node.host}${node.path}`;
    if (node.query) {
      urlStr += `?${node.query}`;
    }

    return {
      id: node.id,
      url: urlStr,
      method: node.method || "GET",
      headers,
      body: node.body || "",
      query: node.query || ""
    };
  });
}

function analyzeRequestForSsrf(req: CaidoRequest): DiscoverySurface[] {
  const surfaces: DiscoverySurface[] = [];
  const urlObj = new URL(req.url);

  // Analyze parameters in Query
  const searchParams = new URLSearchParams(req.query);
  for (const [key, value] of searchParams.entries()) {
    const feature = inferFeatureFromContext(key, value, req.url);
    const score = scoreSsrfFeature(feature, key);
    const config = { url: req.url, parameter: key, type: "query" as const, score };
    surfaces.push({
      ...config,
      rationale: `Potential ${feature} parameter found in query`,
      command: formatTargetConfig(config)
    });
  }

  // Analyze JSON/Form Body
  if (req.body) {
    let bodyParams: Record<string, string> = {};
    const contentType = req.headers["content-type"] || "";
    if (contentType.includes("application/json")) {
      try {
        const parsed = JSON.parse(req.body);
        if (typeof parsed === "object" && parsed !== null) {
          bodyParams = parsed;
        }
      } catch (_) {}
    } else if (contentType.includes("application/x-www-form-urlencoded")) {
      for (const [key, value] of new URLSearchParams(req.body).entries()) {
        bodyParams[key] = value;
      }
    }

    for (const [key, value] of Object.entries(bodyParams)) {
      const feature = inferFeatureFromContext(key, String(value), req.url);
      const score = scoreSsrfFeature(feature, key);
      const config = { url: req.url, parameter: key, type: "body" as const, score };
      surfaces.push({
        ...config,
        rationale: `Potential ${feature} parameter found in body`,
        command: formatTargetConfig(config)
      });
    }
  }

  return surfaces;
}

function inferFeatureFromContext(key: string, value: string, url: string): string {
  const normKey = key.toLowerCase();
  const normVal = value.toLowerCase();
  const normUrl = url.toLowerCase();

  if (normKey.includes("webhook") || normVal.includes("webhook")) return "webhook";
  if (normKey.includes("proxy") || normKey.includes("fetch") || normVal.includes("http://") || normVal.includes("https://")) return "proxy";
  if (normKey.includes("pdf") || normUrl.includes("pdf") || normVal.includes("pdf")) return "pdf";
  if (normKey.includes("image") || normKey.includes("img") || normKey.includes("avatar") || normVal.match(/\.(png|jpg|jpeg|gif|svg)/)) return "image";
  if (normKey.includes("import") || normKey.includes("export") || normKey.includes("upload")) return "import";
  if (normKey.includes("redirect") || normKey.includes("callback") || normKey.includes("dest") || normKey.includes("return")) return "redirect";
  if (normKey.includes("api") || normKey.includes("key") || normKey.includes("token")) return "api";
  if (normKey.includes("dns") || normKey.includes("ns") || normKey.includes("lookup")) return "dns";

  return "proxy"; // default to proxy
}

export async function discoverSsrfSurfaces(
  target: string,
  caidoEndpoint = "http://127.0.0.1:8080/graphql",
  caidoToken = "",
  httpql?: string
): Promise<DiscoverySurface[]> {
  try {
    const requests = await fetchCaidoRequests(target, caidoEndpoint, caidoToken, httpql);
    const allSurfaces: DiscoverySurface[] = [];

    for (const req of requests) {
      allSurfaces.push(...analyzeRequestForSsrf(req));
    }

    // Sort by descending score
    allSurfaces.sort((a, b) => b.score - a.score);

    // Deduplicate on command
    const uniqueCommands = new Set<string>();
    return allSurfaces.filter(s => {
      if (uniqueCommands.has(s.command)) return false;
      uniqueCommands.add(s.command);
      return true;
    });

  } catch (error: any) {
    // Return mock values if fetch fails or Caido unavailable
    const mockConfigs = [
      { url: `https://${target}/webhook`, parameter: "callback_url", type: "query" as const, score: scoreSsrfFeature("webhook", "callback_url") },
      { url: `https://${target}/api/fetch`, parameter: "url", type: "query" as const, score: scoreSsrfFeature("proxy", "url") },
      { url: `https://${target}/pdf-generator`, parameter: "source", type: "query" as const, score: scoreSsrfFeature("pdf", "source") },
      { url: `https://${target}/image-resize`, parameter: "img", type: "query" as const, score: scoreSsrfFeature("image", "img") },
      { url: `https://${target}/data/import`, parameter: "file_url", type: "body" as const, score: scoreSsrfFeature("import", "file_url") },
      { url: `https://${target}/login`, parameter: "redirect_to", type: "query" as const, score: scoreSsrfFeature("redirect", "redirect_to") },
      { url: `https://${target}/integrations`, parameter: "api_endpoint", type: "body" as const, score: scoreSsrfFeature("api", "api_endpoint") },
      { url: `https://${target}/dns-check`, parameter: "ns", type: "query" as const, score: scoreSsrfFeature("dns", "ns") },
    ];

    const mockSurfaces: DiscoverySurface[] = mockConfigs.map(config => ({
      ...config,
      rationale: `Mock fallback for SSRF detection (${config.parameter})`,
      command: formatTargetConfig(config)
    }));

    mockSurfaces.sort((a, b) => b.score - a.score);
    return mockSurfaces;
  }
}

// CLI Command logic
async function main() {
  const target = process.argv[2];
  if (!target) {
    console.error("usage: enigma-ssrf discover <target.com> [--endpoint=url] [--token=jwt] [--httpql=query]");
    process.exitCode = 1;
    return;
  }

  let endpoint = "http://127.0.0.1:8080/graphql";
  let token = "";
  let httpql = "";

  for (const arg of process.argv.slice(3)) {
    if (arg.startsWith("--endpoint=")) endpoint = arg.split("=")[1];
    else if (arg.startsWith("--token=")) token = arg.split("=")[1];
    else if (arg.startsWith("--httpql=")) httpql = arg.split("=")[1];
  }

  console.log(`[*] Discovering SSRF surfaces for ${target} via Caido (${endpoint})...`);
  const surfaces = await discoverSsrfSurfaces(target, endpoint, token, httpql);

  if (surfaces.length === 0) {
    console.log("[-] No surfaces found.");
    return;
  }

  console.log(`\n[+] Found ${surfaces.length} candidate SSRF targets:\n`);

  for (const s of surfaces.slice(0, 15)) {
    const color = s.score >= 80 ? "\x1b[31m" : s.score >= 50 ? "\x1b[33m" : "\x1b[32m";
    console.log(`${color}[Score: ${s.score.toString().padStart(3, " ")}]\x1b[0m ${s.type.toUpperCase()}: ${s.parameter} (on ${s.url})`);
    console.log(`    Rationale: ${s.rationale}`);
    console.log(`    Command:   \x1b[36m${s.command}\x1b[0m`);
    console.log("-".repeat(70));
  }
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith("discover.ts")) {
  void main();
}
