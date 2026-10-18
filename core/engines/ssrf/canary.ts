import { randomUUID } from "node:crypto";

export interface CanaryContext {
  target: string;
  parameter: string;
  payload: string;
  technique: string;
  timestamp?: number;
}

export interface CanaryRecord extends CanaryContext {
  token: string;
  callbacks: {
    directHttp: string;
    dnsOnly: string;
    pathIdentified: string;
    redirectChain: string;
  };
}

export class CanaryRegistry {
  private records = new Map<string, CanaryRecord>();

  register(context: CanaryContext, domain: string): string {
    const token = randomUUID();
    const callbacks = {
      directHttp: `http://${token}.${domain}`,
      dnsOnly: `${token}.${domain}`,
      pathIdentified: `http://${domain}/${token}`,
      redirectChain: `http://${domain}/redirect?url=http://${token}.${domain}`
    };
    const record: CanaryRecord = {
      ...context,
      timestamp: context.timestamp ?? Date.now(),
      token,
      callbacks
    };
    this.records.set(token, record);
    return token;
  }

  get(token: string): CanaryRecord | undefined {
    return this.records.get(token);
  }
}

export interface Measurement {
  target: string;
  durationMs: number;
}

export class TimingAnalyzer {
  static analyze(
    measurements: Measurement[],
    options?: { baselineMs?: number }
  ) {
    const baselineMs = options?.baselineMs ?? 4000;
    const count = measurements.length;
    const mean = count > 0 ? measurements.reduce((sum, m) => sum + m.durationMs, 0) / count : 0;
    const variance = count > 0 ? measurements.reduce((sum, m) => sum + Math.pow(m.durationMs - mean, 2), 0) / count : 0;
    const stdDev = Math.sqrt(variance);
    const threshold = mean + 2 * stdDev;

    const outliers = measurements.filter((m, idx) => {
      const others = measurements.filter((_, i) => i !== idx);
      const c = others.length;
      if (c === 0) return false;
      const mMean = others.reduce((sum, item) => sum + item.durationMs, 0) / c;
      const mVar = others.reduce((sum, item) => sum + Math.pow(item.durationMs - mMean, 2), 0) / c;
      const mStdDev = Math.sqrt(mVar);
      return m.durationMs > mMean + 2 * mStdDev;
    });
    // Timeout detection for internal IPs
    const timeouts = measurements.filter(m => {
      const clean = m.target.trim().toLowerCase();
      if (clean === "localhost") return m.durationMs >= baselineMs;

      // IPv4 check
      const match = clean.match(/^(?:(\d+)\.(\d+)\.(\d+)\.(\d+))$/);
      if (match) {
        const o1 = parseInt(match[1], 10);
        const o2 = parseInt(match[2], 10);
        const isInternal = o1 === 127 || o1 === 10 || (o1 === 192 && o2 === 168) || (o1 === 172 && o2 >= 16 && o2 <= 31) || (o1 === 169 && o2 === 254);
        if (isInternal) return m.durationMs >= baselineMs;
      }

      // IPv6 loopback
      if (clean === "::1" || clean === "0:0:0:0:0:0:0:1") return m.durationMs >= baselineMs;

      // IPv6-mapped IPv4 (e.g. ::ffff:127.0.0.1, ::ffff:7f00:1)
      if (clean.startsWith("::ffff:")) {
        const mapped = clean.slice(7);
        // Dotted notation: ::ffff:127.0.0.1
        const mappedMatch = mapped.match(/^(?:(\d+)\.(\d+)\.(\d+)\.(\d+))$/);
        if (mappedMatch) {
          const o1 = parseInt(mappedMatch[1], 10);
          const o2 = parseInt(mappedMatch[2], 10);
          const isInternal = o1 === 127 || o1 === 10 || (o1 === 192 && o2 === 168) || (o1 === 172 && o2 >= 16 && o2 <= 31) || (o1 === 169 && o2 === 254);
          if (isInternal) return m.durationMs >= baselineMs;
        } else {
          // Hex notation: ::ffff:7f00:1 → parse as two 16-bit hex groups
          const hexParts = mapped.split(":");
          if (hexParts.length === 2) {
            const hi = parseInt(hexParts[0], 16);
            const lo = parseInt(hexParts[1], 16);
            if (!isNaN(hi) && !isNaN(lo)) {
              const o1 = (hi >> 8) & 0xff;
              const o2 = hi & 0xff;
              const isInternal = o1 === 127 || o1 === 10 || (o1 === 192 && o2 === 168) || (o1 === 172 && o2 >= 16 && o2 <= 31) || (o1 === 169 && o2 === 254);
              if (isInternal) return m.durationMs >= baselineMs;
            }
          }
        }
      }

      return false;
    });

    return { mean, stdDev, outliers, timeouts };
  }
}

export class SizeAnalyzer {
  /**
   * Pairwise size comparison against a single baseline response.
   * Prefer {@link analyzeGroups} when internal vs external cohorts are available.
   */
  static analyze(size: number, baselineSize: number): { confidence: "high" | "medium" | "low"; difference: number } {
    if (baselineSize === 0) return { confidence: "low", difference: 0 };
    const diff = Math.abs(size - baselineSize) / baselineSize;
    let confidence: "high" | "medium" | "low" = "low";
    if (diff >= 0.30) {
      confidence = "high";
    } else if (diff >= 0.15) {
      confidence = "medium";
    }
    return { confidence, difference: diff };
  }

  /**
   * Competitor Phase-4 size analysis: compare internal-target responses to
   * external-target responses as groups.
   *
   * - 30%+ mean difference → high confidence
   * - 15%+ mean difference → medium confidence
   * - individual payload ≥50% from its group mean → anomaly flagged
   */
  static analyzeGroups(
    internalSizes: number[],
    externalSizes: number[]
  ): {
    confidence: "high" | "medium" | "low";
    difference: number;
    internalMean: number;
    externalMean: number;
    anomalies: Array<{ group: "internal" | "external"; size: number; deviation: number }>;
  } {
    const mean = (xs: number[]) =>
      xs.length === 0 ? 0 : xs.reduce((a, b) => a + b, 0) / xs.length;

    const internalMean = mean(internalSizes);
    const externalMean = mean(externalSizes);
    const denom = Math.max(internalMean, externalMean, 1);
    const difference =
      internalSizes.length === 0 || externalSizes.length === 0
        ? 0
        : Math.abs(internalMean - externalMean) / denom;

    let confidence: "high" | "medium" | "low" = "low";
    if (difference >= 0.30) confidence = "high";
    else if (difference >= 0.15) confidence = "medium";

    const anomalies: Array<{ group: "internal" | "external"; size: number; deviation: number }> = [];
    for (const size of internalSizes) {
      if (internalMean === 0) continue;
      const deviation = Math.abs(size - internalMean) / internalMean;
      if (deviation >= 0.5) anomalies.push({ group: "internal", size, deviation });
    }
    for (const size of externalSizes) {
      if (externalMean === 0) continue;
      const deviation = Math.abs(size - externalMean) / externalMean;
      if (deviation >= 0.5) anomalies.push({ group: "external", size, deviation });
    }

    return { confidence, difference, internalMean, externalMean, anomalies };
  }
}

export interface ContentMatch {
  pattern: string;
  category: "credential" | "service_fingerprint" | "file_content" | "error_leak";
  matched: string;
  confidence: "high" | "medium" | "low";
}

const CREDENTIAL_PATTERNS: Array<{ regex: RegExp; name: string; confidence: "high" | "medium" | "low" }> = [
  { regex: /(?:AccessKeyId|AKIA[0-9A-Z]{16})/i, name: "AWS Access Key ID", confidence: "high" },
  { regex: /(?:SecretAccessKey|aws_secret_access_key)[=:]\s*["']?[A-Za-z0-9/+=]{40}/i, name: "AWS Secret Access Key", confidence: "high" },
  { regex: /(?:aws_session_token)[=:]\s*["']?[A-Za-z0-9\-_]+/i, name: "AWS Session Token", confidence: "high" },
  { regex: /(?:GCE\.default\.project_id|project_id)[=:]\s*["']?[a-z0-9\-]+/i, name: "GCP Project ID", confidence: "medium" },
  { regex: /(?:client_secret)[=:]\s*["'][A-Za-z0-9\-_]{20,}/i, name: "OAuth Client Secret", confidence: "high" },
  { regex: /(?:private_key)[=:]\s*["']-----BEGIN (?:RSA )?PRIVATE KEY-----/i, name: "Private Key (PEM)", confidence: "high" },
  { regex: /(?:password|passwd|pwd)[=:]\s*["']?[^\s"']{4,}/i, name: "Plaintext Password", confidence: "medium" },
  { regex: /(?:Authorization|Bearer)\s+[A-Za-z0-9\-_\.]+/i, name: "Auth Token", confidence: "medium" },
  { regex: /(?:api[_-]?key)[=:]\s*["']?[A-Za-z0-9\-_]{16,}/i, name: "API Key", confidence: "medium" },
  { regex: /(?:mysql|postgres|mongodb|redis):\/\/[^\s"']+:[^\s"']+@[^\s"']+/i, name: "Database Connection String", confidence: "high" }
];

const SERVICE_FINGERPRINTS: Array<{ regex: RegExp; name: string; confidence: "high" | "medium" | "low" }> = [
  { regex: /redis_version[=:]\s*[0-9.]+/i, name: "Redis", confidence: "high" },
  { regex: /cluster_name[=:]\s*\w+/i, name: "Elasticsearch Cluster", confidence: "medium" },
  { regex: /DockerRootDir[=:]\s*\//i, name: "Docker Daemon", confidence: "high" },
  { regex: /container_id[=:]\s*[a-f0-9]{64}/i, name: "Container Runtime", confidence: "high" },
  { regex: /etcd_cluster[=:]\s*\w+/i, name: "etcd Cluster", confidence: "medium" },
  { regex: /consul[-_]member[=:]\s*\w+/i, name: "Consul Agent", confidence: "medium" },
  { regex: /kubernetes[=:]?\s*(?:v[0-9.]+|enabled|true)/i, name: "Kubernetes API", confidence: "medium" },
  { regex: /(?:MySQL|PostgreSQL|MariaDB|MongoDB)/i, name: "Database Server", confidence: "medium" },
  { regex: /(?:Apache|Nginx|IIS|LiteSpeed)/i, name: "Web Server", confidence: "low" },
  { regex: /(?:Solr|Cassandra|RabbitMQ|Kafka)/i, name: "Middleware Service", confidence: "medium" }
];

const FILE_CONTENT_PATTERNS: Array<{ regex: RegExp; name: string; confidence: "high" | "medium" | "low" }> = [
  { regex: /(?:root|daemon|www-data|nginx|apache|mysql|postgres|redis):[x*]:[0-9]+:[0-9]+/i, name: "/etc/passwd", confidence: "high" },
  { regex: /(?:root:[^:*]+|daemon:[^:*]+):[0-9]+:/i, name: "/etc/shadow", confidence: "high" },
  { regex: /(?:nameserver|domain|search)\s+[0-9.]+/i, name: "/etc/resolv.conf", confidence: "high" },
  { regex: /(?:HOSTNAME|GATEWAY|DNS1|IPADDR)=/i, name: "/etc/sysconfig/network", confidence: "medium" },
  { regex: /(?:Defaults\s+env_keep|Defaults\s+secure_path)/i, name: "/etc/sudoers", confidence: "high" },
  { regex: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/i, name: "Private Key File", confidence: "high" },
  { regex: /-----BEGIN CERTIFICATE-----/i, name: "Certificate File", confidence: "medium" },
  { regex: /(?:ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256)\s+[A-Za-z0-9+/=]+/i, name: "SSH Public Key", confidence: "medium" }
];

const ERROR_LEAK_PATTERNS: Array<{ regex: RegExp; name: string; confidence: "high" | "medium" | "low" }> = [
  { regex: /(?:Traceback|stack trace|at .+\(.+:\d+:\d+\))/i, name: "Stack Trace Leak", confidence: "medium" },
  { regex: /(?:SQL syntax|ORA-\d{5}|pg_query\(\)|mysql_fetch)/i, name: "SQL Error Leak", confidence: "high" },
  { regex: /(?:Internal Server Error|500\s+Server Error)/i, name: "Internal Server Error", confidence: "low" },
  { regex: /(?:Connection refused|ECONNREFUSED|ETIMEDOUT)/i, name: "Connection Error", confidence: "medium" },
  { regex: /(?:Permission denied|EACCES|403 Forbidden)/i, name: "Permission Denied", confidence: "medium" }
];

export class ContentMatcher {
  static analyze(body: string): ContentMatch[] {
    const matches: ContentMatch[] = [];

    for (const p of CREDENTIAL_PATTERNS) {
      const m = body.match(p.regex);
      if (m) {
        matches.push({ pattern: p.name, category: "credential", matched: m[0], confidence: p.confidence });
      }
    }

    for (const p of SERVICE_FINGERPRINTS) {
      const m = body.match(p.regex);
      if (m) {
        matches.push({ pattern: p.name, category: "service_fingerprint", matched: m[0], confidence: p.confidence });
      }
    }

    for (const p of FILE_CONTENT_PATTERNS) {
      const m = body.match(p.regex);
      if (m) {
        matches.push({ pattern: p.name, category: "file_content", matched: m[0], confidence: p.confidence });
      }
    }

    for (const p of ERROR_LEAK_PATTERNS) {
      const m = body.match(p.regex);
      if (m) {
        matches.push({ pattern: p.name, category: "error_leak", matched: m[0], confidence: p.confidence });
      }
    }

    return matches;
  }

  static getConfirmationLevel(matches: ContentMatch[]): "confirmed" | "suspected" | "none" {
    const highConfidence = matches.filter(m => m.confidence === "high");
    const mediumConfidence = matches.filter(m => m.confidence === "medium");

    if (highConfidence.length > 0) return "confirmed";
    if (mediumConfidence.length > 1) return "suspected";
    return "none";
  }
}

export interface ScanResult {
  target: string;
  payload: string;
  technique: string;
  category: string;
  status: "confirmed" | "blocked" | "no_signal" | "error";
  timestamp: number;
  durationMs?: number;
  contentMatches?: ContentMatch[];
  confirmationLevel?: "confirmed" | "suspected" | "none";
  cvss?: {
    base: number;
    severity: "critical" | "high" | "medium" | "low";
    vector: string;
  };
}

export interface NotificationChannel {
  send(result: ScanResult): Promise<void>;
}

export class SlackNotification implements NotificationChannel {
  private webhookUrl: string;
  constructor(webhookUrl: string) { this.webhookUrl = webhookUrl; }

  async send(result: ScanResult): Promise<void> {
    const payload = {
      text: `*SSRF ${result.status.toUpperCase()}*`,
      blocks: [
        {
          type: "section",
          fields: [
            { type: "mrkdwn", text: `*Target:*\n${result.target}` },
            { type: "mrkdwn", text: `*Technique:*\n${result.technique}` },
            { type: "mrkdwn", text: `*Status:*\n${result.status}` },
            { type: "mrkdwn", text: `*Category:*\n${result.category}` }
          ]
        }
      ]
    };

    if (result.cvss) {
      payload.blocks.push({
        type: "section",
        fields: [
          { type: "mrkdwn", text: `*CVSS Score:*\n${result.cvss.base}` },
          { type: "mrkdwn", text: `*Severity:*\n${result.cvss.severity}` }
        ]
      });
    }

    if (result.contentMatches && result.contentMatches.length > 0) {
      const matchList = result.contentMatches.map(m => `• ${m.pattern} (${m.category})`).join("\n");
      payload.blocks.push({
        type: "section",
        fields: [{ type: "mrkdwn", text: `*Content Matches:*\n${matchList}` }]
      });
    }

    try {
      await fetch(this.webhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
    } catch {
      // Silent fail for notification
    }
  }
}

export class DesktopNotification implements NotificationChannel {
  async send(result: ScanResult): Promise<void> {
    const deno = (globalThis as typeof globalThis & {
      Deno?: { Command: new (command: string, options: { args: string[] }) => { output(): Promise<unknown> } };
    }).Deno;
    if (deno?.Command) {
      const title = `SSRF ${result.status.toUpperCase()}`;
      const body = `${result.target} - ${result.technique}`;
      try {
        const cmd = new deno.Command("notify-send", { args: [title, body] });
        await cmd.output();
      } catch {
        // Desktop notification not available
      }
    }
  }
}

export class TerminalNotification implements NotificationChannel {
  async send(result: ScanResult): Promise<void> {
    process.stdout.write("\x07"); // BEL character
    const severity = result.cvss ? result.cvss.severity.toUpperCase() : "UNKNOWN";
    console.log(`\n[ALERT] SSRF ${result.status.toUpperCase()} - ${severity}`);
    console.log(`  Target: ${result.target}`);
    console.log(`  Technique: ${result.technique}`);
    console.log(`  Category: ${result.category}`);
    if (result.contentMatches && result.contentMatches.length > 0) {
      console.log(`  Content Matches:`);
      for (const m of result.contentMatches) {
        console.log(`    - ${m.pattern}: ${m.matched.substring(0, 50)}...`);
      }
    }
  }
}

export class AudioNotification implements NotificationChannel {
  async send(result: ScanResult): Promise<void> {
    // Audio alert —BEL ×3 bursts to differentiate from terminal channel's single BEL.
    // Uses stdout BEL on all platforms; on Linux/Mac fires the audible system bell.
    try {
      for (let i = 0; i < 3; i++) {
        process.stdout.write("\x07");
        await new Promise((r) => setTimeout(r, 250));
      }
    } catch {
      // Audio not available — silent fail
    }
  }
}

export class NotificationManager {
  private channels: NotificationChannel[] = [];

  addChannel(channel: NotificationChannel): void {
    this.channels.push(channel);
  }

  async notify(result: ScanResult): Promise<void> {
    await Promise.allSettled(this.channels.map(ch => ch.send(result)));
  }
}
