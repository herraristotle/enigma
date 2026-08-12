/**
 * Generates decimal, octal, hex, IPv6, and DNS alias representations of an IP.
 *
 * @see RFC3986 §3.2.1 for IP address parsing
 */
export function generateIpObfuscations(ip: string): Array<{ technique: string, host: string }> {
  const partStrings = ip.split('.');
  if (partStrings.length !== 4) {
    return [];
  }

  const parts: number[] = [];
  for (const s of partStrings) {
    if (!/^\d+$/.test(s)) {
      return [];
    }
    const val = parseInt(s, 10);
    if (val < 0 || val > 255) {
      return [];
    }
    parts.push(val);
  }

  const [a, b, c, d] = parts;
  const decimal = ((a << 24) >>> 0) + (b << 16) + (c << 8) + d;

  const result: Array<{ technique: string, host: string }> = [];

  // 1. decimal
  result.push({ technique: "decimal", host: decimal.toString() });

  // 1b. decimal `0` — single-digit decimal that resolves to 0.0.0.0 on
  //     getaddrinfo/gethostbyname (often alias-routed to 127.0.0.1 by the
  //     host stack) and bypasses `faraday`-style allowlist checks that block
  //     127.0.0.0/8 and 10.0.0.0/8 but pass `0`. Orange Tsai L1274: GitHub
  //     Enterprise Webhook blacklist "simply bypassed with a zero".
  result.push({ technique: "decimal", host: "0" });

  // 2. octal dotted (0177.0.0.1)
  const octalDotted = parts.map((p, idx) => {
    if (idx === 0) {
      return "0" + p.toString(8);
    }
    return p.toString(8);
  }).join('.');
  result.push({ technique: "octal dotted", host: octalDotted });

  // 3. hex integer (0x7f000001)
  result.push({ technique: "hex integer", host: "0x" + decimal.toString(16).toLowerCase() });

  // 4. hex dotted (0x7f.0x0.0x0.0x1)
  const hexDotted = parts.map(p => "0x" + p.toString(16)).join('.');
  result.push({ technique: "hex dotted", host: hexDotted });

  // 5. IPv6 mapped ([::ffff:127.0.0.1])
  result.push({ technique: "IPv6 mapped", host: `[::ffff:${ip}]` });

  // 6. IPv6 full ([0000:0000:0000:0000:0000:ffff:7f00:0001])
  const ab = ((a << 8) + b).toString(16).padStart(4, '0');
  const cd = ((c << 8) + d).toString(16).padStart(4, '0');
  result.push({
    technique: "IPv6 full",
    host: `[0000:0000:0000:0000:0000:ffff:${ab}:${cd}]`
  });

  // 7. zero-padded (0127.000.000.001)
  const zeroPadded = parts.map(p => {
    const s = p.toString();
    return s.padStart(Math.max(3, s.length + 1), '0');
  }).join('.');
  result.push({ technique: "zero-padded", host: zeroPadded });

  // 8. url-encoded (%31%32%37%2E%30%2E%30%2E%31)
  const urlEncoded = [...ip].map(char => "%" + char.charCodeAt(0).toString(16).toUpperCase()).join('');
  result.push({ technique: "url-encoded", host: urlEncoded });

  // 9. mixed-encoding (0177.0x00.0.1)
  const mixed = [
    "0" + a.toString(8),
    "0x" + b.toString(16).padStart(2, '0'),
    c.toString(),
    d.toString()
  ].join('.');
  result.push({ technique: "mixed-encoding", host: mixed });

  // 10. shortened (127.1)
  let shortened = ip;
  if (b === 0 && c === 0) {
    shortened = `${a}.${d}`;
  } else if (c === 0) {
    shortened = `${a}.${b}.${d}`;
  }
  result.push({ technique: "shortened", host: shortened });

  // 11. integer overflow / 32-bit wrap-around
  // Some parsers accept values > 2^32 and reduce mod 2^32 before treating as IPv4.
  // Competitor IP-obfuscation table: "Integer overflow | 32-bit wrap-around".
  result.push({
    technique: "integer overflow",
    host: (decimal + 0x100000000).toString()
  });
  result.push({
    technique: "integer overflow",
    host: (decimal + 0x200000000).toString()
  });

  // 12. IPv6 compressed hex form ([::ffff:7f00:1]) — distinct from dotted mapped form
  result.push({
    technique: "IPv6 compressed",
    host: `[::ffff:${ab}:${cd}]`
  });

  // 13. localhost DNS aliases — the SSRF blog lists "20+ localhost DNS names that
  //     resolve to 127.0.0.1". These are factual research artifacts (the DNS is
  //     registered to resolve that way) so they live in source as a default
  //     catalog, NOT in operator config. Operators extend the list at runtime
  //     via the `ENIGMA_EXTRA_LOCALHOST_DNS` env var (comma-separated) without
  //     rebuilding — see `appendExtraDnsAliases` below.
  //
  //     Real TOCTOU rebinding patterns (which require attacker-controlled
  //     alternating-TTL DNS) live in `dns-rebinding.ts`, not here. This list is
  //     for static aliases that always resolve to 127.0.0.1.
  //
  // @see https://labs.trace37.com/blog/enigma-ssrf-engine/ "IP Obfuscation"
  const localhostDnsAliases = new Set<string>([
    "localtest.me",
    "localhost",
    "ip6-localhost",
    "ip6-loopback",
    "loopback",
    "lvh.me",
    "vcap.me",
    `${ip}.nip.io`,
    `${ip}.sslip.io`,
    `${ip}.xip.io`,
    `${ip}.1u.ms`,
    "127.0.0.1.nip.io",
    "127-0-0-1.nip.io",
    "spoofed.burpcollaborator.net",
    "customer1.app.localhost.mycompany.localhost",
  ]);
  appendExtraDnsAliases(localhostDnsAliases);
  for (const alias of localhostDnsAliases) {
    result.push({ technique: "localhost DNS aliases", host: alias });
  }

  return result;
}

/**
 * Operator-supplied additional DNS aliases, read from the
 * `ENIGMA_EXTRA_LOCALHOST_DNS` env var (comma-separated).  Lets analysts add
 * private/lab DNS names without editing source or rebuilding.  Values are
 * de-duplicated against the default catalog; empty entries are ignored.
 */
export function appendExtraDnsAliases(target: Set<string>): void {
  const raw = process.env.ENIGMA_EXTRA_LOCALHOST_DNS ?? "";
  if (!raw.trim()) return;
  for (let entry of raw.split(",")) {
    entry = entry.trim();
    if (entry) target.add(entry);
  }
}
