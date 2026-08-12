import { test } from "node:test";
import assert from "node:assert";
import {
  expandSubnetHosts,
  generateNetworkScanPayloads,
  generateSsrfPayloadPlan,
  detectStack
} from "../core/engines/ssrf/decision-trees.ts";
import { ContentMatcher } from "../core/engines/ssrf/canary.ts";
import { SizeAnalyzer } from "../core/engines/ssrf/canary.ts";
import { inferBlockers, type ComponentObservation } from "../core/engines/mutation/blockers.ts";
import { generateIpObfuscations } from "../core/engines/ssrf/bypasses/ip-obfuscation.ts";
import { generateCloudMetadataTargets } from "../core/engines/ssrf/payloads/cloud-metadata.ts";
import { generateInternalServiceTargets } from "../core/engines/ssrf/payloads/internal-services.ts";
import { MutationComposer } from "../core/engines/mutation/composer.ts";

test("Security Audit Fixes - Comprehensive Test Suite", async (t) => {

  // ── SSRF expandSubnetHosts ──────────────────────────────────────────

  await t.test("expandSubnetHosts: should handle IP overflow at 255 boundary", () => {
    const hosts = expandSubnetHosts("10.0.0.254/30", 4);
    assert.ok(hosts.includes("10.0.0.255"), "Should include .255");
    assert.ok(hosts.includes("10.0.1.0"), "Should wrap to .1.0");
  });

  await t.test("expandSubnetHosts: should handle /32 single host", () => {
    const hosts = expandSubnetHosts("192.168.1.1/32");
    assert.deepStrictEqual(hosts, ["192.168.1.1"]);
  });

  await t.test("expandSubnetHosts: should handle /24 subnet", () => {
    const hosts = expandSubnetHosts("192.168.1.0/24", 5);
    assert.strictEqual(hosts.length, 5);
    assert.strictEqual(hosts[0], "192.168.1.1");
  });

  // ── SSRF ContentMatcher.getConfirmationLevel ─────────────────────────

  await t.test("ContentMatcher.getConfirmationLevel: should require multiple medium matches", () => {
    const singleMedium = [
      { pattern: "html", confidence: "medium" as const, category: "error_leak" as const, matched: "html" }
    ];
    assert.strictEqual(ContentMatcher.getConfirmationLevel(singleMedium), "none");

    const multiMedium = [
      { pattern: "html", confidence: "medium" as const, category: "error_leak" as const, matched: "html" },
      { pattern: "body", confidence: "medium" as const, category: "error_leak" as const, matched: "body" }
    ];
    assert.strictEqual(ContentMatcher.getConfirmationLevel(multiMedium), "suspected");
  });

  await t.test("ContentMatcher.getConfirmationLevel: should confirm with high confidence", () => {
    const highConfidence = [
      { pattern: "AWS", confidence: "high" as const, category: "credential" as const, matched: "AWS" }
    ];
    assert.strictEqual(ContentMatcher.getConfirmationLevel(highConfidence), "confirmed");
  });

  // ── XSS inferBlockers ────────────────────────────────────────────────

  await t.test("inferBlockers: should infer blockers from observations", () => {
    const observations: ComponentObservation[] = [
      { family: "event", value: "onclick", blocked: true, successful: false },
      { family: "event", value: "onerror", blocked: true, successful: false },
      { family: "event", value: "onload", blocked: false, successful: true }
    ];

    const blockers = inferBlockers(observations);
    assert.strictEqual(blockers.length, 1);
    assert.strictEqual(blockers[0].family, "event");
    assert.ok(blockers[0].blockedValues.includes("onclick"));
    assert.ok(blockers[0].blockedValues.includes("onerror"));
  });

  // ── SSRF Network Scanning ───────────────────────────────────────────

  await t.test("generateNetworkScanPayloads: should generate scan payloads", () => {
    const payloads = generateNetworkScanPayloads("192.168.1.1", [80, 443, 8080]);
    assert.strictEqual(payloads.length, 3);
    assert.strictEqual(payloads[0].port, 80);
    assert.strictEqual(payloads[0].service, "http");
  });

  await t.test("generateNetworkScanPayloads: should identify services", () => {
    const payloads = generateNetworkScanPayloads("10.0.0.1", [22, 3306, 6379]);
    const ssh = payloads.find((p) => p.port === 22);
    const mysql = payloads.find((p) => p.port === 3306);
    const redis = payloads.find((p) => p.port === 6379);
    assert.strictEqual(ssh?.service, "ssh");
    assert.strictEqual(mysql?.service, "mysql");
    assert.strictEqual(redis?.service, "redis");
  });

  // ── Existing audit fix verifications ─────────────────────────────────

  await t.test("Audit fix: IP obfuscation is wired into payload plan", () => {
    const plan = generateSsrfPayloadPlan({
      targetUrl: "https://target.com/api/fetch",
      allowedHost: "allowed.com"
    });

    const hasDecimal = plan.some((p) => p.payload.includes("2130706433") || p.payload.includes("2852039166"));
    const hasHex = plan.some((p) => /0x[0-9a-f]+/i.test(p.payload));
    const hasIpv6Mapped = plan.some((p) => p.payload.includes("[::ffff:"));
    const hasOverflow = plan.some((p) => p.technique === "integer overflow");

    assert.ok(hasDecimal, "Plan must include decimal IP obfuscation");
    assert.ok(hasHex, "Plan must include hex IP obfuscation");
    assert.ok(hasIpv6Mapped, "Plan must include IPv6-mapped obfuscation");
    assert.ok(hasOverflow, "Plan must include integer-overflow host forms");
  });

  await t.test("Audit fix: integer overflow technique exists for 127.0.0.1", () => {
    const obf = generateIpObfuscations("127.0.0.1");
    const overflows = obf.filter((o) => o.technique === "integer overflow");
    assert.ok(overflows.length >= 1);
    assert.ok(overflows.some((o) => o.host === "6425673729"));
  });

  await t.test("Audit fix: Oracle metadata uses 169.254.169.254", () => {
    const oracle = generateCloudMetadataTargets().find((t) => t.provider === "Oracle");
    assert.ok(oracle);
    assert.strictEqual(oracle!.endpoint, "169.254.169.254");
  });

  await t.test("Audit fix: Kubernetes API on 6443 + admin path coverage", () => {
    const services = generateInternalServiceTargets();
    const k8s = services.find((s) => s.service === "Kubernetes");
    assert.ok(k8s);
    assert.strictEqual(k8s!.port, 6443);
    assert.ok(k8s!.paths.some((p) => p.startsWith("/api")));

    const admin = services.find((s) => s.service === "localhost admin paths");
    assert.ok(admin);
    for (const path of ["/phpmyadmin", "/server-status", "/actuator", "/actuator/env", "/debug/vars", "/metrics", "/health"]) {
      assert.ok(admin!.paths.includes(path), `Missing admin path ${path}`);
    }
    assert.ok(admin!.paths.length >= 22, `Expected >=22 admin paths, got ${admin!.paths.length}`);
  });

  await t.test("Audit fix: stack priorities match competitor diagram", () => {
    assert.strictEqual(detectStack({ "X-Powered-By": ".NET" }), ".NET");

    const java = generateSsrfPayloadPlan({
      targetUrl: "https://t.com/f",
      allowedHost: "allowed.com",
      headers: { "X-Powered-By": "Java" }
    });
    const javaTechs = [
      ...new Set(java.filter((p) => p.category === "parser confusion").map((p) => p.technique || ""))
    ];
    assert.strictEqual(javaTechs[0], "IPv6 brackets");

    const go = generateSsrfPayloadPlan({
      targetUrl: "https://t.com/f",
      allowedHost: "allowed.com",
      headers: { Server: "Go" }
    });
    const goTechs = [
      ...new Set(go.filter((p) => p.category === "parser confusion").map((p) => p.technique || ""))
    ];
    assert.strictEqual(goTechs[0], "fragment confusion");
    assert.strictEqual(goTechs[1], "Unicode normalization");
  });

  await t.test("Audit fix: header injection and network scan plan options", () => {
    const plan = generateSsrfPayloadPlan({
      targetUrl: "https://t.com/webhook",
      allowedHost: "allowed.com",
      canaryUrl: "https://canary.example/c/tok",
      testHeaders: true,
      subnet: "10.0.0.0/24"
    });

    assert.ok(plan.some((p) => p.category === "header injection"));
    assert.ok(plan.some((p) => p.technique === "X-Forwarded-For"));
    assert.ok(plan.some((p) => p.category === "network scan"));
    assert.ok(plan.some((p) => p.payload.includes("10.0.0.")));

    const hosts = expandSubnetHosts("10.0.0.0/24", 4);
    assert.deepStrictEqual(hosts, ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]);
  });

  await t.test("Audit fix: SizeAnalyzer group comparison (internal vs external)", () => {
    const result = SizeAnalyzer.analyzeGroups(
      [1000, 1100, 1050],
      [200, 210, 190]
    );
    assert.strictEqual(result.confidence, "high");
    assert.ok(result.difference >= 0.3);

    const anomaly = SizeAnalyzer.analyzeGroups([100, 100, 300], [100, 100, 100]);
    assert.ok(anomaly.anomalies.some((a) => a.group === "internal" && a.size === 300));
  });

  await t.test("Audit fix: XSS space cascade maps symbolic names to real whitespace", () => {
    const composer = new MutationComposer("html_content");
    composer.absorbBinarySearch([
      { family: "space", value: " ", blocked: true, successful: false },
      { family: "space", value: "\t", blocked: true, successful: false },
      { family: "tag", value: "img", blocked: false, successful: true }
    ]);
    const candidates = composer.nextCandidates();
    const spacePayloads = candidates.filter((c) => c.family === "space" || c.rationale.includes("space"));
    const joined = spacePayloads.map((c) => c.payload).join("\n");
    assert.ok(
      joined.includes("\t") || joined.includes("\f") || joined.includes("/**/") || joined.includes("/"),
      `Expected real whitespace substitutes, got: ${joined.slice(0, 200)}`
    );
    assert.ok(!spacePayloads.some((c) => c.payload.includes(" tab ") || /onerror=tab/.test(c.payload)));
  });

  await t.test("Audit fix: XSS tag alternative does not double-close tag name", () => {
    const composer = new MutationComposer("html_content");
    composer.absorbBinarySearch([
      { family: "tag", value: "img", blocked: true, successful: false },
      { family: "tag", value: "body", blocked: true, successful: false },
      { family: "event", value: "onerror", blocked: false, successful: true }
    ]);
    const candidates = composer.nextCandidates();
    const tagAlts = candidates.filter((c) => c.rationale.includes("tag cascade"));
    for (const c of tagAlts) {
      assert.ok(!c.payload.match(/<[a-z0-9-]+>>/i), `Double-close bug still present: ${c.payload}`);
    }
  });
});
