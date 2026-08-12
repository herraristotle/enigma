import { test } from "node:test";
import assert from "node:assert";
import {
  CanaryRegistry,
  TimingAnalyzer,
  SizeAnalyzer,
  ContentMatcher
} from "../core/engines/ssrf/canary.ts";

test("SSRF Canary and Blind Analysis Suite", async (t) => {
  await t.test("CanaryRegistry: token registration stores full context", () => {
    const registry = new CanaryRegistry();
    const context = {
      target: "http://169.254.169.254/latest/meta-data/",
      parameter: "url",
      payload: "http://canary.example.com",
      technique: "direct_ssrf",
      timestamp: Date.now()
    };

    const token = registry.register(context, "canary.example.com");
    assert.ok(token);

    const retrieved = registry.get(token);
    assert.ok(retrieved);
    assert.strictEqual(retrieved.target, context.target);
    assert.strictEqual(retrieved.parameter, context.parameter);
    assert.strictEqual(retrieved.payload, context.payload);
    assert.strictEqual(retrieved.technique, context.technique);
    assert.strictEqual(retrieved.timestamp, context.timestamp);
  });

  await t.test("CanaryRegistry: generates 4 callback variants", () => {
    const registry = new CanaryRegistry();
    const context = {
      target: "http://169.254.169.254/latest/meta-data/",
      parameter: "url",
      payload: "PLACEHOLDER",
      technique: "direct_ssrf"
    };

    const token = registry.register(context, "canary.example.com");
    const record = registry.get(token);
    assert.ok(record);

    assert.ok(record.callbacks);
    assert.ok(record.callbacks.directHttp);
    assert.ok(record.callbacks.dnsOnly);
    assert.ok(record.callbacks.pathIdentified);
    assert.ok(record.callbacks.redirectChain);

    // Direct HTTP includes protocol, token, and domain
    assert.match(record.callbacks.directHttp, /^https?:\/\/[a-zA-Z0-9-]+\.canary\.example\.com/);
    
    // DNS-only is a domain/subdomain without protocol/path
    assert.match(record.callbacks.dnsOnly, /^[a-zA-Z0-9-]+\.canary\.example\.com$/);
    
    // Path-identified has the token in the URL path
    assert.match(record.callbacks.pathIdentified, /^https?:\/\/canary\.example\.com\/[a-zA-Z0-9-]+/);
    
    // Redirect chain includes a redirection mechanism pointing to directHttp or path-identified
    assert.ok(record.callbacks.redirectChain.includes("redirect"));
  });

  await t.test("TimingAnalyzer: flags outliers above mean + 2 std deviations", () => {
    const measurements = [
      { target: "example.com", durationMs: 100 },
      { target: "example.com", durationMs: 105 },
      { target: "example.com", durationMs: 98 },
      { target: "example.com", durationMs: 102 },
      { target: "example.com", durationMs: 500 } // Outlier
    ];

    const result = TimingAnalyzer.analyze(measurements);
    assert.strictEqual(result.outliers.length, 1);
    assert.strictEqual(result.outliers[0].durationMs, 500);
  });

  await t.test("TimingAnalyzer: flags internal IP timeout pattern", () => {
    const measurements = [
      { target: "127.0.0.1", durationMs: 5000 }, // Timeout internal
      { target: "10.0.0.1", durationMs: 5000 },  // Timeout internal
      { target: "example.com", durationMs: 100 },
      { target: "192.168.1.1", durationMs: 100 }  // Non-timeout internal
    ];

    // Baseline threshold for timeout
    const result = TimingAnalyzer.analyze(measurements, { baselineMs: 4000 });
    
    assert.strictEqual(result.timeouts.length, 2);
    const targets = result.timeouts.map(t => t.target);
    assert.ok(targets.includes("127.0.0.1"));
    assert.ok(targets.includes("10.0.0.1"));
    assert.ok(!targets.includes("192.168.1.1"));
  });

  await t.test("SizeAnalyzer: computes size confidence correctly", () => {
    // 30%+ size differences as high confidence
    const highDiff1 = SizeAnalyzer.analyze(1350, 1000);
    assert.strictEqual(highDiff1.confidence, "high");
    
    const highDiff2 = SizeAnalyzer.analyze(650, 1000);
    assert.strictEqual(highDiff2.confidence, "high");

    // 15%+ size differences as medium confidence
    const medDiff1 = SizeAnalyzer.analyze(1180, 1000);
    assert.strictEqual(medDiff1.confidence, "medium");

    const medDiff2 = SizeAnalyzer.analyze(820, 1000);
    assert.strictEqual(medDiff2.confidence, "medium");

    // Below 15% difference is low confidence
    const lowDiff = SizeAnalyzer.analyze(1050, 1000);
    assert.strictEqual(lowDiff.confidence, "low");
  });

  await t.test("getConfirmationLevel requires multiple medium matches", () => {
    // Single medium confidence → "none" (not "suspected")
    const singleMedium = [{ pattern: "html", confidence: "medium" as const, category: "error_leak", matched: "html" }];
    assert.equal(ContentMatcher.getConfirmationLevel(singleMedium), "none");
    
    // Multiple medium confidence → "suspected"
    const multiMedium = [
      { pattern: "html", confidence: "medium" as const, category: "error_leak", matched: "html" },
      { pattern: "body", confidence: "medium" as const, category: "error_leak", matched: "body" }
    ];
    assert.equal(ContentMatcher.getConfirmationLevel(multiMedium), "suspected");
    
    // High confidence always wins
    const highAndMedium = [
      { pattern: "AWS", confidence: "high" as const, category: "credential", matched: "AWS" },
      { pattern: "html", confidence: "medium" as const, category: "error_leak", matched: "html" }
    ];
    assert.equal(ContentMatcher.getConfirmationLevel(highAndMedium), "confirmed");
  });
});
