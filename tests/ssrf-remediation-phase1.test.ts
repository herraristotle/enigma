import { test } from "node:test";
import assert from "node:assert";
import { generateProtocolSmugglingPayloads } from "../core/engines/ssrf/bypasses/protocols.ts";
import { generateInternalServiceTargets } from "../core/engines/ssrf/payloads/internal-services.ts";
import { TimingAnalyzer } from "../core/engines/ssrf/canary.ts";

test("Phase 1 SSRF Remediation", async (t) => {
  await t.test("Task 1A: Memcached payloads include gopher and dict protocols", () => {
    const payloads = generateProtocolSmugglingPayloads("target");
    const memcachedPayloads = payloads.filter(p =>
      p.payload.includes("11211")
    );

    // Must have at least 2 memcached payloads
    assert.ok(memcachedPayloads.length >= 2, `Expected at least 2 memcached payloads, got ${memcachedPayloads.length}`);

    // All memcached payloads must use gopher or dict protocol
    for (const mp of memcachedPayloads) {
      assert.ok(
        mp.payload.startsWith("gopher://") || mp.payload.startsWith("dict://"),
        `Memcached payload should use gopher or dict, got: ${mp.payload}`
      );
    }

    // Must include stats and get variants
    const hasStats = memcachedPayloads.some(p => p.payload.includes("_stats") || p.payload.includes("stats"));
    const hasGet = memcachedPayloads.some(p => p.payload.includes("_get") || p.payload.includes("get"));
    assert.ok(hasStats, "Should include a memcached stats payload");
    assert.ok(hasGet, "Should include a memcached get payload");

    // Should have both gopher AND dict for Memcached
    const gopherMemcached = memcachedPayloads.filter(p => p.payload.startsWith("gopher://"));
    const dictMemcached = memcachedPayloads.filter(p => p.payload.startsWith("dict://"));
    assert.ok(gopherMemcached.length >= 1, "Should have at least 1 gopher Memcached payload");
    assert.ok(dictMemcached.length >= 1, "Should have at least 1 dict Memcached payload");
  });

  await t.test("Task 1B: PostgreSQL and MySQL marked as tcpOnly", () => {
    const services = generateInternalServiceTargets();
    const postgres = services.find(s => s.service === "PostgreSQL");
    const mysql = services.find(s => s.service === "MySQL");

    assert.ok(postgres, "PostgreSQL service should exist");
    assert.ok(mysql, "MySQL service should exist");

    assert.strictEqual(
      (postgres as any).tcpOnly,
      true,
      "PostgreSQL should have tcpOnly: true"
    );
    assert.strictEqual(
      (mysql as any).tcpOnly,
      true,
      "MySQL should have tcpOnly: true"
    );

    // They should NOT have HTTP paths
    assert.deepStrictEqual(postgres.paths, [], "PostgreSQL should have empty paths (TCP-only)");
    assert.deepStrictEqual(mysql.paths, [], "MySQL should have empty paths (TCP-only)");
  });

  await t.test("Task 1C: Timeout detection covers cloud metadata and IPv6-mapped", () => {
    const measurements = [
      // Cloud metadata (169.254.x.x)
      { target: "169.254.169.254", durationMs: 5000 },
      { target: "169.254.1.1", durationMs: 5000 },
      // IPv6-mapped loopback
      { target: "::ffff:127.0.0.1", durationMs: 5000 },
      { target: "::ffff:7f00:1", durationMs: 5000 },
      // IPv6 loopback
      { target: "::1", durationMs: 5000 },
      { target: "0:0:0:0:0:0:0:1", durationMs: 5000 },
      // Regular internal (should still work)
      { target: "127.0.0.1", durationMs: 5000 },
      { target: "10.0.0.1", durationMs: 5000 },
      // External (should NOT timeout)
      { target: "example.com", durationMs: 100 },
    ];

    const result = TimingAnalyzer.analyze(measurements, { baselineMs: 4000 });
    const timeoutTargets = result.timeouts.map(t => t.target);

    // Cloud metadata
    assert.ok(timeoutTargets.includes("169.254.169.254"), "Should detect 169.254.169.254 as internal (cloud metadata)");
    assert.ok(timeoutTargets.includes("169.254.1.1"), "Should detect 169.254.x.x as internal");

    // IPv6-mapped loopback
    assert.ok(timeoutTargets.includes("::ffff:127.0.0.1"), "Should detect ::ffff:127.0.0.1 as internal");
    assert.ok(timeoutTargets.includes("::ffff:7f00:1"), "Should detect ::ffff:7f00:1 as internal");

    // IPv6 loopback
    assert.ok(timeoutTargets.includes("::1"), "Should detect ::1 as internal");
    assert.ok(timeoutTargets.includes("0:0:0:0:0:0:0:1"), "Should detect full IPv6 loopback as internal");

    // Regular internal still works
    assert.ok(timeoutTargets.includes("127.0.0.1"), "Should still detect 127.0.0.1");
    assert.ok(timeoutTargets.includes("10.0.0.1"), "Should still detect 10.0.0.1");

    // External should NOT be in timeouts
    assert.ok(!timeoutTargets.includes("example.com"), "Should NOT timeout external hosts");
  });
});
