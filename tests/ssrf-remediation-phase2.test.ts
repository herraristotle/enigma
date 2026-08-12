import { test } from "node:test";
import assert from "node:assert";
import { generateSniInjectionPayloads } from "../core/engines/ssrf/bypasses/parser-confusion.ts";
import { generateHeaderInjectionPayloads } from "../core/engines/ssrf/bypasses/header-injection.ts";
import { generateRedisAttackPayloads } from "../core/engines/ssrf/bypasses/protocols.ts";
import { generateRebindingPayloads } from "../core/engines/ssrf/bypasses/dns-rebinding.ts";

test("Phase 2 SSRF Remediation", async (t) => {
  await t.test("Task 2A: SNI Injection", async (t) => {
    await t.test("generates payloads with correct structure", () => {
      const payloads = generateSniInjectionPayloads("127.0.0.1", 443);
      assert.ok(Array.isArray(payloads), "Should return an array");
      assert.ok(payloads.length >= 3, `Should have at least 3 payloads, got ${payloads.length}`);
      for (const p of payloads) {
        assert.ok(typeof p.technique === "string" && p.technique.length > 0, "Technique must be non-empty string");
        assert.ok(typeof p.payload === "string" && p.payload.length > 0, "Payload must be non-empty string");
        assert.ok(typeof p.description === "string" && p.description.length > 0, "Description must be non-empty string");
      }
    });

    await t.test("generates Redis SNI injection payload", () => {
      const payloads = generateSniInjectionPayloads("127.0.0.1", 443);
      const redis = payloads.find(p => p.technique.includes("Redis") || p.description.toLowerCase().includes("redis"));
      assert.ok(redis, "Should include Redis payload");
      assert.ok(
        redis!.payload.includes("127.0.0.1"),
        "Redis payload should target 127.0.0.1"
      );
      assert.ok(
        redis!.payload.includes("SLAVEOF") || redis!.payload.includes("INFO"),
        "Redis payload should contain Redis command"
      );
      assert.ok(
        redis!.payload.includes(":443") || redis!.payload.includes("443"),
        "Redis payload should reference port 443"
      );
    });

    await t.test("generates Memcached SNI injection payload", () => {
      const payloads = generateSniInjectionPayloads("127.0.0.1", 443);
      const memcached = payloads.find(p =>
        p.technique.includes("Memcached") || p.description.toLowerCase().includes("memcached")
      );
      assert.ok(memcached, "Should include Memcached payload");
      assert.ok(
        memcached!.payload.includes("SET") || memcached!.payload.includes("get"),
        "Memcached payload should contain Memcached command"
      );
    });

    await t.test("generates SMTP SNI injection payload", () => {
      const payloads = generateSniInjectionPayloads("127.0.0.1", 443);
      const smtp = payloads.find(p =>
        p.technique.includes("SMTP") || p.description.toLowerCase().includes("smtp")
      );
      assert.ok(smtp, "Should include SMTP payload");
      assert.ok(
        smtp!.payload.includes("HELO") || smtp!.payload.includes("MAIL"),
        "SMTP payload should contain SMTP command"
      );
    });

    await t.test("all payloads contain CRLF in hostname position", () => {
      const payloads = generateSniInjectionPayloads("127.0.0.1", 443);
      for (const p of payloads) {
        // Payloads use literal \r\n (escaped) as the CRLF sequence in the URL string
        assert.ok(
          p.payload.includes("\\r\\n") || p.payload.includes("\r\n") || p.payload.includes("%0d%0a") || p.payload.includes("%0D%0A"),
          `Payload should contain CRLF: ${p.payload}`
        );
      }
    });

    await t.test("works with custom port", () => {
      const payloads = generateSniInjectionPayloads("10.0.0.1", 8443);
      assert.ok(payloads.length >= 3, "Should generate payloads for custom port");
      for (const p of payloads) {
        assert.ok(p.payload.includes("8443"), `Payload should reference port 8443: ${p.payload}`);
      }
    });
  });

  await t.test("Task 2B: Header Injection", async (t) => {
    await t.test("generates payloads with correct structure", () => {
      const payloads = generateHeaderInjectionPayloads("169.254.169.254", "canary.example.com");
      assert.ok(Array.isArray(payloads), "Should return an array");
      assert.ok(payloads.length >= 10, `Should have at least 10 payloads, got ${payloads.length}`);
      for (const p of payloads) {
        assert.ok(typeof p.header === "string" && p.header.length > 0, "Header must be non-empty string");
        assert.ok(typeof p.value === "string" && p.value.length > 0, "Value must be non-empty string");
        assert.ok(typeof p.technique === "string" && p.technique.length > 0, "Technique must be non-empty string");
      }
    });

    await t.test("includes X-Forwarded-For with internal IPs", () => {
      const payloads = generateHeaderInjectionPayloads("169.254.169.254");
      const xff = payloads.filter(p => p.header === "X-Forwarded-For");
      assert.ok(xff.length >= 1, "Should have X-Forwarded-For payloads");
      const allValues = xff.map(p => p.value).join(" ");
      assert.ok(allValues.includes("127.0.0.1"), "Should include 127.0.0.1");
      assert.ok(allValues.includes("169.254.169.254"), "Should include 169.254.169.254");
    });

    await t.test("includes X-Forwarded-Host with metadata endpoints", () => {
      const payloads = generateHeaderInjectionPayloads("169.254.169.254");
      const xfh = payloads.filter(p => p.header === "X-Forwarded-Host");
      assert.ok(xfh.length >= 1, "Should have X-Forwarded-Host payloads");
      const allValues = xfh.map(p => p.value).join(" ");
      assert.ok(allValues.includes("169.254.169.254"), "Should include cloud metadata IP");
    });

    await t.test("includes X-Callback-URL with canary domain", () => {
      const payloads = generateHeaderInjectionPayloads("169.254.169.254", "canary.example.com");
      const callback = payloads.filter(p => p.header === "X-Callback-URL");
      assert.ok(callback.length >= 1, "Should have X-Callback-URL payloads");
      const allValues = callback.map(p => p.value).join(" ");
      assert.ok(allValues.includes("canary.example.com"), "Should include canary domain");
    });

    await t.test("includes Referer header", () => {
      const payloads = generateHeaderInjectionPayloads("169.254.169.254");
      const referer = payloads.filter(p => p.header === "Referer");
      assert.ok(referer.length >= 1, "Should have Referer payloads");
    });

    await t.test("includes X-Original-URL and X-Rewrite-URL", () => {
      const payloads = generateHeaderInjectionPayloads("169.254.169.254");
      const original = payloads.filter(p => p.header === "X-Original-URL");
      const rewrite = payloads.filter(p => p.header === "X-Rewrite-URL");
      assert.ok(original.length >= 1, "Should have X-Original-URL payloads");
      assert.ok(rewrite.length >= 1, "Should have X-Rewrite-URL payloads");
      const allPaths = [...original, ...rewrite].map(p => p.value).join(" ");
      assert.ok(allPaths.includes("/admin"), "Should include /admin path");
    });

    await t.test("works without canary domain", () => {
      const payloads = generateHeaderInjectionPayloads("169.254.169.254");
      assert.ok(payloads.length >= 10, "Should work without canary domain");
    });
  });

  await t.test("Task 2C: Gopher Redis Attack Chain", async (t) => {
    const TEST_HOST = process.env.ENIGMA_ATTACKER_HOST ?? "attacker.test";
    const TEST_PORT = Number(process.env.ENIGMA_ATTACKER_PORT ?? "6379");
    const TEST_WRITE: import("../core/engines/ssrf/bypasses/protocols.ts").RedisWritePayload = {
      dir: "/tmp/test/",
      filename: "test.txt",
      content: "TEST_CONTENT",
    };

    const baseOpts = { attackerHost: TEST_HOST, attackerPort: TEST_PORT };
    const writeOpts = { ...baseOpts, writes: [TEST_WRITE] };

    await t.test("generates payloads with correct structure", () => {
      const payloads = generateRedisAttackPayloads(writeOpts);
      assert.ok(Array.isArray(payloads), "Should return an array");
      assert.ok(payloads.length >= 6, `Should have at least 6 payloads, got ${payloads.length}`);
      for (const p of payloads) {
        assert.ok(typeof p.technique === "string" && p.technique.length > 0, "Technique must be non-empty string");
        assert.ok(typeof p.payload === "string" && p.payload.length > 0, "Payload must be non-empty string");
        assert.strictEqual(typeof p.dangerous, "boolean", "dangerous must be boolean");
      }
    });

    await t.test("safe INFO query is first and not dangerous", () => {
      const payloads = generateRedisAttackPayloads(baseOpts);
      const info = payloads.find(p => p.technique === "INFO");
      assert.ok(info, "Should have INFO payload");
      assert.strictEqual(info!.dangerous, false, "INFO should not be dangerous");
      assert.ok(info!.payload.includes("INFO"), "Should contain INFO command");
    });

    await t.test("SLAVEOF is marked dangerous", () => {
      const payloads = generateRedisAttackPayloads(baseOpts);
      const slaveof = payloads.find(p => p.technique.includes("SLAVEOF") || p.technique.includes("Slaveof"));
      assert.ok(slaveof, "Should have SLAVEOF payload");
      assert.strictEqual(slaveof!.dangerous, true, "SLAVEOF should be dangerous");
    });

    await t.test("FLUSHALL is marked dangerous", () => {
      const payloads = generateRedisAttackPayloads(baseOpts);
      const flushall = payloads.find(p => p.technique.includes("FLUSHALL") || p.technique.includes("Flushall"));
      assert.ok(flushall, "Should have FLUSHALL payload");
      assert.strictEqual(flushall!.dangerous, true, "FLUSHALL should be dangerous");
    });

    await t.test("CONFIG SET payloads generated when writes provided", () => {
      const payloads = generateRedisAttackPayloads(writeOpts);
      const config = payloads.filter(p => p.technique.includes("CONFIG"));
      assert.ok(config.length >= 2, `Should have at least 2 CONFIG payloads, got ${config.length}`);
      for (const c of config) {
        assert.strictEqual(c.dangerous, true, `${c.technique} should be dangerous`);
      }
    });

    await t.test("all payloads use gopher protocol to target redis host", () => {
      const payloads = generateRedisAttackPayloads(baseOpts);
      for (const p of payloads) {
        assert.ok(
          p.payload.startsWith("gopher://"),
          `Payload should use gopher protocol: ${p.payload}`
        );
      }
    });

    await t.test("write payloads contain caller-supplied content", () => {
      const payloads = generateRedisAttackPayloads(writeOpts);
      const setPayload = payloads.find(p => p.technique.startsWith("SET "));
      assert.ok(setPayload, "Should have SET payload when writes provided");
      assert.strictEqual(setPayload!.dangerous, true, "SET should be dangerous");
      assert.ok(setPayload!.payload.includes(encodeURIComponent("TEST_CONTENT")), "Should contain caller-supplied content (URL-encoded)");
    });

    await t.test("no write payloads when writes omitted", () => {
      const payloads = generateRedisAttackPayloads(baseOpts);
      const setPayload = payloads.find(p => p.technique.startsWith("SET "));
      assert.strictEqual(setPayload, undefined, "Should not have SET payload without writes");
      const config = payloads.find(p => p.technique.includes("CONFIG"));
      assert.strictEqual(config, undefined, "Should not have CONFIG payload without writes");
    });

    await t.test("includes SAVE payload", () => {
      const payloads = generateRedisAttackPayloads(baseOpts);
      const save = payloads.find(p =>
        p.technique.includes("SAVE") || p.technique.includes("Save")
      );
      assert.ok(save, "Should have SAVE payload");
      assert.strictEqual(save!.dangerous, true, "SAVE should be dangerous");
    });
  });

  await t.test("Task 2D: DNS Rebinding TOCTOU", async (t) => {
    await t.test("generates payloads with correct structure", () => {
      const targets = generateRebindingPayloads("1.2.3.4", "127.0.0.1");
      assert.ok(Array.isArray(targets), "Should return an array");
      assert.ok(targets.length >= 2, `Should have at least 2 targets (rebind.attacker.com + ipv6.sslip.io), got ${targets.length}`);
      for (const t of targets) {
        assert.ok(typeof t.domain === "string" && t.domain.length > 0, "Domain must be non-empty string");
        assert.ok(typeof t.firstIp === "string" && t.firstIp.length > 0, "firstIp must be non-empty string");
        assert.ok(typeof t.secondIp === "string" && t.secondIp.length > 0, "secondIp must be non-empty string");
        assert.ok(typeof t.technique === "string" && t.technique.length > 0, "Technique must be non-empty string");
      }
    });

    await t.test("first IP matches allowedIp, second matches internalIp", () => {
      const targets = generateRebindingPayloads("1.2.3.4", "127.0.0.1");
      for (const t of targets) {
        assert.strictEqual(t.firstIp, "1.2.3.4", `firstIp should be 1.2.3.4 for ${t.domain}`);
        assert.strictEqual(t.secondIp, "127.0.0.1", `secondIp should be 127.0.0.1 for ${t.domain}`);
      }
    });

    await t.test("includes rebind.attacker.com TOCTOU domain", () => {
      const targets = generateRebindingPayloads("1.2.3.4", "127.0.0.1");
      const rebind = targets.find(t => t.domain === "rebind.attacker.com");
      assert.ok(rebind, "Should include rebind.attacker.com TOCTOU domain");
      assert.ok(rebind!.technique.toLowerCase().includes("toctou"), "Technique should mention TOCTOU");
    });

    await t.test("includes ipv6.sslip.io variant", () => {
      const targets = generateRebindingPayloads("1.2.3.4", "127.0.0.1");
      const ipv6 = targets.find(t => t.domain.includes("ipv6.") && t.domain.includes("sslip.io"));
      assert.ok(ipv6, "Should include ipv6.sslip.io variant");
    });

    await t.test("does NOT include static-DNS aliases (nip.io, sslip.io plain, 1u.ms, localtest.me)", () => {
      const targets = generateRebindingPayloads("1.2.3.4", "127.0.0.1");
      const domains = targets.map(t => t.domain);
      assert.ok(!domains.some(d => d.includes("nip.io") && !d.includes("ipv6.")), "Should not include plain nip.io alias");
      assert.ok(!domains.some(d => d === "127.0.0.1.sslip.io"), "Should not include plain sslip.io alias");
      assert.ok(!domains.some(d => d.includes("1u.ms")), "Should not include 1u.ms alias");
      assert.ok(!domains.includes("localtest.me"), "Should not include localtest.me alias");
    });

    await t.test("works with different IP pairs", () => {
      const targets = generateRebindingPayloads("10.0.0.1", "169.254.169.254");
      assert.ok(targets.length >= 2, "Should generate targets for different IPs");
      for (const t of targets) {
        assert.strictEqual(t.firstIp, "10.0.0.1");
        assert.strictEqual(t.secondIp, "169.254.169.254");
      }
    });
  });
});
