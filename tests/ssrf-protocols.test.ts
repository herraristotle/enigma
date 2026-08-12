import { test } from "node:test";
import assert from "node:assert";
import { generateProtocolSmugglingPayloads } from "../core/engines/ssrf/bypasses/protocols.ts";

test("Protocol Smuggling Payload Generation", async (t) => {
  const targetHost = "127.0.0.1";
  const payloads = generateProtocolSmugglingPayloads(targetHost);

  await t.test("Verify all 4 protocols are included", () => {
    const protocols = payloads.map(p => p.protocol.toLowerCase());
    const required = ["file", "gopher", "ftp", "data"];
    for (const proto of required) {
      assert.ok(protocols.includes(proto), `Missing protocol: ${proto}`);
    }
  });

  await t.test("Verify file protocol payloads target sensitive paths", () => {
    const filePayloads = payloads.filter(p => p.protocol.toLowerCase() === "file").map(p => p.payload);
    assert.ok(filePayloads.length > 0, "Should generate file payloads");

    // Must check for /etc/passwd, .env, K8s account tokens
    const hasEtcPasswd = filePayloads.some(p => p.includes("/etc/passwd"));
    const hasEnv = filePayloads.some(p => p.includes(".env"));
    const hasK8sToken = filePayloads.some(p => p.includes("kubernetes.io/serviceaccount/token") || p.includes("serviceaccount/token"));

    assert.ok(hasEtcPasswd, "Missing file payload for /etc/passwd");
    assert.ok(hasEnv, "Missing file payload for .env");
    assert.ok(hasK8sToken, "Missing file payload for K8s account token");
  });

  await t.test("Verify gopher protocol Redis payload safety", () => {
    const gopherPayloads = payloads.filter(p => p.protocol.toLowerCase() === "gopher").map(p => p.payload);
    assert.ok(gopherPayloads.length > 0, "Should generate gopher payloads");

    // Look for Redis payload
    const redisPayloads = gopherPayloads.filter(p => p.includes("6379") || p.toLowerCase().includes("redis"));
    assert.ok(redisPayloads.length > 0, "Should generate gopher payload for Redis");

    for (const payload of redisPayloads) {
      // Must contain INFO
      assert.ok(payload.toUpperCase().includes("INFO"), `Redis payload must contain 'INFO': ${payload}`);
      
      // Must not contain mutating/dangerous commands
      const dangerous = ["FLUSHALL", "FLUSHDB", "SLAVEOF", "CONFIG", "KEYS", "SET", "DEL"];
      for (const cmd of dangerous) {
        // Ensure the exact word is not there (or not capitalized/mutated form)
        const upper = payload.toUpperCase();
        assert.ok(!upper.includes(cmd), `Redis payload contains dangerous command '${cmd}': ${payload}`);
      }
    }
  });
});
