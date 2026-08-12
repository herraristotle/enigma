import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { generateNetworkScanPayloads } from "../core/engines/ssrf/decision-trees.ts";

describe("SSRF Network Scanning Enhancement", () => {
  it("should generate common port scan payloads", () => {
    const payloads = generateNetworkScanPayloads("192.168.1.1", [80, 443, 8080, 8443]);

    assert.equal(payloads.length, 4);
    assert.deepEqual(payloads.map(p => p.port), [80, 443, 8080, 8443]);
    assert.equal(payloads[0].payload, "http://192.168.1.1:80");
    assert.equal(payloads[1].payload, "https://192.168.1.1:443");
  });

  it("should include service identification", () => {
    const payloads = generateNetworkScanPayloads("10.0.0.1", [22, 80, 3306]);

    assert.equal(payloads.find(p => p.port === 22)?.service, "ssh");
    assert.equal(payloads.find(p => p.port === 80)?.service, "http");
    assert.equal(payloads.find(p => p.port === 3306)?.service, "mysql");
  });

  it("should support both HTTP and HTTPS", () => {
    const payloads = generateNetworkScanPayloads("172.16.0.1", [443, 8443]);

    assert.equal(payloads[0].payload, "https://172.16.0.1:443");
    assert.equal(payloads[1].payload, "http://172.16.0.1:8443");
  });
});
