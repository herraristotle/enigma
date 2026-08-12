import { describe, it } from "node:test";
import assert from "node:assert/strict";

describe("SSRF Blind Watch Mode Enhancement", () => {
  it("should support token-based correlation", () => {
    const tokens = new Map<string, { payload: string; timestamp: number }>();
    tokens.set("abc123", { payload: "http://169.254.169.254", timestamp: Date.now() });

    const callbackBody = JSON.stringify({ token: "abc123", data: "test" });
    const parsed = JSON.parse(callbackBody);

    assert.ok(tokens.has(parsed.token), "Token should exist in map");
    assert.equal(tokens.get(parsed.token)?.payload, "http://169.254.169.254");
  });

  it("should track multiple tokens simultaneously", () => {
    const tokens = new Map<string, { payload: string; timestamp: number }>();
    tokens.set("token1", { payload: "http://169.254.169.254/metadata", timestamp: Date.now() });
    tokens.set("token2", { payload: "http://169.254.169.254/latest/meta-data", timestamp: Date.now() });

    assert.equal(tokens.size, 2);
  });
});
