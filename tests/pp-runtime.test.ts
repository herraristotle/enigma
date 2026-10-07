import { test } from "node:test";
import assert from "node:assert";
import {
  confirmPrototypePollution,
  fetchAdapter,
  type PpProbeAdapter,
  type PpMechanism,
} from "../core/engines/mutation/pp-runtime.ts";

const TARGET = "https://victim.test/page";
const PARAM = "toString";

/**
 * Fake object-merging server: pollution requests with __proto__[PARAM]=mark
 * store the mark; markerless GETs echo every stored mark (simulating the
 * polluted prototype being rendered).
 */
function mergingAdapter(): PpProbeAdapter & { captured: string[] } {
  const polluted = new Set<string>();
  const captured: string[] = [];
  return {
    captured,
    async send(req) {
      captured.push(`${req.method} ${req.url} ${req.body ?? ""}`);
      if (req.method === "POST" && req.body) {
        const m = req.body.match(/ppm_[0-9a-f]+/);
        if (m) polluted.add(m[0]);
      }
      const url = new URL(req.url);
      for (const [k, v] of url.searchParams) {
        if (k.startsWith("__proto__")) {
          const m = v.match(/ppm_[0-9a-f]+/);
          if (m) polluted.add(m[0]);
        }
      }
      const echoed = [...polluted].join(",");
      return { status: 200, body: `<html>value=${echoed}</html>` };
    },
  };
}

/** Server that ignores pollution entirely. */
function ignoringAdapter(): PpProbeAdapter {
  return {
    async send() {
      return { status: 200, body: "<html>static</html>" };
    },
  };
}

const MECHANISMS: PpMechanism[] = ["query", "form-body", "json-body"];

for (const mechanism of MECHANISMS) {
  test(`pp-runtime — ${mechanism}: pollution taken → CONFIRMED`, async () => {
    const adapter = mergingAdapter();
    const result = await confirmPrototypePollution(TARGET, PARAM, adapter, mechanism);
    assert.ok(result, `${mechanism} should confirm`);
    assert.strictEqual(result!.mechanism, mechanism);
    assert.strictEqual(result!.confidence, "CONFIRMED");
    assert.match(result!.marker, /^ppm_[0-9a-f]{8}$/);
    assert.notStrictEqual(result!.baselineHash, result!.pollutedHash);
    assert.ok(result!.evidence.includes(result!.marker));
  });
}

test("pp-runtime — ignored pollution → null", async () => {
  for (const mechanism of MECHANISMS) {
    const result = await confirmPrototypePollution(TARGET, PARAM, ignoringAdapter(), mechanism);
    assert.strictEqual(result, null, `${mechanism} should not confirm`);
  }
});

test("pp-runtime — adapter rejects → null, never throws", async () => {
  const rejecting: PpProbeAdapter = {
    async send() { throw new Error("ECONNRESET"); },
  };
  const result = await confirmPrototypePollution(TARGET, PARAM, rejecting, "query");
  assert.strictEqual(result, null);
});

test("pp-runtime — one of two rounds lands → LIKELY", async () => {
  // Store only the second pollution's marker; first round lands nowhere.
  let stored = "";
  let pollutionSeen = 0;
  const oneOfTwo: PpProbeAdapter = {
    async send(req) {
      const isPollution = req.method === "POST" || req.url.includes("__proto__");
      if (isPollution) {
        pollutionSeen++;
        const m = `${req.body ?? req.url}`.match(/ppm_[0-9a-f]+/);
        if (m && pollutionSeen >= 2) stored = m[0];
        return { status: 200, body: "ok" };
      }
      return { status: 200, body: stored ? `<html>value=${stored}</html>` : "<html>static</html>" };
    },
  };
  const result = await confirmPrototypePollution(TARGET, PARAM, oneOfTwo, "json-body");
  assert.ok(result, "second-round hit should still confirm");
  assert.strictEqual(result!.confidence, "LIKELY");
});

test("pp-runtime — safety: captured requests never contain NODE_OPTIONS/--require/shell", async () => {
  const adapter = mergingAdapter();
  for (const mechanism of MECHANISMS) {
    await confirmPrototypePollution(TARGET, PARAM, adapter, mechanism);
  }
  assert.ok(adapter.captured.length > 0, "adapter should have seen requests");
  for (const req of adapter.captured) {
    assert.ok(!req.includes("NODE_OPTIONS"), `NODE_OPTIONS leaked: ${req}`);
    assert.ok(!req.includes("--require"), `--require leaked: ${req}`);
    assert.ok(!req.includes("shell"), `shell gadget leaked: ${req}`);
    assert.ok(!req.includes("child_process"), `child_process leaked: ${req}`);
  }
  // Only the requested marker parameter family appears
  // (query strings arrive URL-encoded: %5B = '[', %5D = ']').
  for (const req of adapter.captured) {
    if (req.includes("__proto__")) {
      const encoded = `__proto__%5B${PARAM}%5D`;
      const plain = `__proto__[${PARAM}]`;
      assert.ok(
        req.includes(encoded) || req.includes(plain) || req.includes(`"${PARAM}"`),
        `unexpected proto key: ${req}`,
      );
    }
  }
});

test("fetchAdapter — exists as default transport factory", () => {
  const adapter = fetchAdapter();
  assert.strictEqual(typeof adapter.send, "function");
});
