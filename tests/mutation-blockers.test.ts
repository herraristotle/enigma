import { test } from "node:test";
import assert from "node:assert";
import { inferBlockers, type ComponentObservation } from "../core/engines/mutation/blockers.ts";

test("inferBlockers Tests", async (t) => {
  await t.test("inferBlockers correctly infers from observations", () => {
    const observations: ComponentObservation[] = [
      { family: "event", value: "onclick", blocked: true, successful: false },
      { family: "event", value: "onerror", blocked: true, successful: false },
      { family: "event", value: "onload", blocked: false, successful: true }
    ];

    const blockers = inferBlockers(observations);
    assert.equal(blockers.length, 1, "Should infer blocker for event family");
    assert.equal(blockers[0].family, "event");
    assert.deepStrictEqual(blockers[0].blockedValues, ["onclick", "onerror"]);
  });
});
