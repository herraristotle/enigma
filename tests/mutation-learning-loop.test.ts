import { test } from "node:test";
import assert from "node:assert";
import { LearningLoop } from "../core/engines/mutation/learning-loop.ts";

test("Learning Loop Feedback", async (t) => {
  await t.test("should provide feedback to mutation composer", () => {
    const learningLoop = new LearningLoop();

    // Record some outcomes
    learningLoop.record("executed", "<script>alert(1)</script>", "R1 context baseline");
    learningLoop.record("blocked", "<img onerror=alert(1)>", "R2 blockers");
    learningLoop.record("reflected", "<svg onload=alert(1)>", "R3 encoding");

    // Get feedback
    const feedback = learningLoop.getFeedback();

    assert.ok(feedback !== undefined, "feedback should be defined");
    assert.ok(feedback.successfulPayloads.includes("<script>alert(1)</script>"), "should contain successful payload");
    assert.ok(feedback.blockedPatterns.includes("<img onerror=alert(1)>"), "should contain blocked pattern");
    assert.ok(feedback.reflectedPatterns.includes("<svg onload=alert(1)>"), "should contain reflected pattern");
  });

  await t.test("should track rotor-specific outcomes", () => {
    const learningLoop = new LearningLoop();

    learningLoop.record("executed", "payload1", "R1 context baseline");
    learningLoop.record("executed", "payload2", "R2 blockers");
    learningLoop.record("blocked", "payload3", "R3 encoding");

    const feedback = learningLoop.getFeedback();

    const r1 = feedback.rotorOutcomes.get("r1_context");
    assert.ok(r1 !== undefined, "r1_context should exist");
    assert.strictEqual(r1!.executed, 1);

    const r2 = feedback.rotorOutcomes.get("r2_blockers");
    assert.ok(r2 !== undefined, "r2_blockers should exist");
    assert.strictEqual(r2!.executed, 1);

    const r3 = feedback.rotorOutcomes.get("r3_encoding");
    assert.ok(r3 !== undefined, "r3_encoding should exist");
    assert.strictEqual(r3!.blocked, 1);
  });
});
