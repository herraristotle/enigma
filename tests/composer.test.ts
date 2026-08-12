import { test } from "node:test";
import assert from "node:assert";
import { MutationComposer } from "../core/engines/mutation/composer.ts";

test("MutationComposer Tests", async (t) => {
  await t.test("Initial candidates include baseline", () => {
    const composer = new MutationComposer("html_content");
    const candidates = composer.nextCandidates();
    
    assert.ok(candidates.length > 0);
    assert.strictEqual(candidates[0]!.rotor, "context");
    assert.ok(candidates[0]!.payload.includes("<img src=x onerror=alert(1)>"));
  });

  await t.test("absorbBinarySearch updates blocked families and tags", () => {
    const composer = new MutationComposer("html_content");
    
    composer.absorbBinarySearch([
      { family: "angle", value: "<", blocked: true, reflected: false, successful: false },
      { family: "angle", value: ">", blocked: true, reflected: false, successful: false },
      { family: "tag", value: "img", blocked: true, reflected: false, successful: false },
      { family: "tag", value: "svg", blocked: true, reflected: false, successful: false },
      { family: "other", value: "val", blocked: false, reflected: true, successful: true }
    ]);
    
    const state = composer.exportState();
    
    // Check angle family blocked
    const blockedAngles = (state.blockedFamilies as any)["angle"];
    assert.ok(blockedAngles.includes("<"));
    
    // Check tag family blocked
    const blockedTags = (state.blockedFamilies as any)["tag"];
    assert.ok(blockedTags.includes("img"));
    
    // Check blocked tags set
    assert.ok((state.blockedTags as string[]).includes("img"));
  });

  await t.test("Exhaustive Enumeration Pivot on 4+ blocked tags", () => {
    const composer = new MutationComposer("html_content");
    
    // Simulate 4 blocked tags and exhausted candidate space
    composer.absorbBinarySearch([
      { component: "img", family: "tag", value: "img", blocked: true, reflected: false, successful: false },
      { component: "svg", family: "tag", value: "svg", blocked: true, reflected: false, successful: false },
      { component: "body", family: "tag", value: "body", blocked: true, reflected: false, successful: false },
      { component: "div", family: "tag", value: "div", blocked: true, reflected: false, successful: false }
    ]);

    const candidates = composer.nextCandidates();
    
    const hasEnumeration = candidates.some(c => c.family === "enumeration");
    assert.ok(hasEnumeration, "Composer should pivot to enumeration with 4 blocked tags");
  });

  await t.test("Tested payloads are never re-proposed", () => {
    const composer = new MutationComposer("html_content");
    
    // Generate first batch
    const batch1 = composer.nextCandidates();
    assert.ok(batch1.length > 0);
    
    // Generate second batch
    const batch2 = composer.nextCandidates();
    
    // Ensure no overlap
    for (const c1 of batch1) {
      for (const c2 of batch2) {
        assert.notStrictEqual(c1.payload, c2.payload, "Payload was re-proposed!");
      }
    }
  });

  await t.test("CSP presence triggers CSP bypass cascade", () => {
    const composer = new MutationComposer("html_content");
    composer.setCspDetected(true);
    
    const candidates = composer.nextCandidates();
    const hasCspBypass = candidates.some(c => c.family === "csp");
    
    assert.ok(hasCspBypass, "Composer should include CSP bypasses when CSP is detected");
  });

  await t.test("Pivot to Enumeration: should prioritize successful events when pivoting", () => {
    const composer = new MutationComposer("html_content");

    // Block 4 tags to trigger pivot
    composer.absorbBinarySearch([
      { family: "tag", value: "img", blocked: true, reflected: false, successful: false },
      { family: "tag", value: "svg", blocked: true, reflected: false, successful: false },
      { family: "tag", value: "body", blocked: true, reflected: false, successful: false },
      { family: "tag", value: "div", blocked: true, reflected: false, successful: false }
    ]);

    // Mark onerror and svg as successful
    composer.absorbPartialSuccess("event", "onerror");
    composer.absorbPartialSuccess("tag", "svg");

    const candidates = composer.nextCandidates();

    const pivotCandidates = candidates.filter(c => c.family === "enumeration");
    assert.ok(pivotCandidates.length > 0, "Should include pivot candidates");

    // onerror should appear before onclick (which wasn't successful)
    const onerrorIndex = pivotCandidates.findIndex(c => c.payload.includes("onerror"));
    const onclickIndex = pivotCandidates.findIndex(c => c.payload.includes("onclick"));
    if (onerrorIndex >= 0 && onclickIndex >= 0) {
      assert.ok(onerrorIndex < onclickIndex, "onerror should appear before onclick");
    }
  });

  await t.test("Pivot to Enumeration: should generate 24 events per tag", () => {
    const composer = new MutationComposer("html_content");

    // Block 4 tags to trigger pivot
    composer.absorbBinarySearch([
      { family: "tag", value: "img", blocked: true, reflected: false, successful: false },
      { family: "tag", value: "svg", blocked: true, reflected: false, successful: false },
      { family: "tag", value: "body", blocked: true, reflected: false, successful: false },
      { family: "tag", value: "div", blocked: true, reflected: false, successful: false }
    ]);

    const candidates = composer.nextCandidates();

    // Should generate at least 24 candidates per tag in pivot mode
    const pivotCandidates = candidates.filter(c => c.family === "enumeration");
    assert.ok(pivotCandidates.length >= 24, `Expected at least 24 pivot candidates, got ${pivotCandidates.length}`);
  });

  await t.test("absorbPartialSuccess tracks successful events", () => {
    const composer = new MutationComposer("html_content");
    composer.absorbPartialSuccess("event", "onerror");

    const state = composer.exportState();
    assert.ok((state.successfulEvents as string[]).includes("onerror"));
  });
});
