import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { MutationComposer } from "../core/engines/mutation/composer.ts";

describe("CSP Bypass Cascade Enhancement", () => {
  it("should generate more CSP bypass attempts", () => {
    const composer = new MutationComposer("html");
    composer.setCspDetected(true);
    const candidates = composer.nextCandidates();

    const cspCandidates = candidates.filter(c => c.family === "csp");
    assert.ok(cspCandidates.length >= 10, `Expected >=10 CSP candidates, got ${cspCandidates.length}`);
  });

  it("should include advanced CSP bypasses", () => {
    const composer = new MutationComposer("html");
    composer.setCspDetected(true);
    const candidates = composer.nextCandidates();

    const advancedBypasses = candidates.filter(c =>
      c.family === "csp" &&
      (c.rationale.includes("jsonp") || c.rationale.includes("dynamic") || c.rationale.includes("angular"))
    );
    assert.ok(advancedBypasses.length > 0, "Expected at least one advanced CSP bypass");
  });
});
