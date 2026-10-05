import { test } from "node:test";
import assert from "node:assert";
import {
  validateWorkflow,
  transformPayload,
  buildProfileAdminEmailChain,
  type StoredXssStage
} from "../core/runner/workflow.ts";
import { MutationComposer } from "../core/engines/mutation/composer.ts";
import { EnigmaRunner, type BrowserAdapter, type BrowserObservation, type RunOptions } from "../core/runner/index.ts";

test("Workflow validation — valid chain", () => {
  const stages: StoredXssStage[] = [
    { name: "profile", injectUrl: "https://t.com/profile", observeUrl: "https://t.com/user/1", cookie: "victim=1" },
    { name: "admin", injectUrl: "https://t.com/profile", observeUrl: "https://t.com/admin/users", cookie: "admin=1" },
    { name: "email", injectUrl: "https://t.com/profile", observeUrl: "https://t.com/inbox", cookie: "admin=1", payloadTransform: "json-string-escape" }
  ];
  const errors = validateWorkflow(stages);
  assert.strictEqual(errors.length, 0, "valid workflow should have no errors");
});

test("Workflow validation — empty stages", () => {
  const errors = validateWorkflow([]);
  assert.ok(errors.includes("workflow must contain at least one stage"));
});

test("Workflow validation — duplicate names", () => {
  const stages: StoredXssStage[] = [
    { name: "profile", injectUrl: "https://t.com/p", observeUrl: "https://t.com/o" },
    { name: "profile", injectUrl: "https://t.com/p2", observeUrl: "https://t.com/o2" }
  ];
  const errors = validateWorkflow(stages);
  assert.ok(errors.some(e => e.includes("duplicate stage name: profile")));
});

test("Workflow validation — missing injectUrl", () => {
  const stages: StoredXssStage[] = [
    { name: "profile", observeUrl: "https://t.com/o" }
  ];
  const errors = validateWorkflow(stages);
  assert.ok(errors.some(e => e.includes("no injectUrl")));
});

test("Workflow validation — missing observeUrl", () => {
  const stages: StoredXssStage[] = [
    { name: "profile", injectUrl: "https://t.com/p" }
  ];
  const errors = validateWorkflow(stages);
  assert.ok(errors.some(e => e.includes("no observeUrl")));
});

test("transformPayload — identity", () => {
  const payload = "<img src=x onerror=alert(1)>";
  assert.strictEqual(transformPayload(payload, "identity"), payload);
});

test("transformPayload — url-encode", () => {
  const payload = "<img src=x onerror=alert(1)>";
  const encoded = transformPayload(payload, "url-encode");
  assert.ok(encoded.includes("%3C"), "url-encode should escape angle brackets");
});

test("transformPayload — json-string-escape", () => {
  const payload = '<img src="x" onerror="alert(1)">';
  const escaped = transformPayload(payload, "json-string-escape");
  assert.ok(escaped.includes('\\"'), "json-string-escape should escape double quotes");
  assert.ok(escaped.includes('\\<') || escaped.includes('<'), "json-string-escape should preserve or escape angle brackets");
});

test("buildProfileAdminEmailChain — canonical three-stage chain", () => {
  const chain = buildProfileAdminEmailChain({
    profileInjectUrl: "https://target.com/profile",
    profileObserveUrl: "https://target.com/user/1",
    adminObserveUrl: "https://target.com/admin/users",
    adminCookie: "admin=session123",
    emailInboxUrl: "https://target.com/inbox",
    victimParam: "bio",
    profileParam: "bio",
    adminParam: "bio",
    emailParam: "content",
    victimCookie: "victim=sess456"
  });

  assert.strictEqual(chain.length, 3);
  assert.strictEqual(chain[0].name, "profile");
  assert.strictEqual(chain[1].name, "admin-panel");
  assert.strictEqual(chain[2].name, "email-notification");

  assert.strictEqual(chain[0].cookie, "victim=sess456");
  assert.strictEqual(chain[1].cookie, "admin=session123");
  assert.strictEqual(chain[2].cookie, "admin=session123");

  assert.strictEqual(chain[2].payloadTransform, "json-string-escape");
  assert.ok(chain[0].formData?.bio === "bio");
});

test("absorbState — union-merges blockers/footholds/CSP without overwriting context", () => {
  const parent = new MutationComposer("html_content");
  const stage = new MutationComposer("attribute_url");

  stage.absorbBinarySearch([
    { family: "tag", value: "<img", blocked: true, successful: false, reflected: false },
    { family: "tag", value: "<svg", blocked: true, successful: false, reflected: false },
    { family: "event", value: "onerror", blocked: false, successful: true, reflected: true }
  ]);
  stage.absorbPartialSuccess("tag", "svg");
  stage.setCspDetected(true);

  parent.absorbState(stage.state);

  assert.deepStrictEqual([...(parent.state.blockedFamilies.get("tag") ?? [])].sort(), ["<img", "<svg"]);
  assert.ok(parent.state.successfulFamilies.get("event")?.has("onerror"));
  assert.ok(parent.state.footholds.some(f => f.family === "tag" && f.value === "svg"));
  assert.strictEqual(parent.state.cspDetected, true);
  assert.strictEqual(parent.state.context, "html_content", "absorbState must not overwrite context");

  // Idempotent: re-absorbing creates no duplicates.
  const footholdCount = parent.state.footholds.length;
  parent.absorbState(stage.state);
  assert.strictEqual(parent.state.footholds.length, footholdCount);
});

test("EnigmaRunner workflow — stage learnings transfer to parent knowledge and later stages", async () => {
  type Call = { target: string; payload: string; options?: RunOptions };
  const calls: Call[] = [];
  let phase: "main" | "s1" | "s2" = "main";

  const browser: BrowserAdapter = {
    async injectHooks(): Promise<void> {},
    async navigate(target: string, _parameter: string, payload: string, options?: RunOptions): Promise<BrowserObservation> {
      calls.push({ target, payload, options });
      if (target.includes("/s1")) phase = "s1";
      if (target.includes("/s2")) phase = "s2";

      if (target.includes("/s2")) {
        // Stage 2 baseline fires unconditionally — models an unfiltered renderer.
        return { statusCode: 200, blocked: false, reflected: true, executed: true, responseBody: "admin panel" };
      }
      if (target.includes("/s1")) {
        // Stage 1 reflects but never executes — its learnings must flow forward.
        return { statusCode: 200, blocked: false, reflected: true, executed: false, responseBody: "profile bio" };
      }
      return { statusCode: 200, blocked: false, reflected: true, executed: false, responseBody: "<div>page</div>" };
    },
    async probe(value: string) {
      // Top-level binary search passes; stage-1 binary search blocks two tags
      // so inferBlockers (≥2 confirmations) records blockedFamilies.tag.
      if (phase === "s1" && (value === "<img" || value === "<svg")) {
        return { blocked: true, reflected: false, successful: false };
      }
      return { blocked: false, reflected: false, successful: false };
    }
  };

  const workflow: StoredXssStage[] = [
    { name: "stage-1", injectUrl: "https://t.com/s1", observeUrl: "https://t.com/user/1", cookie: "victim=1" },
    { name: "stage-2", injectUrl: "https://t.com/s2", observeUrl: "https://t.com/admin", cookie: "admin=1" }
  ];

  const runner = new EnigmaRunner(browser, { workflow, cookie: "victim=0" });
  const result = await runner.run("https://t.com/", "bio");

  assert.strictEqual(result.success, true, "workflow should fire at stage-2");

  // stage-1 binary-search blockers merged back into parent composer → RunResult.knowledge.
  const blockedTags = (result.knowledge.blockedFamilies as Record<string, string[]>)["tag"] ?? [];
  assert.ok(blockedTags.includes("<img") && blockedTags.includes("<svg"),
    `stage-1 learnings missing from knowledge: ${JSON.stringify(blockedTags)}`);

  // Fired stage payload is present in attempts (previously dropped).
  assert.ok(result.attempts.some(a => a.result.executed), "executed workflow payload missing from attempts");

  // Per-stage cookie switching: stage-2 navigations used the admin cookie.
  const stage2Calls = calls.filter(c => c.target.includes("/s2"));
  assert.ok(stage2Calls.length > 0, "stage-2 never navigated");
  assert.ok(stage2Calls.every(c => c.options?.cookie === "admin=1"));

  // Workflow stages recorded into the learning-loop transcript.
  const rationales = result.learningLoop.transitions.map(t => t.rationale ?? "");
  assert.ok(rationales.some(r => r.startsWith("workflow:stage-1 baseline")));
  assert.ok(rationales.some(r => r.startsWith("workflow:stage-2 baseline")));
});