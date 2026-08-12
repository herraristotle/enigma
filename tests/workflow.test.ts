import { test } from "node:test";
import assert from "node:assert";
import { 
  validateWorkflow, 
  transformPayload, 
  buildProfileAdminEmailChain,
  type StoredXssStage 
} from "../core/runner/workflow.ts";

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