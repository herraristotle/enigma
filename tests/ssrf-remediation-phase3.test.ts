import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  generateCloudMetadataTargets,
  generateImdsV2Payloads,
} from "../core/engines/ssrf/payloads/cloud-metadata.ts";

describe("Task 3A: requiredHeaders in metadata payloads", () => {
  const targets = generateCloudMetadataTargets();

  it("GCP includes requiredHeaders with Metadata-Flavor", () => {
    const gcp = targets.find((t) => t.provider === "GCP");
    assert.ok(gcp, "GCP entry exists");
    assert.deepEqual(gcp.requiredHeaders, { "Metadata-Flavor": "Google" });
  });

  it("Azure includes requiredHeaders with Metadata flag", () => {
    const azure = targets.find((t) => t.provider === "Azure");
    assert.ok(azure, "Azure entry exists");
    assert.deepEqual(azure.requiredHeaders, { "Metadata": "true" });
  });

  it("AWS has no requiredHeaders (undefined)", () => {
    const aws = targets.find((t) => t.provider === "AWS");
    assert.ok(aws, "AWS entry exists");
    assert.equal(aws.requiredHeaders, undefined);
  });

  it("DigitalOcean has no requiredHeaders (undefined)", () => {
    const doo = targets.find((t) => t.provider === "DigitalOcean");
    assert.ok(doo, "DigitalOcean entry exists");
    assert.equal(doo.requiredHeaders, undefined);
  });
});

describe("Task 3B: new cloud providers", () => {
  const targets = generateCloudMetadataTargets();
  const providers = targets.map((t) => t.provider);

  it("contains Hetzner", () => {
    assert.ok(providers.includes("Hetzner"));
    const h = targets.find((t) => t.provider === "Hetzner")!;
    assert.equal(h.endpoint, "169.254.169.254");
    assert.deepEqual(h.paths, ["/metadata/v1/", "/metadata/v1/instance-id", "/metadata/v1/hostname"]);
  });

  it("contains OpenStack/Nova", () => {
    assert.ok(providers.includes("OpenStack/Nova"));
    const os = targets.find((t) => t.provider === "OpenStack/Nova")!;
    assert.equal(os.endpoint, "169.254.169.254");
    assert.deepEqual(os.paths, ["/openstack/latest/", "/openstack/latest/meta_data.json"]);
  });

  it("contains SoftLayer", () => {
    assert.ok(providers.includes("SoftLayer"));
    const sl = targets.find((t) => t.provider === "SoftLayer")!;
    assert.equal(sl.endpoint, "169.254.169.254");
    assert.deepEqual(sl.paths, ["/rest/v1.1/", "/rest/v1.1/SoftLayer_Resource_Metadata"]);
  });

  it("contains Linode", () => {
    assert.ok(providers.includes("Linode"));
    const l = targets.find((t) => t.provider === "Linode")!;
    assert.equal(l.endpoint, "169.254.169.254");
    assert.deepEqual(l.paths, ["/v1/", "/v1/instance", "/v1/region"]);
  });

  it("contains Vultr", () => {
    assert.ok(providers.includes("Vultr"));
    const v = targets.find((t) => t.provider === "Vultr")!;
    assert.equal(v.endpoint, "169.254.169.254");
    assert.deepEqual(v.paths, ["/v1/", "/v1/meta-data", "/v1/user-data"]);
  });

  it("contains ECS with Alibaba's IP and paths", () => {
    assert.ok(providers.includes("ECS"));
    const ecs = targets.find((t) => t.provider === "ECS")!;
    assert.equal(ecs.endpoint, "100.100.100.200");
    const alibaba = targets.find((t) => t.provider === "Alibaba")!;
    assert.deepEqual(ecs.paths, alibaba.paths);
  });

  it("contains AWS IPv6 with fd00:ec2::254 and same paths as AWS", () => {
    assert.ok(providers.includes("AWS IPv6"));
    const aws6 = targets.find((t) => t.provider === "AWS IPv6")!;
    assert.equal(aws6.endpoint, "fd00:ec2::254");
    const aws = targets.find((t) => t.provider === "AWS")!;
    assert.deepEqual(aws6.paths, aws.paths);
  });

  it("total provider count is 14", () => {
    assert.equal(targets.length, 14);
  });
});

describe("Task 3C: IMDSv2 payloads", () => {
  it("returns token PUT then credential GET sequence", () => {
    const payloads = generateImdsV2Payloads("169.254.169.254");
    assert.equal(payloads.length, 2);

    const tokenReq = payloads[0];
    assert.equal(tokenReq.step, "get-token");
    assert.equal(tokenReq.method, "PUT");
    assert.equal(tokenReq.url, "http://169.254.169.254/latest/api/token");
    assert.deepEqual(tokenReq.headers, {
      "X-aws-ec2-metadata-token-ttl-seconds": "21600",
    });

    const credReq = payloads[1];
    assert.equal(credReq.step, "get-credentials");
    assert.equal(credReq.method, "GET");
    assert.equal(credReq.url, "http://169.254.169.254/latest/meta-data/iam/security-credentials/");
    assert.ok("_IMDSv2_TOKEN_PLACEHOLDER_" in credReq.headers || "Authorization" in credReq.headers || Object.keys(credReq.headers).length >= 0);
    assert.equal(credReq.headers["X-aws-ec2-metadata-token"], "_IMDSv2_TOKEN_PLACEHOLDER_");
  });

  it("uses provided ip parameter", () => {
    const payloads = generateImdsV2Payloads("10.0.0.1");
    assert.ok(payloads[0].url.includes("10.0.0.1"));
    assert.ok(payloads[1].url.includes("10.0.0.1"));
  });
});
