import { test } from "node:test";
import assert from "node:assert";
import { generateCloudMetadataTargets } from "../core/engines/ssrf/payloads/cloud-metadata.ts";
import { generateInternalServiceTargets } from "../core/engines/ssrf/payloads/internal-services.ts";

test("SSRF Targets Coverage", async (t) => {
  await t.test("Cloud metadata coverage", () => {
    const cloudTargets = generateCloudMetadataTargets();
    
    // Assert cloud metadata providers coverage
    const providers = cloudTargets.map(c => c.provider.toLowerCase());
    const requiredProviders = ["aws", "gcp", "azure", "digitalocean", "alibaba", "oracle", "kubernetes api"];
    for (const p of requiredProviders) {
      assert.ok(providers.includes(p), `Missing cloud provider: ${p}`);
    }
  });

  await t.test("Internal services coverage", () => {
    const internalTargets = generateInternalServiceTargets();

    const services = internalTargets.map(s => s.service.toLowerCase());
    const requiredServices = [
      "redis", "elasticsearch", "docker", "kubernetes", "consul", "etcd", "jenkins",
      "mongodb", "postgresql", "mysql", "memcached", "zookeeper", "prometheus",
      "grafana", "rabbitmq", "activemq", "kibana"
    ];
    for (const s of requiredServices) {
      assert.ok(services.includes(s), `Missing internal service: ${s}`);
    }

    // Assert total path count is at least 22 paths across internal targets
    const totalPathsCount = internalTargets.reduce((sum, item) => sum + item.paths.length, 0);
    assert.ok(totalPathsCount >= 22, `Paths count ${totalPathsCount} should be >= 22`);

    // Verify Redis payload check: "INFO" and no destructive commands
    const redis = internalTargets.find(s => s.service.toLowerCase() === "redis");
    assert.ok(redis, "Redis service configuration exists");
    assert.strictEqual(redis.safePayload, "INFO\r\n");
    const safePayload = redis.safePayload || "";
    const destructive = ["FLUSHALL", "SLAVEOF", "CONFIG SET"];
    for (const cmd of destructive) {
      assert.ok(!safePayload.includes(cmd), `Redis payload contains destructive command: ${cmd}`);
    }
  });
});
