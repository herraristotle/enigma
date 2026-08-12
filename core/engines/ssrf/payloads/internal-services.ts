/**
 * 18 service definitions + localhost admin path database.
 *
 * The competitor SSRF blog references "30+ internal services" but enumerates by
 * name only Redis, Elasticsearch, Docker, Kubernetes, Consul, etcd plus
 * "22 more services...". This module ships the 18 service targets with HTTP
 * fingerprintable paths (covering every named example in the blog's
 * "Internal Services" mermaid), intentionally excluding services with no
 * HTTP probe surface (e.g. Cassandra, Kafka, zk-only). Add new entries as
 * additional research surfaces specific fingerprint regexes for them.
 *
 * @see https://labs.trace37.com/blog/enigma-ssrf-engine/ "Internal Services"
 */
export function generateInternalServiceTargets(): Array<{ service: string, port: number, paths: string[], safePayload?: string, tcpOnly?: boolean }> {
  return [
    {
      service: "Redis",
      port: 6379,
      paths: ["/"],
      safePayload: "INFO\r\n"
    },
    {
      service: "Elasticsearch",
      port: 9200,
      paths: ["/", "/_cat/indices", "/_cluster/health"]
    },
    {
      service: "Docker",
      port: 2375,
      paths: ["/images/json", "/containers/json", "/info"]
    },
    {
      // Competitor diagram targets Kubernetes API (6443) with /api fingerprint.
      // Port 10250 is the kubelet read-only/HTTPS port — keep as a secondary surface.
      service: "Kubernetes",
      port: 6443,
      paths: ["/api", "/api/v1", "/api/v1/namespaces", "/api/v1/secrets", "/api/v1/namespaces/default/secrets"]
    },
    {
      service: "Kubernetes kubelet",
      port: 10250,
      paths: ["/pods", "/metrics", "/spec/"]
    },
    {
      service: "Consul",
      port: 8500,
      paths: ["/v1/agent/self", "/v1/kv/?recurse", "/v1/catalog/services"]
    },
    {
      service: "etcd",
      port: 2379,
      paths: ["/v2/keys", "/v3/kv/range"]
    },
    {
      service: "Jenkins",
      port: 8080,
      paths: ["/script", "/asynchPeople/", "/api/json"]
    },
    {
      service: "MongoDB",
      port: 27017,
      paths: ["/"]
    },
    {
      service: "PostgreSQL",
      port: 5432,
      paths: [],
      tcpOnly: true
    },
    {
      service: "MySQL",
      port: 3306,
      paths: [],
      tcpOnly: true
    },
    {
      service: "Memcached",
      port: 11211,
      paths: ["/stats", "/slabs", "/items"]
    },
    {
      service: "Zookeeper",
      port: 2181,
      paths: ["/"]
    },
    {
      service: "Prometheus",
      port: 9090,
      paths: ["/metrics", "/api/v1/targets", "/api/v1/query"]
    },
    {
      service: "Grafana",
      port: 3000,
      paths: ["/api/health", "/api/users", "/api/admin/settings"]
    },
    {
      service: "RabbitMQ",
      port: 15672,
      paths: ["/api/overview", "/api/connections", "/api/queues"]
    },
    {
      service: "ActiveMQ",
      port: 8161,
      paths: ["/admin/", "/admin/queues.jsp", "/admin/topics.jsp"]
    },
    {
      service: "Kibana",
      port: 5601,
      paths: ["/status", "/api/status", "/app/kibana"]
    },
    {
      // Competitor lists 22 common admin endpoints including phpMyAdmin, Apache
      // server-status, Spring Actuator, Go pprof/debug, and health/metrics surfaces.
      service: "localhost admin paths",
      port: 80,
      paths: [
        "/admin",
        "/administrator",
        "/admin/config",
        "/admin/settings",
        "/phpmyadmin",
        "/pma",
        "/server-status",
        "/server-info",
        "/actuator",
        "/actuator/env",
        "/actuator/health",
        "/actuator/mappings",
        "/debug/vars",
        "/debug/pprof",
        "/metrics",
        "/health",
        "/info",
        "/backend",
        "/manage",
        "/manager/html",
        "/private",
        "/internal",
        "/setup",
        "/console",
        "/status"
      ]
    }
  ];
}
