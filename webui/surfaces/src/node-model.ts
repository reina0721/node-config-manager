import { z } from 'zod';

const toggle = z.object({ enabled: z.boolean() }).strict();
const transportSchema = z.enum(['xhttp', 'ws', 'raw']);
const securitySchema = z.enum(['tls', 'reality']);
const listenerSchema = z.enum(['shared-https', 'dedicated']);
const inboundProtocol = z.enum(['xhttp', 'ws', 'reality', 'vless']);
const inboundCapabilitiesSchema = z.object({
  combinations: z.array(
    z.object({
      protocol: z.literal('vless'),
      transport: transportSchema,
      security: securitySchema,
      listener: listenerSchema,
      runtime: z.string(),
      formats: z.array(z.enum(['xray', 'mihomo'])),
    }),
  ),
});
export type InboundCombination = z.infer<typeof inboundCapabilitiesSchema>['combinations'][number];
export const adminFieldErrorSchema = z.object({
  field: z.string(),
  code: z.string(),
  message: z.string(),
});
export type AdminFieldError = z.infer<typeof adminFieldErrorSchema>;
const managedInboundSchema = z
  .object({
    remark: z.string(),
    protocol: inboundProtocol,
    transport: transportSchema.optional(),
    security: securitySchema.optional(),
    listener: listenerSchema.optional(),
    path: z.string(),
    port: z.number().int(),
    enabled: z.boolean(),
  })
  .strict();
const managedHostSchema = z
  .object({
    remark: z.string(),
    description: z.string(),
    node: z.literal('local'),
    inbound: z.string(),
    addresses: z.array(z.string()),
    port: z.number().int(),
    tags: z.array(z.string()),
    enabled: z.boolean(),
    sni: z.string(),
    alpn: z.array(z.string()),
    host_header: z.string(),
    path: z.string(),
    fingerprint: z.string(),
    order: z.number().int(),
    mihomo_ip_version: z.enum(['dual', 'ipv4', 'ipv6', 'ipv4-prefer', 'ipv6-prefer']),
    mihomo_udp: z.boolean(),
    formats: z.array(z.enum(['xray', 'mihomo'])),
  })
  .strict();
const managedGroupSchema = z
  .object({
    name: z.string(),
    description: z.string(),
    enabled: z.boolean(),
    inbounds: z.array(z.string()),
    hosts: z.array(z.string()),
  })
  .strict();
const upstreamSchema = z
  .object({
    name: z.string(),
    enabled: z.boolean(),
    protocol: z.enum(['socks5', 'https-connect', 'vless']),
    address: z.string(),
    port: z.number().int(),
    server_name: z.string(),
  })
  .strict();
const routingRuleSchema = z
  .object({
    name: z.string(),
    order: z.number().int(),
    enabled: z.boolean(),
    inbounds: z.array(z.string()),
    domains: z.array(z.string()),
    ips: z.array(z.string()),
    port_min: z.number().int().nullable().optional(),
    port_max: z.number().int().nullable().optional(),
    network: z.enum(['tcp', 'udp']).nullable().optional(),
    outbound: z.string(),
  })
  .strict();
const catalogueSchema = z
  .object({
    inbounds: z.record(z.string(), managedInboundSchema).optional(),
    hosts: z.record(z.string(), managedHostSchema).optional(),
    groups: z.record(z.string(), managedGroupSchema).optional(),
    upstreams: z.record(z.string(), upstreamSchema).optional(),
    rules: z.record(z.string(), routingRuleSchema).optional(),
  })
  .strict();
export type ManagedInbound = z.infer<typeof managedInboundSchema>;
export type ManagedHost = z.infer<typeof managedHostSchema>;
export type ManagedGroup = z.infer<typeof managedGroupSchema>;
export type ManagedUpstream = z.infer<typeof upstreamSchema>;
export type ManagedRule = z.infer<typeof routingRuleSchema>;
export type UpstreamCredential =
  { kind: 'password'; username: string; password: string } | { kind: 'vless'; id: string };
export type CatalogueEdit = { id: string | null } & (
  | { kind: 'inbound'; value: ManagedInbound | null }
  | { kind: 'host'; value: ManagedHost | null }
  | { kind: 'group'; value: ManagedGroup | null }
  | {
      kind: 'upstream';
      value: ManagedUpstream | null;
      credential?: UpstreamCredential;
      clear_credential?: boolean;
    }
  | { kind: 'rule'; value: ManagedRule | null }
);
export type RoutingQuery = {
  inbound: string;
  domain?: string;
  ip?: string;
  port: number;
  network: 'tcp' | 'udp';
};
export const routingMatchSchema = z.object({
  rule: z.string().nullable(),
  outbound: z.string(),
  cn_precedence: z.boolean(),
});
export type RoutingMatch = z.infer<typeof routingMatchSchema>;
export const fleetSchema = z.object({
  local: z.object({ id: z.literal('local'), hostname: z.string().nullable(), version: z.string() }),
  peers: z.array(
    z.object({
      id: z.string(),
      name: z.string(),
      hostname: z.string(),
      address: z.string(),
      port: z.number(),
      last_seen: z.number(),
      stale: z.boolean(),
    }),
  ),
  grants: z.array(
    z.object({ id: z.string(), name: z.string(), scope: z.enum(['read', 'manage']) }),
  ),
});
export type Fleet = z.infer<typeof fleetSchema>;
export type PeerRegistration = {
  name: string;
  hostname: string;
  address: string;
  port: number;
  token: string;
};
export type PeerGrant = { name: string; scope: 'read' | 'manage' };
export const panelSchema = z.object({
  administrator_configured: z.boolean(),
  session_lifetime: z.number(),
  session_idle_timeout: z.number(),
  subscription_enabled: z.boolean(),
  subscription_access: z.string(),
  browser_access: z.boolean(),
  browser_ttl: z.number(),
});
export type PanelSettings = z.infer<typeof panelSchema>;
export const xrayViewSchema = z.object({
  release: z.string(),
  configuration: z.record(z.string(), z.unknown()),
  encrypted: z.boolean(),
  browser_access: z.boolean(),
  managed_routing: z.boolean(),
});
export type XrayView = z.infer<typeof xrayViewSchema>;
const node = z
  .object({
    domain: z.string(),
    reality_domain: z.string(),
    aliases: z.array(z.string()),
    ipv4: z.string(),
    ipv6: z.string(),
  })
  .strict();
export const nodeConfigurationSchema = z
  .object({
    schema_version: z.number().int(),
    node,
    ports: z.object({ http: z.number(), https: z.number(), reality: z.number() }).strict(),
    transport: z
      .object({
        xhttp: z.object({ path: z.string(), mode: z.string(), socket: z.string() }).strict(),
        ws: z.object({ path: z.string(), socket: z.string() }).strict(),
        reality: z.object({ path: z.string(), mode: z.string() }).strict(),
      })
      .strict(),
    tls: z
      .object({
        protocols: z.array(z.string()),
        http2: z.boolean(),
        http3: z.boolean(),
        alt_svc_max_age: z.number(),
        domain_cert_dir: z.string(),
        ip_cert_dir: z.string(),
      })
      .strict(),
    website: z
      .object({ root: z.string(), reserved_paths: z.array(z.string()).default([]) })
      .strict(),
    runtime: z
      .object({
        xray_binary: z.string(),
        nginx_binary: z.string(),
        usque_binary: z.string(),
        xray_user: z.string(),
        nginx_user: z.string(),
        log_root: z.string(),
      })
      .strict(),
    clients: z
      .object({
        xhttp_weight: z.number(),
        ws_weight: z.number(),
        reality_weight: z.number(),
        fingerprint_weights: z.record(z.string(), z.number()),
      })
      .strict(),
    warp: z
      .object({
        enabled: z.boolean(),
        config_file: z.string(),
        take_over_default_route: z.boolean(),
      })
      .strict(),
    vless: z.object({ encryption: z.boolean() }).strict().optional(),
    distribution: toggle.optional(),
    management: catalogueSchema.optional(),
    cn_warp: z
      .object({
        enabled: z.boolean(),
        interface: z.string(),
        config_file: z.string(),
        routing_table: z.number(),
        rule_priority: z.number(),
        socket_mark: z.number(),
        geodata_dir: z.string(),
      })
      .strict()
      .optional(),
    web_services: z
      .object({
        enabled: z.boolean(),
        librespeed_port: z.number(),
        openlist_port: z.number(),
        openlist_data_dir: z.string(),
        openlist_files_dir: z.string(),
        download_size_mib: z.number(),
      })
      .strict()
      .optional(),
  })
  .strict();
export type NodeConfiguration = z.infer<typeof nodeConfigurationSchema>;
export const serviceSchema = z.object({
  name: z.string(),
  enabled: z.boolean(),
  available: z.boolean(),
  state: z.record(z.string(), z.string()).nullable(),
});
export type ManagedService = z.infer<typeof serviceSchema>;
const networkCounter = z.object({
  interface: z.string(),
  rx_bytes: z.number(),
  tx_bytes: z.number(),
  rx_bytes_per_second: z.number().nullable(),
  tx_bytes_per_second: z.number().nullable(),
});
export const overviewSchema = z.object({
  version: z.string(),
  domain: z.string().nullable(),
  configured: z.boolean(),
  current: z.string().nullable(),
  integrity: z.boolean(),
  recovery_required: z.boolean(),
  services: z.array(serviceSchema),
  metrics: z.object({
    sample_unix: z.number(),
    source: z.string(),
    cpu_percent: z.number().nullable(),
    uptime_seconds: z.number().nullable(),
    memory: z
      .object({ total_bytes: z.number(), available_bytes: z.number(), used_bytes: z.number() })
      .nullable(),
    disk: z
      .object({ mount: z.string(), total_bytes: z.number(), available_bytes: z.number() })
      .nullable(),
    network: z.array(networkCounter).nullable(),
  }),
});
export type NodeOverview = z.infer<typeof overviewSchema>;
export const configurationViewSchema = z.object({
  config: nodeConfigurationSchema,
  assets: z.array(z.string()),
  base: z.string(),
  safe_mode: z.boolean(),
  inbound_capabilities: inboundCapabilitiesSchema.optional(),
});
export type ConfigurationView = z.infer<typeof configurationViewSchema>;
export const nodesViewSchema = z.object({
  release: z.string(),
  domain: node,
  ports: z.object({ http: z.number(), https: z.number(), reality: z.number() }),
  distribution_enabled: z.boolean(),
  access: z.string(),
  protocols: z.array(z.object({ name: z.string(), port: z.number(), weight: z.number() })),
});
export type NodesView = z.infer<typeof nodesViewSchema>;
export const networkViewSchema = z.object({
  native: node,
  warp: nodeConfigurationSchema.shape.warp,
  cn_warp: nodeConfigurationSchema.shape.cn_warp.nullable(),
  interfaces: z
    .array(
      z.object({
        ifname: z.string(),
        operstate: z.string().optional(),
        mtu: z.number().optional(),
        addr_info: z
          .array(z.object({ local: z.string(), family: z.string(), prefixlen: z.number() }))
          .optional(),
      }),
    )
    .nullable(),
  routes_v4: z.string().nullable(),
  routes_v6: z.string().nullable(),
  rules_v6: z.string().nullable(),
  rules: z.string().nullable(),
  services: z.array(serviceSchema),
});
export type NetworkView = z.infer<typeof networkViewSchema>;
export const dnsViewSchema = z.object({
  records: z.array(
    z.object({ name: z.string(), A: z.string(), AAAA: z.string(), proxied: z.boolean() }),
  ),
  certificates: z.array(
    z.object({ kind: z.string(), details: z.string().nullable(), valid_24h: z.boolean() }),
  ),
  credentials_configured: z.boolean(),
  zone: z.string().nullable(),
});
export type DnsView = z.infer<typeof dnsViewSchema>;
export const planViewSchema = z.object({
  restores_identity: z.boolean().default(false),
  plan: z.string(),
  release: z.string(),
  expires_in: z.number(),
  advanced: z.boolean(),
  risk: z.string(),
  diff: z.string(),
  changes: z.array(
    z.object({
      field: z.string(),
      before: z.unknown(),
      after: z.unknown(),
      protected: z.boolean(),
    }),
  ),
});
export type ConfigPlan = z.infer<typeof planViewSchema>;
export const deploymentViewSchema = z.object({
  configuration_diff: z.string(),
  required_actions: z.array(z.string()),
  dns_changes: z.array(
    z.object({ name: z.string(), kind: z.string(), before: z.unknown(), after: z.unknown() }),
  ),
  stages: z.array(z.string()),
  recovery_limits: z.array(z.string()),
  manual_dns: z.boolean(),
  manual_certificates: z.boolean(),
});
export const jobResultSchema = z.object({
  message: z.string().optional(),
  error: z.string().optional(),
  failed_stage: z.string().optional(),
  hint: z.string().optional(),
  token: z.string().optional(),
  log: z.string().optional(),
  checked: z.boolean().optional(),
  plan: z.string().optional(),
  backup: z.string().optional(),
  release: z.string().optional(),
  current: z.string().nullable().optional(),
  deployment: deploymentViewSchema.or(z.boolean()).optional(),
  deployment_digest: z.string().optional(),
  check_deferred_until_dependencies: z.boolean().optional(),
  ok: z.boolean().optional(),
  checks: z
    .array(z.object({ name: z.string(), ok: z.boolean(), detail: z.string(), remedy: z.string() }))
    .optional(),
  diagnostics: z
    .array(z.object({ name: z.string(), ok: z.boolean(), trace: z.string().nullable() }))
    .optional(),
});
export type JobResult = z.infer<typeof jobResultSchema>;
export const jobSchema = z.object({
  id: z.string(),
  operation: z.string(),
  phase: z.string(),
  started: z.number(),
  finished: z.number().nullable(),
  ok: z.boolean().nullable(),
  result: jobResultSchema.nullable(),
});
export type ManagedJob = z.infer<typeof jobSchema>;
export const operationsViewSchema = z.object({
  jobs: z.array(jobSchema),
  audit: z.array(
    z.object({
      time: z.number(),
      operation: z.string(),
      outcome: z.string(),
      id: z.string().nullable(),
    }),
  ),
  current: z.string().nullable(),
  previous: z.string().nullable(),
  recovery_required: z.boolean(),
  backups: z.array(z.object({ id: z.string(), created: z.number(), restorable: z.boolean() })),
});
export type OperationsView = z.infer<typeof operationsViewSchema>;
export type OperationName =
  | 'api-restart'
  | 'doctor'
  | 'dns-check'
  | 'network-check'
  | 'renew-certificates'
  | 'backup'
  | 'rollback'
  | 'recover'
  | 'subscription-rotate'
  | 'subscription-revoke'
  | 'logs'
  | 'service-restart'
  | 'service-reload'
  | 'upgrade';
export type OperationInput = Readonly<{
  operation: OperationName;
  confirm: string;
  service?: string;
  version?: string;
}>;
export type ProvisionOptions = Readonly<{
  manual_certificates: boolean;
  acme_email?: string;
  accept_ca_terms: boolean;
  accept_warp_terms: boolean;
  skip_dependencies: boolean;
}>;

export const proxyUsersSchema = z.array(
  z.object({ username: z.string(), device_limit: z.number().int().optional() }).strict(),
);
export const proxyAccessSchema = z.object({
  enabled: z.boolean(),
  ttl_seconds: z.number(),
  portal: z.string(),
  users: z.array(
    z.object({
      username: z.string(),
      device_limit: z.number(),
      groups: z.array(z.string()).default([]),
      disabled: z.boolean().default(false),
      expires: z.number().nullable().default(null),
      quota_bytes: z.number().nullable().default(null),
      traffic: z
        .object({ upload: z.number(), download: z.number() })
        .default({ upload: 0, download: 0 }),
      devices: z.array(
        z.object({
          id: z.string(),
          label: z.string(),
          expires: z.number().nullable(),
          connections: z.number().default(0),
        }),
      ),
    }),
  ),
});
export type ProxyAccess = z.infer<typeof proxyAccessSchema>;
export type ProxyAccessChange =
  | { action: 'settings'; enabled: boolean; ttl_seconds: number }
  | { action: 'create'; users: { username: string; password: string; device_limit?: number }[] }
  | { action: 'import'; users: z.infer<typeof proxyUsersSchema> }
  | { action: 'delete'; usernames: string[] }
  | { action: 'edit'; username: string; device_limit: number; password?: string }
  | {
      action: 'policy';
      username: string;
      disabled: boolean;
      expires: number | null;
      quota_bytes: number | null;
    }
  | { action: 'group-members'; group: string; usernames: string[] }
  | { action: 'reset-traffic'; username: string }
  | { action: 'create-device'; username: string; label: string }
  | { action: 'delete-device'; device: string };

export const versionsSchema = z.object({
  running: z.string(),
  lookup_failed: z.boolean(),
  releases: z.array(z.string()),
  proxy_access_enabled: z.boolean(),
  minimum_version: z.string().optional(),
  status: z
    .object({
      target: z.string(),
      finished: z.number().nullable(),
      ok: z.boolean().nullable(),
    })
    .nullable(),
});
export type VersionsView = z.infer<typeof versionsSchema>;
