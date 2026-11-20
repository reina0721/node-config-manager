import { z } from 'zod';
import {
  overviewSchema,
  configurationViewSchema,
  nodesViewSchema,
  networkViewSchema,
  dnsViewSchema,
  operationsViewSchema,
  proxyAccessSchema,
  proxyUsersSchema,
  versionsSchema,
  routingMatchSchema,
  fleetSchema,
  copySourceSchema,
  copyPreviewSchema,
  panelSchema,
  xrayViewSchema,
  planViewSchema,
  jobSchema,
  jobResultSchema,
  serviceSchema,
  adminFieldErrorSchema,
  type AdminFieldError,
  type NodeManagementPort,
  type ClientExportFormat,
  type ManagedJob,
  type JobResult,
} from '@community-go/surface/node-management';
const sessionSchema = z.object({ csrf: z.string() });
const taskSchema = z.object({ job: z.string() });
export class ApiError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly fields: readonly AdminFieldError[] = [],
  ) {
    super(message);
  }
}
export function createAdminApi(
  onUnauthorized: () => void,
  onJob: (job: ManagedJob) => void,
  onNode: (node: NodeManagementPort['selectedNode']) => void = () => {},
) {
  let csrf = '';
  let selected = 'local';
  async function request<T>(
    path: string,
    schema: z.ZodType<T>,
    body?: unknown,
    node = selected,
  ): Promise<T> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 180000);
    try {
      const response = await fetch('/nc/api/' + path, {
        method: body === undefined ? 'GET' : 'POST',
        credentials: 'same-origin',
        cache: 'no-store',
        headers: {
          ...(body === undefined
            ? {}
            : { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf }),
          ...(node === 'local' ? {} : { 'X-nodectl-node': node }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        signal: controller.signal,
      });
      let value: unknown;
      try {
        value = await response.json();
      } catch {
        throw new ApiError(
          'invalid_response',
          response.status === 413
            ? '配置请求超过 128 KiB 限制。'
            : 'API 返回了非 JSON 响应，请检查管理服务和 HTTPS 代理。',
        );
      }
      if (!response.ok) {
        const error = z
          .object({
            error: z.string(),
            message: z.string(),
            field_errors: z.array(adminFieldErrorSchema).optional(),
          })
          .safeParse(value);
        if (response.status === 401) {
          csrf = '';
          onUnauthorized();
        }
        throw new ApiError(
          error.success ? error.data.error : 'request_failed',
          error.success ? error.data.message : 'API 请求失败',
          error.success ? error.data.field_errors : undefined,
        );
      }
      return schema.parse(value);
    } finally {
      clearTimeout(timeout);
    }
  }
  async function watch(
    path: string,
    body: unknown,
    onAccepted?: () => void,
    node = selected,
  ): Promise<JobResult> {
    const task = await request(path, taskSchema, body, node);
    if (node === selected) {
      onJob({
        id: task.job,
        operation: path,
        phase: 'queued',
        started: Date.now() / 1000,
        finished: null,
        ok: null,
        result: null,
      });
    }
    onAccepted?.();
    for (;;) {
      const job = await request('jobs/' + task.job, jobSchema, undefined, node);
      const progressResult = job.result ? { ...job.result } : null;
      if (progressResult) delete progressResult.token;
      if (node === selected) onJob({ ...job, result: progressResult });
      if (job.finished !== null) {
        if (job.ok !== true)
          throw new ApiError(
            job.result?.error ?? 'operation_failed',
            job.result?.hint ?? job.result?.message ?? '操作失败，请检查事务和依赖状态。',
          );
        return job.result ?? jobResultSchema.parse({});
      }
      await new Promise<void>((resolve) => setTimeout(resolve, 1000));
    }
  }
  const port: Omit<NodeManagementPort, 'job' | 'selectedNode'> = {
    restoreBackup: (backup, token) => request('backups/preview', planViewSchema, { backup, token }),
    downloadClients,
    versions: () => request('versions', versionsSchema),
    proxyAccess: () => request('proxy-access', proxyAccessSchema),
    clientDetails: (id) =>
      request(
        'proxy-access/client-links/' + encodeURIComponent(id),
        z.object({
          links: z.array(z.string()),
          claim_url: z.string().nullable().default(null),
          bootstrap: z.object({
            nodectl: z.object({
              version: z.literal(1), origin: z.string(), client: z.uuid(),
              enrollment: z.uuid(), name: z.string(),
            }),
          }).nullable().default(null),
          bootstrap_unsupported: z.array(z.string()).default([]),
        }),
      ),
    downloadClientBootstrap: (config) =>
      download('nodectl-' + config.nodectl.client + '.yaml', 'application/yaml', JSON.stringify(config, null, 2) + '\n'),
    copyClientClaimLink: (url) => navigator.clipboard.writeText(url),
    newClaimRequest: () => crypto.randomUUID(),
    claimClient: async (id, claimRequest) => {
      const result = await request('proxy-access', proxyAccessSchema, {
        action: 'claim-client',
        id,
        request: claimRequest,
      });
      if (!result.created_device_id) throw new Error('后台未返回安装标识。');
      return result.created_device_id;
    },
    changeProxyAccess: (input) => request('proxy-access', proxyAccessSchema, input),
    downloadProxyUsers: async () => {
      const users = await request('proxy-access/export', proxyUsersSchema);
      download('nodectl-users.json', 'application/json', JSON.stringify(users, null, 2));
    },
    importProxyUsers: async () => {
      const file = await pickUserFile();
      if (!file) return null;
      if (file.size > 128 * 1024) throw new Error('用户文件超过 128 KiB。');
      const users = proxyUsersSchema.parse(JSON.parse(await file.text()));
      return request('proxy-access', proxyAccessSchema, { action: 'import', users });
    },
    downloadProxyProfile: async (device, format) => {
      const { content } = await request(
        'proxy-access/profile/' + encodeURIComponent(device) + '/' + format,
        z.object({ content: z.string() }),
      );
      if (format === 'subscriptions') {
        download('nodectl-device-subscriptions.json', 'application/json', content);
      } else if (format === 'xray-config') {
        download('nodectl-xray-client.json', 'application/json', content);
      } else {
        downloadClients(format, content);
      }
    },
    overview: () => request('overview', overviewSchema),
    configuration: () => request('config', configurationViewSchema),
    nodes: () => request('nodes', nodesViewSchema),
    network: () => request('network', networkViewSchema),
    dns: () => request('dns', dnsViewSchema),
    services: async () =>
      (await request('services', z.object({ services: z.array(serviceSchema) }))).services,
    operations: () => request('operations', operationsViewSchema),
    jobDetails: async (id, node) => {
      const job = await request('jobs/' + encodeURIComponent(id), jobSchema, undefined, node);
      if (job.result) delete job.result.token;
      return job;
    },
    unlock: async (token) =>
      (await request('unlock', z.object({ unlock: z.string() }), { token })).unlock,
    preview: (config, unlock) =>
      request('config/preview', planViewSchema, { config, ...(unlock ? { unlock } : {}) }),
    previewCatalogue: (edit, base) =>
      request('catalogue/preview', planViewSchema, { ...edit, base }),
    matchRoute: (input) => request('routing/match', routingMatchSchema, input),
    testUpstream: (id) => watch('outbounds/test', { id }),
    fleet: () => request('fleet', fleetSchema, undefined, 'local'),
    copySource: (node) => request('catalogue/copy-source', copySourceSchema, undefined, node),
    previewCopy: (input) => request('fleet/copy-preview', copyPreviewSchema, input, 'local'),
    panel: () => request('panel', panelSchema),
    xray: () => request('xray', xrayViewSchema),
    openApi: () => request('openapi', z.record(z.string(), z.unknown())),
    registerPeer: async (registration) => {
      await request('fleet/register', z.object({ id: z.string() }), registration, 'local');
    },
    grantPeer: async (grant) =>
      (await request('fleet/grant', z.object({ token: z.string() }), grant, 'local')).token,
    removePeer: async (id, grant) => {
      await request('fleet/remove', z.object({ ok: z.boolean() }), { id, grant }, 'local');
    },
    selectNode: (id, name) => {
      selected = id;
      onNode({ id, name });
    },
    check: (plan, node) => watch('config/check', { plan }, undefined, node),
    prepareDeployment: (plan, options) => watch('config/deploy-preview', { plan, options }),
    apply: (plan, confirm, node) => watch('config/apply', { plan, confirm }, undefined, node),
    operate: (input, onAccepted) => watch('operations', input, onAccepted),
    credentials: async (zone, token) => {
      await request('credentials', z.object({ saved: z.boolean() }), { zone, token });
    },
    exportClients: async (format) =>
      (await request('clients/' + format, z.object({ content: z.string() }))).content,
  };
  return {
    port,
    session: async () => {
      const s = await request('session', sessionSchema, undefined, 'local');
      csrf = s.csrf;
    },
    login: async (token: string) => {
      selected = 'local';
      onNode({ id: 'local', name: '' });
      const s = await request('login', sessionSchema, { token }, 'local');
      csrf = s.csrf;
    },
    logout: async () => {
      await request('logout', z.object({ ok: z.boolean() }), {}, 'local');
      csrf = '';
      onUnauthorized();
    },
  };
}

function download(name: string, type: string, content: string) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function downloadClients(format: ClientExportFormat, content: string) {
  const xray = format === 'xray';
  download(
    xray ? 'nodectl-xray.json' : 'nodectl-' + format + '.yaml',
    xray ? 'application/json' : 'text/yaml',
    content,
  );
}

function pickUserFile() {
  return new Promise<File | null>((resolve) => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json,application/json';
    input.addEventListener('change', () => resolve(input.files?.item(0) ?? null), { once: true });
    input.addEventListener('cancel', () => resolve(null), { once: true });
    input.click();
  });
}
