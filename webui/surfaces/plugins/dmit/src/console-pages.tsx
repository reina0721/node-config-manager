'use client';
import type { ReactNode } from 'react';
import { Section } from '@community-go/surface-foundation/layout';
import { useNodeManagement } from '../../../src/node-management';
import { ProxyAccessSettings } from './proxy-access-settings';
import { Code, Details, NodePage, useNodeQuery, useNodeText } from './common';

export function PanelSettingsPage({ links }: { links: ReactNode }) {
  const api = useNodeManagement();
  const q = useNodeQuery(api.panel);
  const t = useNodeText();
  const enabled = (value: boolean) => t(value ? 'common.enabled' : 'common.disabled');
  return (
    <NodePage
      name="panel"
      loading={q.loading}
      refreshing={q.refreshing}
      error={q.error}
      refresh={q.refresh}
    >
      {q.data && (
        <>
          <ProxyAccessSettings
            enabled={q.data.browser_access}
            ttl={q.data.browser_ttl}
            refresh={q.refresh}
          />
          <Section title={t('panel.session')} contentInset>
            <div className="grid gap-4">
              <Details
                label={t('panel.session')}
                items={[
                  [t('panel.credential'), enabled(q.data.administrator_configured)],
                  [t('panel.lifetime'), q.data.session_lifetime + ' s'],
                  [t('panel.idle'), q.data.session_idle_timeout + ' s'],
                ]}
              />
              <p className="text-sm text-ink-muted">{t('panel.rotation')}</p>
              <Code>sudo nodectl admin reset-token</Code>
            </div>
          </Section>
          <Section title={t('panel.authorization')} contentInset>
            <Details
              label={t('panel.authorization')}
              items={[
                [t('nodes.subscription'), enabled(q.data.subscription_enabled)],
                [t('nodes.status'), q.data.subscription_access],
              ]}
            />
          </Section>
        </>
      )}
      {links}
    </NodePage>
  );
}

export function XrayPage({ links }: { links: ReactNode }) {
  const api = useNodeManagement();
  const q = useNodeQuery(api.xray);
  const t = useNodeText();
  return (
    <NodePage
      name="xray"
      loading={q.loading}
      refreshing={q.refreshing}
      error={q.error}
      refresh={q.refresh}
    >
      {links}
      {q.data && (
        <Section title={t('xray.redacted')} description={q.data.release} contentInset>
          <Details
            label={t('xray.redacted')}
            items={[
              ['VLESS', t(q.data.encrypted ? 'common.enabled' : 'common.disabled')],
              [t('access.title'), t(q.data.browser_access ? 'common.enabled' : 'common.disabled')],
              [t('nav.rules'), t(q.data.managed_routing ? 'common.enabled' : 'common.disabled')],
            ]}
          />
          <details className="mt-4">
            <summary className="cursor-pointer font-medium">{t('console.showPreview')}</summary>
            <Code>{JSON.stringify(q.data.configuration, null, 2)}</Code>
          </details>
        </Section>
      )}
    </NodePage>
  );
}

export function ApiPage() {
  const api = useNodeManagement();
  const q = useNodeQuery(api.openApi);
  const t = useNodeText();
  return (
    <NodePage
      name="api"
      loading={q.loading}
      refreshing={q.refreshing}
      error={q.error}
      refresh={q.refresh}
    >
      <Section title={t('api.authentication')} description={t('api.authDescription')} contentInset>
        <Code>{`GET /nc/api/session
POST /nc/api/catalogue/preview
Content-Type: application/json
X-CSRF-Token: <csrf>
Origin: https://<测速域名>

{"kind":"group","value":{"name":"demo","description":"","enabled":true,"inbounds":[],"hosts":[]}}`}</Code>
      </Section>
      <Section title={t('api.tasks')} description={t('api.taskDescription')} contentInset>
        <Code>{`POST /nc/api/config/check
{"plan":"<plan>"}

GET /nc/api/jobs/<job>
{"finished":null,"phase":"check","ok":null}`}</Code>
      </Section>
      {q.data && (
        <Section title="OpenAPI 3.1" contentInset>
          <details>
            <summary className="cursor-pointer font-medium">{t('console.viewDetails')}</summary>
            <Code>{JSON.stringify(q.data, null, 2)}</Code>
          </details>
        </Section>
      )}
    </NodePage>
  );
}
