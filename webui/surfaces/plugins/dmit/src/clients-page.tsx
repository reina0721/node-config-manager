'use client';
import { lazy, Suspense } from 'react';
import { useNodeManagement } from '../../../src/node-management';
import { NodePage, JobProgress, useNodeQuery, useNodeText } from './common';
const ProxyAccessPanel = lazy(() => import('./proxy-access-panel'));

export default function ClientsPage() {
  const t = useNodeText();
  const api = useNodeManagement();
  const access = useNodeQuery(api.proxyAccess, 15000);
  const config = useNodeQuery(api.configuration);
  return (
    <NodePage
      name="clients"
      loading={access.loading || config.loading}
      error={access.error || config.error}
      refresh={async () => {
        await Promise.all([access.refresh(), config.refresh()]);
      }}
    >
      <JobProgress />
      {access.data && (
        <Suspense fallback={<p role="status">{t('common.loading')}</p>}>
          <ProxyAccessPanel
            data={access.data}
            subscriptions={config.data?.config.distribution?.enabled ?? false}
            refresh={access.refresh}
          />
        </Suspense>
      )}
    </NodePage>
  );
}
