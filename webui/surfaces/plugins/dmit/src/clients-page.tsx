'use client';
import { lazy, Suspense } from 'react';
import { useNodeManagement } from '../../../src/node-management';
import { NodePage, useNodeQuery, NodeLoading } from './common';
const ProxyAccessPanel = lazy(() => import('./proxy-access-panel'));

export default function ClientsPage() {
  const api = useNodeManagement();
  const access = useNodeQuery(api.proxyAccess, 15000);
  const config = useNodeQuery(api.panel);
  return (
    <NodePage
      name="clients"
      loading={access.loading || config.loading}
      refreshing={access.refreshing || config.refreshing}
      error={access.error || config.error}
      refresh={async () => {
        await Promise.all([access.refresh(), config.refresh()]);
      }}
    >
      {access.data && (
        <Suspense fallback={<NodeLoading kind="collection" />}>
          <ProxyAccessPanel
            data={access.data}
            subscriptions={config.data?.subscription_enabled ?? false}
            refresh={access.refresh}
          />
        </Suspense>
      )}
    </NodePage>
  );
}
