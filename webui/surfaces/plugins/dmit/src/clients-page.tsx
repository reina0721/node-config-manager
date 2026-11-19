'use client';
import { lazy, Suspense } from 'react';
import { TabsView } from '@community-go/ui-adapter/data-display';
import { useNodeManagement } from '../../../src/node-management';
import { NodePage, useNodeQuery, NodeLoading, useNodeText } from './common';
const ProxyAccessPanel = lazy(() => import('./proxy-access-panel'));
const SharedClients = lazy(() => import('./shared-clients'));

export default function ClientsPage() {
  const api = useNodeManagement();
  const t = useNodeText();
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
          <TabsView
            label={t('clients.title')}
            variant="section"
            items={[
              {
                id: 'users',
                label: t('sharedClients.usersTab'),
                content: (
                  <ProxyAccessPanel
                    data={access.data}
                    subscriptions={config.data?.subscription_enabled ?? false}
                    refresh={access.refresh}
                  />
                ),
              },
              {
                id: 'definitions',
                label: t('sharedClients.definitionsTab'),
                content: <SharedClients data={access.data} refresh={access.refresh} />,
              },
            ]}
          />
        </Suspense>
      )}
    </NodePage>
  );
}
