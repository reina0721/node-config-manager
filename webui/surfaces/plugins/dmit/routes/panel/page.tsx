'use client';
import { lazy, Suspense } from 'react';
import { Section } from '@community-go/surface-foundation/layout';
import { ConsoleLink, NodeLoading, useNodeText } from '../../src/common';
const PanelSettingsPage = lazy(() =>
  import('../../src/console-pages').then(({ PanelSettingsPage }) => ({
    default: PanelSettingsPage,
  })),
);

export default function Page() {
  const t = useNodeText();
  return (
    <Suspense fallback={<NodeLoading />}>
      <PanelSettingsPage
        links={
          <Section title={t('panel.settings')} contentInset>
            <div className="flex flex-wrap gap-4 font-semibold text-brand">
              <ConsoleLink to="dmit.clients">{t('access.title')}</ConsoleLink>
              <ConsoleLink to="dmit.nodes">{t('nodes.subscription')}</ConsoleLink>
              <a href="https://github.com/reina0721/node-config-manager">{t('panel.support')}</a>
            </div>
          </Section>
        }
      />
    </Suspense>
  );
}
