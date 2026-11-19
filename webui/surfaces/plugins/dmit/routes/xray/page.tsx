'use client';
import { lazy, Suspense } from 'react';
import { Section } from '@community-go/surface-foundation/layout';
import { ConsoleLink, NodeLoading, useNodeText } from '../../src/common';
const XrayPage = lazy(() =>
  import('../../src/console-pages').then(({ XrayPage }) => ({ default: XrayPage })),
);

export default function Page() {
  const t = useNodeText();
  return (
    <Suspense fallback={<NodeLoading />}>
      <XrayPage
        links={
          <Section title={t('xray.edit')} contentInset>
            <div className="flex flex-wrap gap-4 font-semibold text-brand">
              <ConsoleLink to="dmit.config">{t('nav.config')}</ConsoleLink>
              <ConsoleLink to="dmit.inbounds">{t('nav.inbounds')}</ConsoleLink>
              <ConsoleLink to="dmit.upstreams">{t('nav.upstreams')}</ConsoleLink>
              <ConsoleLink to="dmit.rules">{t('nav.rules')}</ConsoleLink>
            </div>
          </Section>
        }
      />
    </Suspense>
  );
}
