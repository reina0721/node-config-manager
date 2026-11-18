'use client';
import Link from 'next/link';
import { Section } from '@community-go/surface-foundation/layout';
import { PanelSettingsPage } from '../../src/console-pages';
import { useNodeText } from '../../src/common';
export default function Page() {
  const t = useNodeText();
  return (
    <PanelSettingsPage
      links={
        <Section title={t('panel.settings')} contentInset>
          <div className="flex flex-wrap gap-4 font-semibold text-brand">
            <Link href="/dmit/clients">{t('access.title')}</Link>
            <Link href="/dmit/nodes">{t('nodes.subscription')}</Link>
            <a href="https://github.com/reina0721/node-config-manager">{t('panel.support')}</a>
          </div>
        </Section>
      }
    />
  );
}
