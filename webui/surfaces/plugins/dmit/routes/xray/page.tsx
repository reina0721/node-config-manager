'use client';
import Link from 'next/link';
import { Section } from '@community-go/surface-foundation/layout';
import { XrayPage } from '../../src/console-pages';
import { useNodeText } from '../../src/common';
export default function Page() {
  const t = useNodeText();
  return (
    <XrayPage
      links={
        <Section title={t('xray.edit')} contentInset>
          <div className="flex flex-wrap gap-4 font-semibold text-brand">
            <Link href="/dmit/config">{t('nav.config')}</Link>
            <Link href="/dmit/inbounds">{t('nav.inbounds')}</Link>
            <Link href="/dmit/upstreams">{t('nav.upstreams')}</Link>
            <Link href="/dmit/rules">{t('nav.rules')}</Link>
          </div>
        </Section>
      }
    />
  );
}
