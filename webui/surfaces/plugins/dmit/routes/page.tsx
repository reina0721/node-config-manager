'use client';
import { lazy, Suspense } from 'react';
import { useNodeText } from '../src/common';

const Overview = lazy(() => import('../src/overview-page'));

export default function Page() {
  const t = useNodeText();
  return (
    <Suspense fallback={<p role="status">{t('common.loading')}</p>}>
      <Overview />
    </Suspense>
  );
}
