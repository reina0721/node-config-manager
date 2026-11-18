'use client';
import { lazy, Suspense } from 'react';
import { useNodeText } from '../../src/common';

const FleetPage = lazy(() => import('../../src/fleet-page'));

export default function Page() {
  const t = useNodeText();
  return (
    <Suspense fallback={<p role="status">{t('common.loading')}</p>}>
      <FleetPage />
    </Suspense>
  );
}
