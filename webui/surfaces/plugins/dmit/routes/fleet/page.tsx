'use client';
import { lazy, Suspense } from 'react';
import { NodeLoading } from '../../src/common';

const FleetPage = lazy(() => import('../../src/fleet-page'));

export default function Page() {
  return (
    <Suspense fallback={<NodeLoading />}>
      <FleetPage />
    </Suspense>
  );
}
