'use client';
import { lazy, Suspense } from 'react';
import { NodeLoading } from '../../src/common';

const Operations = lazy(() => import('../../src/operations-page'));

export default function Page() {
  return (
    <Suspense fallback={<NodeLoading />}>
      <Operations />
    </Suspense>
  );
}
