'use client';
import { lazy, Suspense } from 'react';
import { NodeLoading } from '../src/common';

const Overview = lazy(() => import('../src/overview-page'));

export default function Page() {
  return (
    <Suspense fallback={<NodeLoading />}>
      <Overview />
    </Suspense>
  );
}
