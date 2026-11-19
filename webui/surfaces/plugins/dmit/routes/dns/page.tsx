'use client';
import { lazy, Suspense } from 'react';
import { NodeLoading } from '../../src/common';

const Dns = lazy(() => import('../../src/dns-page'));

export default function Page() {
  return (
    <Suspense fallback={<NodeLoading />}>
      <Dns />
    </Suspense>
  );
}
