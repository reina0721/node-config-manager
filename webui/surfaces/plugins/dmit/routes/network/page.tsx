'use client';
import { lazy, Suspense } from 'react';
import { NodeLoading } from '../../src/common';
const View = lazy(() => import('../../src/network-page'));

export default function Page() {
  return (
    <Suspense fallback={<NodeLoading kind="page" />}>
      <View />
    </Suspense>
  );
}
