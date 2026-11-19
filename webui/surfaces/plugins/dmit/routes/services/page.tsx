'use client';
import { lazy, Suspense } from 'react';
import { NodeLoading } from '../../src/common';
const View = lazy(() => import('../../src/services-page'));

export default function Page() {
  return (
    <Suspense fallback={<NodeLoading kind="collection" />}>
      <View />
    </Suspense>
  );
}
