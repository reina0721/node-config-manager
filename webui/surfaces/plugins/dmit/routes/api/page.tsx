'use client';
import { lazy, Suspense } from 'react';
import { NodeLoading } from '../../src/common';
const ApiPage = lazy(() =>
  import('../../src/console-pages').then(({ ApiPage }) => ({ default: ApiPage })),
);

export default function Page() {
  return (
    <Suspense fallback={<NodeLoading />}>
      <ApiPage />
    </Suspense>
  );
}
