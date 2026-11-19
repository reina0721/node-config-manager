'use client';
import { lazy, Suspense, type ComponentProps } from 'react';
import { NodeLoading } from './common';

const CataloguePage = lazy(() => import('./catalogue-page'));

export default function CatalogueRoute(props: ComponentProps<typeof CataloguePage>) {
  return (
    <Suspense fallback={<NodeLoading kind="collection" />}>
      <CataloguePage {...props} />
    </Suspense>
  );
}
