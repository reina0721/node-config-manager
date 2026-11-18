'use client';
import { lazy, Suspense, type ComponentProps } from 'react';
import { useNodeText } from './common';

const CataloguePage = lazy(() => import('./catalogue-page'));

export default function CatalogueRoute(props: ComponentProps<typeof CataloguePage>) {
  const t = useNodeText();
  return (
    <Suspense fallback={<p role="status">{t('common.loading')}</p>}>
      <CataloguePage {...props} />
    </Suspense>
  );
}
