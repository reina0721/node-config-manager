'use client';
import { useFrontendTranslation } from '@community-go/i18n';
import { PageLoadingSurface } from '@community-go/surface-foundation/states-operations';

export default function Loading() {
  const { t } = useFrontendTranslation();
  return <PageLoadingSurface label={t('dmit.common.loading')} />;
}
