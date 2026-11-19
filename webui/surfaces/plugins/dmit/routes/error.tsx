'use client';
import { useFrontendTranslation } from '@community-go/i18n';
import { AlertBanner } from '@community-go/ui-adapter/feedback';

export default function RouteError({ reset }: Readonly<{ reset: () => void }>) {
  const { t } = useFrontendTranslation();
  return (
    <AlertBanner
      icon="!"
      tone="danger"
      title={t('dmit.common.error')}
      description={t('dmit.console.routeError')}
      actionLabel={t('dmit.common.retry')}
      onAction={reset}
      announcement="urgent"
    />
  );
}
