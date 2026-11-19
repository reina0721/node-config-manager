'use client';
import { useState } from 'react';
import { Section } from '@community-go/surface-foundation/layout';
import { Action } from '@community-go/ui-adapter/action';
import { AlertBanner, Badge } from '@community-go/ui-adapter/feedback';
import { TextField } from '@community-go/ui-adapter/form-field';
import { ConfirmDialog } from '@community-go/ui-adapter/overlays';
import { useNodeManagement } from '../../../src/node-management';
import { useNodeText } from './common';

export function ProxyAccessSettings({
  enabled,
  ttl,
  refresh,
}: Readonly<{ enabled: boolean; ttl: number; refresh: () => Promise<void> }>) {
  const api = useNodeManagement();
  const t = useNodeText();
  const [draft, setDraft] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [saved, setSaved] = useState(false);
  const seconds = Number(draft ?? ttl);
  const invalid = !Number.isInteger(seconds) || seconds < 60 || seconds > 90 * 86400;
  const toggleLabel = t(enabled ? 'access.disable' : 'access.enable');

  async function save(nextEnabled: boolean) {
    setBusy(true);
    setSaved(false);
    setError('');
    try {
      await api.changeProxyAccess({
        action: 'settings',
        enabled: nextEnabled,
        ttl_seconds: seconds,
      });
      setDraft(undefined);
      setSaved(true);
      await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
      throw cause;
    } finally {
      setBusy(false);
    }
  }

  return (
    <Section
      title={t('access.title')}
      contentInset
      action={
        <Badge tone={enabled ? 'success' : 'neutral'}>
          {t(enabled ? 'common.enabled' : 'common.disabled')}
        </Badge>
      }
    >
      <div className="grid gap-4">
        <TextField
          label={t('access.ttl')}
          hint={t('access.ttlHint')}
          error={invalid ? t('console.ttlError') : ''}
          value={draft ?? String(ttl)}
          disabled={busy}
          onChange={(event) => {
            setDraft(event.target.value);
            setSaved(false);
          }}
        />
        <div className="flex flex-wrap items-center gap-3">
          <Action
            loading={busy}
            disabled={invalid || seconds === ttl || busy}
            onPress={() => {
              void save(enabled).catch(() => undefined);
            }}
          >
            {t('access.save')}
          </Action>
          <ConfirmDialog
            triggerLabel={toggleLabel}
            title={toggleLabel}
            description={t(enabled ? 'access.disableRisk' : 'access.enableRisk')}
            impact={null}
            cancelLabel={t('common.cancel')}
            confirmLabel={toggleLabel}
            confirmDisabled={invalid || busy}
            failureMessage={t('common.failed')}
            onConfirm={() => save(!enabled)}
          />
          {saved && <p role="status">{t('access.saved')}</p>}
        </div>
        {error && (
          <AlertBanner icon="!" tone="danger" title={t('common.failed')} description={error} />
        )}
      </div>
    </Section>
  );
}
