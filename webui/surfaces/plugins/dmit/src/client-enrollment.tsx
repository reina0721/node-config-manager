'use client';

import { useCallback, useState } from 'react';
import { Action } from '@community-go/ui-adapter/action';
import { AlertBanner } from '@community-go/ui-adapter/feedback';
import { TextField } from '@community-go/ui-adapter/form-field';
import { ConfirmDialog } from '@community-go/ui-adapter/overlays';
import { useNodeManagement, type ProxyAccess } from '../../../src/node-management';
import { EditorDrawer } from './collection-controls';
import { useNodeQuery, useNodeText } from './common';

export default function ClientEnrollment({
  client,
  available,
  refresh,
  onClose,
}: {
  client: ProxyAccess['clients'][number];
  available: boolean;
  refresh: () => Promise<void>;
  onClose: () => void;
}) {
  const api = useNodeManagement();
  const t = useNodeText();
  const loadDetails = useCallback(() => api.clientDetails(client.id), [api, client.id]);
  const details = useNodeQuery(loadDetails);
  const url = details.data?.claim_url;
  const [count, setCount] = useState('8');
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState<'mihomo' | 'xray' | 'subscriptions'>();
  const [device, setDevice] = useState<string>();
  const [claimRequest, setClaimRequest] = useState(api.newClaimRequest);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const validCount = /^\d{1,2}$/.test(count) && Number(count) >= 1 && Number(count) <= 32;

  const prepare = async () => {
    setError('');
    try {
      await api.changeProxyAccess({
        action: 'prepare-client',
        id: client.id,
        count: Number(count),
      });
      await Promise.all([details.refresh(), refresh()]);
      setConfirm(false);
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : String(cause);
      setError(message);
      throw cause;
    }
  };

  const download = async (format: 'mihomo' | 'xray' | 'subscriptions') => {
    if (!available || !url || busy) return;
    setBusy(format);
    setError('');
    setMessage('');
    try {
      const installation = device ?? (await api.claimClient(client.id, claimRequest));
      setDevice(installation);
      await api.downloadProxyProfile(
        installation,
        format === 'mihomo' ? 'mihomo-weighted' : format === 'xray' ? 'xray-config' : format,
      );
      setMessage(t('sharedClients.claimHint'));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      await refresh();
      setBusy(undefined);
    }
  };

  return (
    <EditorDrawer
      title={t('sharedClients.enrollment')}
      description={client.name}
      dirty={false}
      busy={Boolean(busy)}
      onClose={onClose}
    >
      {(error || details.error) && (
        <AlertBanner
          icon="!"
          tone="danger"
          title={t('common.failed')}
          description={error || details.error}
        />
      )}
      <p>
        {t('sharedClients.remainingClaims')} · {client.claim_remaining}
      </p>
      {!available && <p>{t('sharedClients.claimDependency')}</p>}
      {available && !client.claim_enabled && <p>{t('sharedClients.claimOff')}</p>}
      {available && url && (
        <>
          <div className="grid min-w-0 gap-2">
            <p>{t('sharedClients.claimLink')}</p>
            <code className="break-all select-all text-sm">{url}</code>
            <div>
              <Action
                variant="secondary"
                onPress={() =>
                  void api.copyClientClaimLink(url).then(
                    () => setMessage(t('sharedClients.copiedClaim')),
                    () => setMessage(t('sharedClients.copyClaimError')),
                  )
                }
              >
                {t('sharedClients.copyClaim')}
              </Action>
            </div>
          </div>
          {!client.claim_remaining && !device && <p>{t('sharedClients.claimEmpty')}</p>}
          <div className="flex flex-wrap gap-2">
            <Action
              disabled={
                (!device && !client.claim_remaining) || (busy !== undefined && busy !== 'mihomo')
              }
              loading={busy === 'mihomo'}
              onPress={() => void download('mihomo')}
            >
              {t('sharedClients.claimMihomo')}
            </Action>
            <Action
              variant="secondary"
              disabled={
                (!device && !client.claim_remaining) || (busy !== undefined && busy !== 'xray')
              }
              loading={busy === 'xray'}
              onPress={() => void download('xray')}
            >
              {t('sharedClients.claimXray')}
            </Action>
            {device && (
              <>
                <Action
                  variant="secondary"
                  disabled={busy !== undefined && busy !== 'subscriptions'}
                  loading={busy === 'subscriptions'}
                  onPress={() => void download('subscriptions')}
                >
                  {t('access.downloadSubscriptions')}
                </Action>
                <Action
                  variant="secondary"
                  disabled={Boolean(busy)}
                  onPress={() => {
                    setDevice(undefined);
                    setClaimRequest(api.newClaimRequest());
                    setMessage('');
                  }}
                >
                  {t('sharedClients.claimNext')}
                </Action>
              </>
            )}
          </div>
        </>
      )}
      {message && <p role="status">{message}</p>}
      <div className="grid gap-3 border-t border-border pt-4">
        <TextField
          label={t('sharedClients.claimCount')}
          value={count}
          disabled={!available || Boolean(busy)}
          onChange={(event) => setCount(event.target.value)}
        />
        <div>
          <Action
            variant="secondary"
            disabled={!available || !validCount || Boolean(busy)}
            onPress={() => setConfirm(true)}
          >
            {t('sharedClients.prepareClaims')}
          </Action>
        </div>
      </div>
      <ConfirmDialog
        isOpen={confirm}
        onOpenChange={setConfirm}
        triggerLabel={t('sharedClients.prepareClaims')}
        title={t('sharedClients.prepareClaims')}
        description={t('sharedClients.confirmPrepare')}
        impact={client.name + ' · ' + count}
        cancelLabel={t('common.cancel')}
        confirmLabel={t('common.confirm')}
        failureMessage={error || t('common.failed')}
        onConfirm={prepare}
      />
    </EditorDrawer>
  );
}
