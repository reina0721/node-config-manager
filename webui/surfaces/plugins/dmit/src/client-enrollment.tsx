'use client';

import { useCallback, useState } from 'react';
import { Action } from '@community-go/ui-adapter/action';
import { AlertBanner } from '@community-go/ui-adapter/feedback';
import { useNodeManagement, type ProxyAccess } from '../../../src/node-management';
import { EditorDrawer } from './collection-controls';
import { useNodeQuery, useNodeText } from './common';

export default function ClientEnrollment({
  client,
  available,
  onClose,
}: {
  client: ProxyAccess['clients'][number];
  available: boolean;
  onClose: () => void;
}) {
  const api = useNodeManagement();
  const t = useNodeText();
  const loadDetails = useCallback(() => api.clientDetails(client.id), [api, client.id]);
  const details = useNodeQuery(loadDetails);
  const url = details.data?.claim_url;
  const unsupported = details.data?.bootstrap_unsupported.join('、');
  const [busy, setBusy] = useState<'mihomo' | 'xray' | 'subscriptions'>();
  const [device, setDevice] = useState<string>();
  const [claimRequest, setClaimRequest] = useState(api.newClaimRequest);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
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
      {!available && <p>{t('sharedClients.claimDependency')}</p>}
      {available && !client.claim_enabled && <p>{t('sharedClients.claimOff')}</p>}
      {available && details.data?.bootstrap && (
        <div className="grid gap-2">
          <p>{t('sharedClients.publicFileHint')}</p>
          <div>
            <Action onPress={() => {
              const config = details.data?.bootstrap;
              if (config) api.downloadClientBootstrap(config);
            }}>
              {t('sharedClients.publicFile')}
            </Action>
          </div>
        </div>
      )}
      {available && unsupported && (
        <AlertBanner icon="!" tone="danger" title={t('sharedClients.publicFileUnsupported')}
          description={unsupported} />
      )}
      {available && url && (
        <details open={details.data?.bootstrap ? undefined : true}>
          <summary className="cursor-pointer font-semibold">{t('sharedClients.personalDownloads')}</summary>
          <div className="mt-3 grid min-w-0 gap-2">
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
          <div className="mt-3 flex flex-wrap gap-2">
            <Action
              disabled={busy !== undefined && busy !== 'mihomo'}
              loading={busy === 'mihomo'}
              onPress={() => void download('mihomo')}
            >
              {t('sharedClients.claimMihomo')}
            </Action>
            <Action
              variant="secondary"
              disabled={busy !== undefined && busy !== 'xray'}
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
        </details>
      )}
      {message && <p role="status">{message}</p>}
    </EditorDrawer>
  );
}
