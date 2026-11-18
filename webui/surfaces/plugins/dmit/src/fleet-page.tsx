'use client';
import { useState } from 'react';
import { Section } from '@community-go/surface-foundation/layout';
import { Action } from '@community-go/ui-adapter/action';
import { DataTable } from '@community-go/ui-adapter/data-display';
import { AlertBanner } from '@community-go/ui-adapter/feedback';
import { PasswordField, SelectField, TextField } from '@community-go/ui-adapter/form-field';
import { ConfirmDialog } from '@community-go/ui-adapter/overlays';
import { useNodeManagement, type PeerGrant } from '../../../src/node-management';
import { Code, Details, NodePage, Timestamp, useNodeQuery, useNodeText } from './common';

export default function FleetPage() {
  const api = useNodeManagement();
  const fleet = useNodeQuery(api.fleet, 15000);
  const status = useNodeQuery(api.overview);
  const t = useNodeText();
  const label = (key: string) => t('fleet.' + key);
  const [name, setName] = useState('');
  const [hostname, setHostname] = useState('');
  const [address, setAddress] = useState('');
  const [port, setPort] = useState('9443');
  const [token, setToken] = useState('');
  const [grantName, setGrantName] = useState('');
  const [scope, setScope] = useState<PeerGrant['scope']>('read');
  const [issued, setIssued] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const mutate = async (request: () => Promise<unknown>) => {
    setError('');
    setBusy(true);
    try {
      await request();
      await fleet.refresh();
      await status.refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      throw e;
    } finally {
      setBusy(false);
    }
  };
  const confirm = (
    title: string,
    description: string,
    request: () => Promise<void>,
    disabled = false,
  ) => (
    <ConfirmDialog
      triggerLabel={title}
      title={title}
      description={description}
      impact={null}
      cancelLabel={t('common.cancel')}
      confirmLabel={title}
      failureMessage={t('common.failed')}
      confirmDisabled={busy || disabled}
      onConfirm={request}
    />
  );
  return (
    <NodePage
      name="fleet"
      loading={fleet.loading || status.loading}
      error={fleet.error || status.error}
      refresh={async () => {
        await Promise.all([fleet.refresh(), status.refresh()]);
      }}
    >
      {error && (
        <AlertBanner icon="!" tone="danger" title={t('common.failed')} description={error} />
      )}
      {fleet.data && (
        <>
          <Section title={label('targets')} contentInset>
            <div className="grid gap-4">
              <SelectField
                label={label('selected')}
                value={api.selectedNode.id}
                options={[
                  { value: 'local', label: fleet.data.local.hostname ?? label('local') },
                  ...fleet.data.peers.map((peer) => ({ value: peer.id, label: peer.name })),
                ]}
                onValueChange={(id) =>
                  api.selectNode(id, fleet.data?.peers.find((peer) => peer.id === id)?.name ?? '')
                }
              />
              {status.data && (
                <Details
                  label={label('selected')}
                  items={[
                    [label('version'), status.data.version],
                    [label('hostname'), status.data.domain ?? t('common.unavailable')],
                    [
                      label('integrity'),
                      t(status.data.integrity ? 'common.complete' : 'common.failed'),
                    ],
                  ]}
                />
              )}
            </div>
          </Section>
          <Section title={label('peers')}>
            <DataTable
              label={label('peers')}
              rows={fleet.data.peers}
              emptyContent={t('common.empty')}
              columns={[
                { id: 'name', label: label('name'), rowHeader: true, render: (peer) => peer.name },
                {
                  id: 'address',
                  label: label('address'),
                  render: (peer) => peer.hostname + ':' + peer.port + ' · ' + peer.address,
                },
                {
                  id: 'seen',
                  label: label('seen'),
                  render: (peer) => (
                    <span>
                      <Timestamp value={peer.last_seen} /> {peer.stale ? label('stale') : ''}
                    </span>
                  ),
                },
                {
                  id: 'remove',
                  label: t('access.actions'),
                  render: (peer) =>
                    confirm(label('remove'), label('removeHint'), () =>
                      mutate(async () => {
                        await api.removePeer(peer.id, false);
                        if (api.selectedNode.id === peer.id) api.selectNode('local', '');
                      }),
                    ),
                },
              ]}
            />
          </Section>
          <Section title={label('register')} description={label('registerHint')} contentInset>
            <div className="grid gap-4">
              <TextField
                label={label('name')}
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
              <TextField
                label={label('hostname')}
                value={hostname}
                onChange={(e) => setHostname(e.target.value)}
              />
              <TextField
                label={label('address')}
                value={address}
                onChange={(e) => setAddress(e.target.value)}
              />
              <TextField
                label={t('catalogue.port')}
                value={port}
                onChange={(e) => setPort(e.target.value)}
              />
              <PasswordField
                purpose="current"
                showLabel={t('common.show')}
                hideLabel={t('common.hide')}
                label={label('token')}
                value={token}
                onChange={(e) => setToken(e.target.value)}
              />
              <div>
                {confirm(
                  label('register'),
                  label('registerHint'),
                  () =>
                    mutate(async () => {
                      await api.registerPeer({
                        name,
                        hostname,
                        address,
                        port: Number(port),
                        token,
                      });
                      setToken('');
                    }),
                  !name || !hostname || !address || token.length !== 64,
                )}
              </div>
            </div>
          </Section>
          <Section title={label('grants')} description={label('grantHint')} contentInset>
            <div className="grid gap-4">
              <TextField
                label={label('name')}
                value={grantName}
                onChange={(e) => setGrantName(e.target.value)}
              />
              <SelectField
                label={label('scope')}
                options={[
                  { value: 'read', label: label('read') },
                  { value: 'manage', label: label('manage') },
                ]}
                value={scope}
                onValueChange={(value) => setScope(value === 'manage' ? 'manage' : 'read')}
              />
              <div>
                {confirm(
                  label('grant'),
                  label('grantHint'),
                  () =>
                    mutate(async () => {
                      setIssued(await api.grantPeer({ name: grantName, scope }));
                    }),
                  !grantName.trim(),
                )}
              </div>
              {issued && (
                <>
                  <Code>{issued}</Code>
                  <div>
                    <Action variant="secondary" onPress={() => setIssued('')}>
                      {t('common.hide')}
                    </Action>
                  </div>
                </>
              )}
              <DataTable
                label={label('grants')}
                rows={fleet.data.grants}
                emptyContent={t('common.empty')}
                columns={[
                  {
                    id: 'name',
                    label: label('name'),
                    rowHeader: true,
                    render: (grant) => grant.name,
                  },
                  { id: 'scope', label: label('scope'), render: (grant) => label(grant.scope) },
                  {
                    id: 'remove',
                    label: t('access.actions'),
                    render: (grant) =>
                      confirm(label('revoke'), label('revokeHint'), () =>
                        mutate(() => api.removePeer(grant.id, true)),
                      ),
                  },
                ]}
              />
            </div>
          </Section>
        </>
      )}
    </NodePage>
  );
}
