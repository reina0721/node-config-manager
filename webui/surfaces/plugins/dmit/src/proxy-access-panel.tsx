'use client';
import { useState } from 'react';
import { Section } from '@community-go/surface-foundation/layout';
import { Action } from '@community-go/ui-adapter/action';
import { DataTable } from '@community-go/ui-adapter/data-display';
import { AlertBanner } from '@community-go/ui-adapter/feedback';
import { PasswordField, TextField } from '@community-go/ui-adapter/form-field';
import { ConfirmDialog } from '@community-go/ui-adapter/overlays';
import {
  useNodeManagement,
  type ProxyAccess,
  type ProxyAccessChange,
} from '../../../src/node-management';
import { Details, Timestamp, useNodeText } from './common';

type User = ProxyAccess['users'][number];
type NewUser = Extract<ProxyAccessChange, { action: 'create' }>['users'][number];
type DeviceFormat = 'xray' | 'mihomo' | 'subscriptions';
type Confirm = Readonly<{ label: string; description: string; change: ProxyAccessChange }>;

export default function ProxyAccessPanel({
  data,
  subscriptions,
  refresh,
}: Readonly<{ data: ProxyAccess; subscriptions: boolean; refresh: () => Promise<void> }>) {
  const api = useNodeManagement();
  const t = useNodeText();
  const [ttl, setTtl] = useState<string>();
  const [selected, setSelected] = useState<string[]>([]);
  const [editing, setEditing] = useState<string>();
  const [confirm, setConfirm] = useState<Confirm | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [saved, setSaved] = useState(false);
  const [bulk, setBulk] = useState<NewUser[]>([]);
  const user = data.users.find((candidate) => candidate.username === editing);
  const selectedUsers = data.users.filter((user) => selected.includes(user.username));
  const seconds = Number(ttl ?? data.ttl_seconds);
  const validTtl = Number.isInteger(seconds) && seconds >= 60 && seconds <= 90 * 86400;

  const perform = async (request: () => Promise<unknown>, mutation = true) => {
    setBusy(true);
    setError('');
    setSaved(false);
    try {
      const result = await request();
      if (mutation && result !== null) {
        setSaved(true);
        await refresh();
      }
      return true;
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return false;
    } finally {
      setBusy(false);
    }
  };
  const change = (input: ProxyAccessChange) => perform(() => api.changeProxyAccess(input));

  return (
    <Section title={t('access.title')} description={t('access.description')} contentInset>
      <div className="grid gap-5">
        <Details
          label={t('access.title')}
          items={[
            [t('nodes.status'), t(data.enabled ? 'common.enabled' : 'common.disabled')],
            [
              t('access.portal'),
              <code key="portal" className="break-all">
                {data.portal}
              </code>,
            ],
          ]}
        />
        <div className="grid gap-3">
          <TextField
            label={t('access.ttl')}
            hint={t('access.ttlHint')}
            value={ttl ?? String(data.ttl_seconds)}
            onChange={(e) => setTtl(e.target.value)}
          />
          <div className="flex flex-wrap gap-3">
            <Action
              variant="secondary"
              disabled={busy || !validTtl || seconds === data.ttl_seconds}
              onPress={() => {
                void change({ action: 'settings', enabled: data.enabled, ttl_seconds: seconds });
              }}
            >
              {t('access.save')}
            </Action>
            <Action
              variant="secondary"
              disabled={busy || !validTtl}
              onPress={() =>
                setConfirm({
                  label: t(data.enabled ? 'access.disable' : 'access.enable'),
                  description: t(data.enabled ? 'access.disableRisk' : 'access.enableRisk'),
                  change: { action: 'settings', enabled: !data.enabled, ttl_seconds: seconds },
                })
              }
            >
              {t(data.enabled ? 'access.disable' : 'access.enable')}
            </Action>
          </div>
        </div>

        {error ? (
          <AlertBanner icon="!" tone="danger" title={t('common.failed')} description={error} />
        ) : null}
        {saved ? (
          <AlertBanner
            icon="✓"
            tone="success"
            title={t('common.complete')}
            description={t('access.saved')}
          />
        ) : null}
        <DataTable
          label={t('access.users')}
          rows={data.users.map((user) => ({ ...user, id: user.username }))}
          emptyContent={t('access.noUsers')}
          columns={[
            {
              id: 'username',
              label: t('access.username'),
              rowHeader: true,
              render: (user) => user.username,
            },
            {
              id: 'devices',
              label: t('access.onlineDevices'),
              render: (user) =>
                user.devices.filter((device) => device.expires !== null).length +
                ' / ' +
                user.device_limit,
            },
            {
              id: 'actions',
              label: t('access.actions'),
              render: (user) => (
                <div className="flex flex-wrap gap-2">
                  <Action
                    variant="secondary"
                    disabled={busy}
                    onPress={() => setEditing(user.username)}
                  >
                    {t('access.manage')}
                  </Action>
                  <Action
                    variant="secondary"
                    disabled={busy}
                    onPress={() =>
                      setSelected((current) =>
                        current.includes(user.username)
                          ? current.filter((name) => name !== user.username)
                          : [...current, user.username],
                      )
                    }
                  >
                    {t(selected.includes(user.username) ? 'access.deselect' : 'access.select')}
                  </Action>
                </div>
              ),
            },
          ]}
        />
        <div className="flex flex-wrap gap-3">
          <Action
            variant="secondary"
            disabled={busy}
            onPress={() => {
              void perform(api.importProxyUsers);
            }}
          >
            {t('access.import')}
          </Action>
          <Action
            variant="secondary"
            disabled={busy || data.users.length === 0}
            onPress={() => {
              void perform(api.downloadProxyUsers, false);
            }}
          >
            {t('access.export')}
          </Action>
          <Action
            variant="secondary"
            disabled={busy || selectedUsers.length === 0}
            onPress={() =>
              setConfirm({
                label: t('access.deleteUsers'),
                description:
                  t('access.deleteRisk') +
                  ' ' +
                  selectedUsers.map((user) => user.username).join(', '),
                change: { action: 'delete', usernames: selectedUsers.map((user) => user.username) },
              })
            }
          >
            {t('access.deleteUsers')} ({selectedUsers.length})
          </Action>
        </div>
        <p className="text-sm text-ink-muted">{t('access.importHint')}</p>
        <UserEditor
          key={user?.username ?? 'new'}
          user={user}
          busy={busy}
          change={change}
          onNew={() => setEditing(undefined)}
          onDelete={() => {
            if (user)
              setConfirm({
                label: t('access.deleteUser'),
                description: t('access.deleteRisk') + ' ' + user.username,
                change: { action: 'delete', usernames: [user.username] },
              });
          }}
          onDeviceDelete={(id) =>
            setConfirm({
              label: t('access.deleteDevice'),
              description: t('access.deviceRisk'),
              change: { action: 'delete-device', device: id },
            })
          }
          download={(id, format) => {
            void perform(() => api.downloadProxyProfile(id, format), false);
          }}
          subscriptions={data.enabled && subscriptions}
          queue={(entry) =>
            setBulk((items) => [...items.filter((item) => item.username !== entry.username), entry])
          }
          queueFull={bulk.length >= 50}
        />
        {bulk.length ? (
          <div className="grid gap-3">
            <h3 className="font-semibold">
              {t('access.batch')} ({bulk.length})
            </h3>
            <p className="break-words text-sm text-ink-muted">
              {bulk.map((entry) => entry.username).join(', ')}
            </p>
            <div className="flex flex-wrap gap-3">
              <Action
                variant="secondary"
                disabled={busy}
                onPress={() => {
                  void change({ action: 'create', users: bulk }).then((ok) => {
                    if (ok) setBulk([]);
                  });
                }}
              >
                {t('access.batch')}
              </Action>
              <Action variant="secondary" disabled={busy} onPress={() => setBulk([])}>
                {t('access.clearBatch')}
              </Action>
            </div>
          </div>
        ) : null}
      </div>
      {confirm ? (
        <ConfirmDialog
          triggerLabel={confirm.label}
          title={confirm.label}
          description={confirm.description}
          impact={null}
          isOpen
          onOpenChange={(open) => {
            if (!open) setConfirm(null);
          }}
          cancelLabel={t('common.cancel')}
          confirmLabel={confirm.label}
          failureMessage={error || t('common.failed')}
          confirmDisabled={busy}
          tone="danger"
          onConfirm={async () => {
            if (!(await change(confirm.change))) throw new Error(t('common.failed'));
            if (confirm.change.action === 'delete') {
              const deleted = confirm.change.usernames;
              setSelected((names) => names.filter((name) => !deleted.includes(name)));
              setEditing((name) => (name && deleted.includes(name) ? undefined : name));
            }
            setConfirm(null);
          }}
        />
      ) : null}
    </Section>
  );
}

function UserEditor({
  user,
  busy,
  change,
  onNew,
  onDelete,
  onDeviceDelete,
  download,
  subscriptions,
  queue,
  queueFull,
}: Readonly<{
  user: User | undefined;
  busy: boolean;
  change: (input: ProxyAccessChange) => Promise<boolean>;
  onNew: () => void;
  onDelete: () => void;
  onDeviceDelete: (id: string) => void;
  download: (id: string, format: DeviceFormat) => void;
  subscriptions: boolean;
  queue: (entry: NewUser) => void;
  queueFull: boolean;
}>) {
  const t = useNodeText();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [limit, setLimit] = useState<string>();
  const [device, setDevice] = useState('');
  const count = Number(limit ?? user?.device_limit ?? 1);
  const valid = Number.isInteger(count) && count >= 1 && count <= 32;
  return (
    <div className="grid gap-3">
      <h3 className="font-semibold">{user ? user.username : t('access.create')}</h3>
      {user ? null : (
        <TextField
          label={t('access.username')}
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
      )}
      <PasswordField
        label={t(user ? 'access.changePassword' : 'access.password')}
        purpose="new"
        showLabel={t('common.show')}
        hideLabel={t('common.hide')}
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      <TextField
        label={t('access.deviceLimit')}
        value={limit ?? String(user?.device_limit ?? 1)}
        onChange={(e) => setLimit(e.target.value)}
      />
      <div className="flex flex-wrap gap-3">
        <Action
          variant="secondary"
          disabled={busy || !valid || (!user && (!username.trim() || !password))}
          onPress={() => {
            const action: ProxyAccessChange = user
              ? {
                  action: 'edit',
                  username: user.username,
                  device_limit: count,
                  ...(password ? { password } : {}),
                }
              : {
                  action: 'create',
                  users: [{ username: username.trim(), password, device_limit: count }],
                };
            void change(action).then((ok) => {
              if (ok) {
                setPassword('');
                setLimit(undefined);
                if (!user) setUsername('');
              }
            });
          }}
        >
          {t(user ? 'access.save' : 'access.create')}
        </Action>
        {!user ? (
          <Action
            variant="secondary"
            disabled={busy || queueFull || !valid || !username.trim() || !password}
            onPress={() => {
              queue({ username: username.trim(), password, device_limit: count });
              setPassword('');
              setUsername('');
              setLimit(undefined);
            }}
          >
            {t('access.queue')}
          </Action>
        ) : null}
        {user ? (
          <>
            <Action variant="secondary" disabled={busy} onPress={onNew}>
              {t('access.create')}
            </Action>
            <Action variant="secondary" disabled={busy} onPress={onDelete}>
              {t('access.deleteUser')}
            </Action>
          </>
        ) : null}
      </div>
      {user ? (
        <>
          <TextField
            label={t('access.deviceName')}
            hint={t('access.deviceHint')}
            value={device}
            onChange={(e) => setDevice(e.target.value)}
          />
          <div>
            <Action
              variant="secondary"
              disabled={busy || !device.trim()}
              onPress={() => {
                void change({
                  action: 'create-device',
                  username: user.username,
                  label: device.trim(),
                }).then((ok) => {
                  if (ok) setDevice('');
                });
              }}
            >
              {t('access.createDevice')}
            </Action>
          </div>
          <DataTable
            label={t('access.devices')}
            rows={user.devices}
            emptyContent={t('access.noDevices')}
            columns={[
              {
                id: 'device',
                label: t('access.deviceName'),
                rowHeader: true,
                render: (row) => row.label,
              },
              {
                id: 'expiry',
                label: t('access.expiry'),
                render: (row) =>
                  row.expires ? <Timestamp value={row.expires} /> : t('access.signedOut'),
              },
              {
                id: 'actions',
                label: t('access.actions'),
                render: (row) => (
                  <div className="flex flex-wrap gap-2">
                    <Action
                      variant="secondary"
                      disabled={busy}
                      onPress={() => download(row.id, 'mihomo')}
                    >
                      {t('nodes.mihomo')}
                    </Action>
                    <Action
                      variant="secondary"
                      disabled={busy}
                      onPress={() => download(row.id, 'xray')}
                    >
                      {t('nodes.xray')}
                    </Action>
                    {subscriptions ? (
                      <Action
                        variant="secondary"
                        disabled={busy}
                        onPress={() => download(row.id, 'subscriptions')}
                      >
                        {t('access.downloadSubscriptions')}
                      </Action>
                    ) : null}
                    <Action
                      variant="secondary"
                      disabled={busy}
                      onPress={() => onDeviceDelete(row.id)}
                    >
                      {t('access.deleteDevice')}
                    </Action>
                  </div>
                ),
              },
            ]}
          />
        </>
      ) : null}
    </div>
  );
}
