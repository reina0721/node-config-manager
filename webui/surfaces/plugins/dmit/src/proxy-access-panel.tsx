'use client';
import { useState } from 'react';
import { Section } from '@community-go/surface-foundation/layout';
import { Action } from '@community-go/ui-adapter/action';
import { DataTable } from '@community-go/ui-adapter/data-display';
import { AlertBanner, Badge } from '@community-go/ui-adapter/feedback';
import { PasswordField, SwitchField, TextField } from '@community-go/ui-adapter/form-field';
import { ConfirmDialog } from '@community-go/ui-adapter/overlays';
import {
  useNodeManagement,
  type DeviceExportFormat,
  type NativeProfile,
  type ProxyAccess,
  type ProxyAccessChange,
} from '../../../src/node-management';
import { EditorDrawer, EnabledBadge, ListFilters, useListFilters } from './collection-controls';
import { ConsoleLink, Details, Timestamp, useNodeText } from './common';

type User = ProxyAccess['users'][number];
type NewUser = Extract<ProxyAccessChange, { action: 'create' }>['users'][number];
type Confirm = Readonly<{ label: string; description: string; change: ProxyAccessChange }>;

export default function ProxyAccessPanel({
  data,
  subscriptions,
  refresh,
}: Readonly<{ data: ProxyAccess; subscriptions: boolean; refresh: () => Promise<void> }>) {
  const api = useNodeManagement();
  const t = useNodeText();
  const [selected, setSelected] = useState<string[]>([]);
  const [editing, setEditing] = useState<string | null>();
  const [profileDirty, setProfileDirty] = useState(false);
  const [policyDirty, setPolicyDirty] = useState(false);
  const [deviceDirty, setDeviceDirty] = useState(false);
  const filters = useListFilters();
  const [sample, setSample] = useState(() => ({ data, now: Date.now() / 1000 }));
  if (sample.data !== data) setSample({ data, now: new Date().getTime() / 1000 });
  const open = (name: string | null) => {
    setError('');
    setProfileDirty(false);
    setPolicyDirty(false);
    setDeviceDirty(false);
    setEditing(name);
  };
  const close = () => {
    setEditing(undefined);
    setError('');
  };
  const [confirm, setConfirm] = useState<Confirm | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [saved, setSaved] = useState(false);
  const [bulk, setBulk] = useState<NewUser[]>([]);
  const user = data.users.find((candidate) => candidate.username === editing);
  const selectedUsers = data.users.filter((user) => selected.includes(user.username));

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
    <Section
      title={t('access.users')}
      contentInset
      action={
        <Action disabled={busy} onPress={() => open(null)}>
          {t('access.create')}
        </Action>
      }
    >
      <div className="grid gap-5">
        <Details
          label={t('access.title')}
          items={[
            [t('access.title'), <EnabledBadge key="auth" enabled={data.enabled} />],
            [
              t('access.portal'),
              <code key="portal" className="break-all">
                {data.portal}
              </code>,
            ],
          ]}
        />
        {data.enabled && <p className="text-sm text-ink-muted">{t('access.description')}</p>}
        <ConsoleLink to="dmit.panel">{t('console.authSettings')}</ConsoleLink>
        {error && editing === undefined ? (
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
        <ListFilters filters={filters} />
        <DataTable
          label={t('access.users')}
          rows={data.users
            .filter((user) => filters.matches(!user.disabled, user.username))
            .map((user) => ({ ...user, id: user.username }))}
          emptyContent={t(filters.active ? 'console.noMatches' : 'access.noUsers')}
          columns={[
            {
              id: 'username',
              label: t('access.username'),
              rowHeader: true,
              render: (user) => user.username,
            },
            {
              id: 'status',
              label: t('nodes.status'),
              render: (user) => {
                const expired = user.expires !== null && user.expires <= sample.now;
                const quotaUsed =
                  user.quota_bytes !== null &&
                  user.traffic.upload + user.traffic.download >= user.quota_bytes;
                if (user.disabled) return <EnabledBadge enabled={false} />;
                if (expired || quotaUsed)
                  return (
                    <Badge tone="warning">
                      {t(expired ? 'console.accountExpired' : 'console.quotaUsed')}
                    </Badge>
                  );
                return <EnabledBadge enabled />;
              },
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
              label: t('access.connectedDevices'),
              render: (user) => user.devices.filter((device) => device.connections > 0).length,
            },
            {
              id: 'controls',
              label: t('access.actions'),
              render: (user) => (
                <div className="flex flex-wrap gap-2">
                  <Action variant="secondary" disabled={busy} onPress={() => open(user.username)}>
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
        {editing !== undefined && (
          <EditorDrawer
            title={user?.username ?? t('access.create')}
            description={t('clients.description')}
            dirty={profileDirty || deviceDirty || policyDirty}
            onClose={close}
            busy={busy}
          >
            {error && (
              <AlertBanner icon="!" tone="danger" title={t('common.failed')} description={error} />
            )}
            {saved && <p role="status">{t('access.saved')}</p>}
            <UserEditor
              key={'profile:' + (user?.username ?? '')}
              user={user}
              busy={busy}
              change={change}
              onProfileDirty={setProfileDirty}
              onDeviceDirty={setDeviceDirty}
              onCreated={close}
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
              extraFormats={data.extra_profile_formats ?? []}
              queue={(entry) =>
                setBulk((items) => [
                  ...items.filter((item) => item.username !== entry.username),
                  entry,
                ])
              }
              queueFull={bulk.length >= 50}
            />
            {user && (
              <AccountPolicy
                key={'policy:' + user.username}
                user={user}
                busy={busy}
                enabled={data.enabled}
                onDirty={setPolicyDirty}
                change={change}
                reset={() =>
                  setConfirm({
                    label: t('access.reset'),
                    description: t('access.resetRisk'),
                    change: { action: 'reset-traffic', username: user.username },
                  })
                }
                trafficCycles={data.traffic_cycles === true}
              />
            )}
          </EditorDrawer>
        )}
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
  onProfileDirty,
  onDeviceDirty,
  onCreated,
  onDelete,
  onDeviceDelete,
  download,
  subscriptions,
  extraFormats,
  queue,
  queueFull,
}: Readonly<{
  user: User | undefined;
  busy: boolean;
  change: (input: ProxyAccessChange) => Promise<boolean>;
  onProfileDirty: (dirty: boolean) => void;
  onDeviceDirty: (dirty: boolean) => void;
  onCreated: () => void;
  onDelete: () => void;
  onDeviceDelete: (id: string) => void;
  download: (id: string, format: DeviceExportFormat) => void;
  subscriptions: boolean;
  extraFormats: NonNullable<ProxyAccess['extra_profile_formats']>;
  queue: (entry: NewUser) => void;
  queueFull: boolean;
}>) {
  const t = useNodeText();
  const api = useNodeManagement();
  const [native, setNative] = useState<{
    device: string;
    profiles: NativeProfile[];
    error?: string;
  }>();
  const [loadingNative, setLoadingNative] = useState(false);
  const showNative = async (device: string) => {
    setLoadingNative(true);
    try {
      setNative({ device, profiles: await api.nativeProfiles(device) });
    } catch (e) {
      setNative({
        device,
        profiles: [],
        error: e instanceof Error ? e.message : t('common.failed'),
      });
    } finally {
      setLoadingNative(false);
    }
  };
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [limit, setLimit] = useState<string>();
  const [device, setDevice] = useState('');
  const count = Number(limit ?? user?.device_limit ?? 1);
  const valid = Number.isInteger(count) && count >= 1 && count <= 32;
  const usernameValid = Boolean(user) || /^[a-zA-Z0-9._@-]{1,64}$/.test(username.trim());
  const passwordBytes = new TextEncoder().encode(password).length;
  const passwordValid =
    (Boolean(user) && !password) || (passwordBytes >= 6 && passwordBytes <= 256);
  const canSave = valid && usernameValid && passwordValid;
  return (
    <div className="grid gap-3">
      <h3 className="font-semibold">{t('console.devicesTab')}</h3>
      {user ? null : (
        <TextField
          label={t('access.username')}
          value={username}
          error={username && !usernameValid ? t('console.usernameError') : ''}
          onChange={(e) => {
            setUsername(e.target.value);
            onProfileDirty(true);
          }}
        />
      )}
      <PasswordField
        label={t(user ? 'access.changePassword' : 'access.password')}
        purpose="new"
        showLabel={t('common.show')}
        hideLabel={t('common.hide')}
        value={password}
        error={password && !passwordValid ? t('console.passwordError') : ''}
        onChange={(e) => {
          setPassword(e.target.value);
          onProfileDirty(true);
        }}
      />
      <TextField
        label={t('access.deviceLimit')}
        value={limit ?? String(user?.device_limit ?? 1)}
        error={!valid ? t('console.deviceLimitError') : ''}
        onChange={(e) => {
          setLimit(e.target.value);
          onProfileDirty(true);
        }}
      />
      <div className="flex flex-wrap gap-3">
        <Action
          loading={busy}
          disabled={busy || !canSave}
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
                onProfileDirty(false);
                if (!user) onCreated();
              }
            });
          }}
        >
          {t(user ? 'access.save' : 'access.create')}
        </Action>
        {!user ? (
          <Action
            variant="secondary"
            disabled={busy || queueFull || !canSave}
            onPress={() => {
              queue({ username: username.trim(), password, device_limit: count });
              setPassword('');
              setUsername('');
              setLimit(undefined);
              onProfileDirty(false);
              onCreated();
            }}
          >
            {t('access.queue')}
          </Action>
        ) : null}
        {user ? (
          <>
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
            onChange={(e) => {
              setDevice(e.target.value);
              onDeviceDirty(true);
            }}
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
                  if (ok) {
                    setDevice('');
                    onDeviceDirty(false);
                  }
                });
              }}
            >
              {t('access.createDevice')}
            </Action>
          </div>
          {user.devices.length ? (
            <ul className="grid gap-3" aria-label={t('access.devices')}>
              {user.devices.map((row) => (
                <li
                  key={row.id}
                  className="grid min-w-0 gap-3 rounded-panel border border-border p-3"
                >
                  <div className="grid gap-1">
                    <h4 className="break-words font-semibold">{row.label}</h4>
                    <p className="text-sm text-ink-muted">
                      {row.expires ? <Timestamp value={row.expires} /> : t('access.signedOut')}
                    </p>
                  </div>
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
                    <Action
                      variant="secondary"
                      disabled={busy}
                      onPress={() => download(row.id, 'mihomo-weighted')}
                    >
                      {t('nodes.mihomoWeighted')}
                    </Action>
                    {extraFormats
                      .filter((format) => format !== 'native')
                      .map((format) => (
                        <Action
                          key={format}
                          variant="secondary"
                          disabled={busy}
                          onPress={() => download(row.id, format)}
                        >
                          {t('access.export-' + format)}
                        </Action>
                      ))}
                    {extraFormats.includes('native') && (
                      <Action
                        variant="secondary"
                        disabled={busy || loadingNative}
                        onPress={() => void showNative(row.id)}
                      >
                        {t('access.nativeProfiles')}
                      </Action>
                    )}
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
                  {native?.device === row.id && (
                    <div className="grid gap-2">
                      {native.error ? (
                        <AlertBanner
                          icon="!"
                          tone="danger"
                          title={t('common.failed')}
                          description={native.error}
                        />
                      ) : native.profiles.length ? (
                        native.profiles.map((profile) => (
                          <div className="grid min-w-0 gap-1" key={profile.format}>
                            <p className="break-all text-sm">{profile.name}</p>
                            <div>
                              <Action
                                variant="secondary"
                                disabled={busy}
                                onPress={() => download(row.id, profile.format)}
                              >
                                {t(
                                  profile.format.startsWith('native-wireguard/')
                                    ? 'access.downloadWireguard'
                                    : profile.format.startsWith('native-tuic/')
                                      ? 'access.downloadTuic'
                                      : profile.format.startsWith('native-amneziawg/')
                                        ? 'access.downloadAmneziawg'
                                        : 'access.downloadHysteria',
                                )}
                              </Action>
                            </div>
                          </div>
                        ))
                      ) : (
                        <p role="status">{t('access.noNativeProfiles')}</p>
                      )}
                    </div>
                  )}
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-ink-muted">{t('access.noDevices')}</p>
          )}
        </>
      ) : null}
    </div>
  );
}

function AccountPolicy({
  user,
  busy,
  enabled,
  onDirty,
  change,
  reset,
  trafficCycles,
}: {
  user: User;
  busy: boolean;
  enabled: boolean;
  onDirty: (dirty: boolean) => void;
  change: (input: ProxyAccessChange) => Promise<boolean>;
  reset: () => void;
  trafficCycles: boolean;
}) {
  const t = useNodeText();
  const [disabled, setDisabled] = useState(user.disabled);
  const [expiry, setExpiry] = useState(
    user.expires === null ? '' : new Date(user.expires * 1000).toISOString(),
  );
  const [quota, setQuota] = useState(user.quota_bytes === null ? '' : String(user.quota_bytes));
  const [cycle, setCycle] = useState(user.traffic_cycle?.interval_seconds?.toString() ?? '');
  const cycleSeconds = cycle.trim() ? Number(cycle) : null;
  const cycleValid =
    cycleSeconds === null ||
    (Number.isSafeInteger(cycleSeconds) && cycleSeconds >= 60 && cycleSeconds <= 366 * 86400);
  const expirySeconds = expiry.trim() ? Math.floor(Date.parse(expiry) / 1000) : null;
  const quotaBytes = quota.trim() ? Number(quota) : null;
  const expiryValid =
    expirySeconds === null ||
    (/Z$/i.test(expiry) && Number.isSafeInteger(expirySeconds) && expirySeconds > 0);
  const cycleDirty =
    trafficCycles && cycleSeconds !== (user.traffic_cycle?.interval_seconds ?? null);
  const quotaValid = quotaBytes === null || (Number.isSafeInteger(quotaBytes) && quotaBytes > 0);
  const valid = expiryValid && quotaValid;
  const differs =
    user.disabled !== disabled || user.expires !== expirySeconds || user.quota_bytes !== quotaBytes;
  return (
    <div className="grid gap-4">
      <h3 className="font-semibold">{t('access.accountPolicy')}</h3>
      <Details
        label={t('access.accountPolicy')}
        items={[
          [t('access.upload'), user.traffic.upload.toLocaleString()],
          [t('access.download'), user.traffic.download.toLocaleString()],
        ]}
      />
      <SwitchField
        label={t('access.accountEnabled')}
        description=""
        checked={!disabled}
        onCheckedChange={(value) => {
          setDisabled(!value);
          onDirty(true);
        }}
      />
      <TextField
        label={t('access.accountExpiry')}
        hint={t('access.accountExpiryHint')}
        value={expiry}
        error={!expiryValid ? t('console.expiryError') : ''}
        onChange={(e) => {
          setExpiry(e.target.value);
          onDirty(true);
        }}
      />
      <TextField
        label={t('access.accountQuota')}
        hint={t('access.accountQuotaHint')}
        value={quota}
        error={!quotaValid ? t('console.quotaError') : ''}
        onChange={(e) => {
          setQuota(e.target.value);
          onDirty(true);
        }}
      />
      {trafficCycles && (
        <>
          <TextField
            label={t('access.cyclePeriod')}
            hint={t('access.cycleHint')}
            value={cycle}
            error={cycleValid ? '' : t('access.cycleHint')}
            onChange={(e) => {
              setCycle(e.target.value);
              onDirty(true);
            }}
          />
          {user.traffic_cycle && (
            <Details
              label={t('access.cyclePeriod')}
              items={[
                [
                  t('access.cycleNext'),
                  <Timestamp key="cycle" value={user.traffic_cycle.next_reset} />,
                ],
              ]}
            />
          )}
          <div>
            <ConfirmDialog
              triggerLabel={t('access.saveCycle')}
              title={t('access.saveCycle')}
              description={t('access.cycleRisk')}
              impact={null}
              cancelLabel={t('common.cancel')}
              confirmLabel={t('access.save')}
              failureMessage={t('common.failed')}
              confirmDisabled={busy || !enabled || !cycleValid || !cycleDirty}
              onConfirm={async () => {
                if (
                  !(await change({
                    action: 'traffic-cycle',
                    username: user.username,
                    interval_seconds: cycleSeconds,
                  }))
                )
                  throw new Error(t('common.failed'));
                onDirty(differs);
              }}
            />
          </div>
        </>
      )}
      <div className="flex flex-wrap gap-3">
        <ConfirmDialog
          triggerLabel={t('access.applyPolicy')}
          title={t('access.applyPolicy')}
          description={t('access.policyRisk')}
          impact={null}
          cancelLabel={t('common.cancel')}
          confirmLabel={t('access.save')}
          failureMessage={t('common.failed')}
          confirmDisabled={busy || !enabled || !valid || !differs}
          onConfirm={async () => {
            if (
              !(await change({
                action: 'policy',
                username: user.username,
                disabled,
                expires: expirySeconds,
                quota_bytes: quotaBytes,
              }))
            )
              throw new Error(t('common.failed'));
            onDirty(cycleDirty);
          }}
        />
        <Action variant="secondary" disabled={busy} onPress={reset}>
          {t('access.reset')}
        </Action>
      </div>
    </div>
  );
}
