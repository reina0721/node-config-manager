'use client';

import { useRef, useState } from 'react';
import { Action } from '@community-go/ui-adapter/action';
import { AlertBanner } from '@community-go/ui-adapter/feedback';
import { SelectField, TextField } from '@community-go/ui-adapter/form-field';
import {
  useNodeManagement,
  type DeviceExportFormat,
  type NativeProfile,
  type ProxyAccess,
} from '../../../src/node-management';
import { EditorDrawer } from './collection-controls';
import { useNodeText } from './common';

type Client = ProxyAccess['clients'][number];
type Device = ProxyAccess['users'][number]['devices'][number];

export default function ClientDeviceDownloads({
  client,
  data,
  observedAt,
  subscriptions,
  refresh,
  onClose,
}: {
  client: Client | undefined;
  data: ProxyAccess;
  observedAt: number;
  subscriptions: boolean;
  refresh: () => Promise<void>;
  onClose: () => void;
}) {
  const api = useNodeManagement();
  const t = useNodeText();
  const [username, setUsername] = useState<string>();
  const [deviceId, setDeviceId] = useState<string>();
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [issued, setIssued] = useState<{ device: Device; owner: string; source: ProxyAccess }>();
  const users = data.users.filter((user) => !client || client.usernames.includes(user.username));
  const user = users.find(
    (account) =>
      account.username === (username ?? (users.length === 1 ? users[0]?.username : undefined)),
  );
  const blockedReason =
    user?.profile_blocked_reason !== undefined
      ? user.profile_blocked_reason
      : user?.disabled
        ? 'disabled'
        : user?.expires != null && user.expires <= observedAt
          ? 'expired'
          : null;
  const clientId = client?.id ?? null;
  const devices =
    user?.devices.filter((device) => device.client === clientId && !device.enrolled) ?? [];
  const canIssue = !client || !data.enrollment_supported;
  if (
    issued &&
    issued.source === data &&
    issued.owner === user?.username &&
    !devices.some((device) => device.id === issued.device.id)
  ) {
    devices.push(issued.device);
  }
  const device = devices.find(
    (entry) => entry.id === (deviceId ?? (devices.length === 1 ? devices[0]?.id : undefined)),
  );
  const nameValid =
    name.trim().length > 0 &&
    new TextEncoder().encode(name.trim()).length <= 96 &&
    !/\p{Cc}/u.test(name);
  const issue = async () => {
    if (!user || !canIssue || blockedReason || busy || !nameValid) return;
    setBusy(true);
    setError('');
    try {
      const next = await api.changeProxyAccess({
        action: 'create-device',
        username: user.username,
        label: name.trim(),
        ...(client ? { client: client.id } : {}),
      });
      const created = next.users
        .find((account) => account.username === user.username)
        ?.devices.find(
          (record) => record.id === next.created_device_id && record.client === clientId,
        );
      setName('');
      if (!created) {
        await refresh();
        setError(t('sharedClients.issuedRefresh'));
        return;
      }
      setIssued({ device: created, owner: user.username, source: data });
      setDeviceId(created.id);
      await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  };
  return (
    <EditorDrawer
      title={t('sharedClients.deviceDownloads')}
      description={client?.name ?? t('sharedClients.legacy')}
      dirty={Boolean(name.trim())}
      busy={busy}
      onClose={onClose}
    >
      {error && (
        <AlertBanner icon="!" tone="danger" title={t('common.failed')} description={error} />
      )}
      {users.length === 0 ? (
        <p>{t('sharedClients.noAssignments')}</p>
      ) : (
        <>
          <SelectField
            label={t('access.username')}
            placeholder={t('sharedClients.chooseUser')}
            value={user?.username ?? ''}
            disabled={busy}
            options={users.map((account) => ({ value: account.username, label: account.username }))}
            onValueChange={(selection) => {
              setUsername(selection);
              setDeviceId(undefined);
              setName('');
              setError('');
            }}
          />
          {user && (
            <>
              {blockedReason && (
                <p role="status" className="text-sm text-ink-muted">
                  {t(
                    blockedReason === 'expired'
                      ? 'sharedClients.profileExpired'
                      : 'sharedClients.profileDisabled',
                  )}
                </p>
              )}
              {devices.length === 0 ? (
                <p className="text-sm text-ink-muted">{t('access.noDevices')}</p>
              ) : (
                <SelectField
                  label={t('sharedClients.chooseDevice')}
                  value={device?.id ?? ''}
                  placeholder={t('sharedClients.chooseDevice')}
                  disabled={busy}
                  options={devices.map((entry, index) => ({
                    value: entry.id,
                    label:
                      devices.filter((item) => item.label === entry.label).length > 1
                        ? `${entry.label} (${index + 1})`
                        : entry.label,
                  }))}
                  onValueChange={setDeviceId}
                />
              )}
              {!blockedReason && issued?.device.id === device?.id && device && (
                <p role="status">{t('sharedClients.deviceIssued')}</p>
              )}
              {!blockedReason && device && (
                <DeviceFormats
                  key={device.id}
                  id={device.id}
                  disabled={busy}
                  extraFormats={data.extra_profile_formats ?? []}
                  subscriptions={data.enabled && subscriptions}
                  refresh={refresh}
                />
              )}
              {canIssue && (
                <div className="grid gap-3 border-t border-border pt-4">
                  <TextField
                    label={t('access.deviceName')}
                    hint={data.enabled ? t('access.deviceHint') : ''}
                    value={name}
                    disabled={busy || Boolean(blockedReason)}
                    onChange={(event) => setName(event.target.value)}
                  />
                  <div>
                    <Action
                      variant="secondary"
                      disabled={busy || Boolean(blockedReason) || !nameValid}
                      loading={busy}
                      onPress={() => void issue()}
                    >
                      {t('access.createDevice')}
                    </Action>
                  </div>
                </div>
              )}
            </>
          )}
        </>
      )}
    </EditorDrawer>
  );
}

function DeviceFormats({
  id,
  disabled,
  extraFormats,
  subscriptions,
  refresh,
}: {
  id: string;
  disabled: boolean;
  extraFormats: NonNullable<ProxyAccess['extra_profile_formats']>;
  subscriptions: boolean;
  refresh: () => Promise<void>;
}) {
  const t = useNodeText();
  const api = useNodeManagement();
  const inFlight = useRef(false);
  const [pending, setPending] = useState<DeviceExportFormat | 'native-list'>();
  const [error, setError] = useState('');
  const [native, setNative] = useState<NativeProfile[]>();
  const run = async (format: NonNullable<typeof pending>, request: () => Promise<void>) => {
    if (disabled || inFlight.current) return;
    inFlight.current = true;
    setPending(format);
    setError('');
    try {
      await request();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
      await refresh();
    } finally {
      inFlight.current = false;
      setPending(undefined);
    }
  };
  const download = (format: DeviceExportFormat) =>
    void run(format, () => api.downloadProxyProfile(id, format));
  const formats: { format: DeviceExportFormat; label: string }[] = [
    { format: 'mihomo', label: 'nodes.mihomo' },
    { format: 'xray', label: 'nodes.xray' },
    { format: 'mihomo-weighted', label: 'nodes.mihomoWeighted' },
  ];
  for (const format of extraFormats) {
    if (format !== 'native') formats.push({ format, label: 'access.export-' + format });
  }
  if (subscriptions)
    formats.push({ format: 'subscriptions', label: 'access.downloadSubscriptions' });
  return (
    <div className="grid min-w-0 gap-3">
      {error && (
        <AlertBanner icon="!" tone="danger" title={t('common.failed')} description={error} />
      )}
      <div className="flex flex-wrap gap-2">
        {formats.map(({ format, label }) => (
          <Action
            key={format}
            variant="secondary"
            disabled={disabled || (pending !== undefined && pending !== format)}
            loading={pending === format}
            onPress={() => download(format)}
          >
            {t(label)}
          </Action>
        ))}
        {extraFormats.includes('native') && (
          <Action
            variant="secondary"
            disabled={disabled || (pending !== undefined && pending !== 'native-list')}
            loading={pending === 'native-list'}
            onPress={() =>
              void run('native-list', async () => setNative(await api.nativeProfiles(id)))
            }
          >
            {t('access.nativeProfiles')}
          </Action>
        )}
      </div>
      {native?.length === 0 && <p role="status">{t('access.noNativeProfiles')}</p>}
      {native?.map((profile) => (
        <div className="grid min-w-0 gap-1" key={profile.format}>
          <p className="break-all text-sm">{profile.name}</p>
          <div>
            <Action
              variant="secondary"
              disabled={disabled || (pending !== undefined && pending !== profile.format)}
              loading={pending === profile.format}
              onPress={() => download(profile.format)}
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
      ))}
    </div>
  );
}
