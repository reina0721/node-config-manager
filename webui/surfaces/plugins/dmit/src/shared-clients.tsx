'use client';
import { useState } from 'react';
import { Section } from '@community-go/surface-foundation/layout';
import { Action } from '@community-go/ui-adapter/action';
import { DataTable } from '@community-go/ui-adapter/data-display';
import { AlertBanner } from '@community-go/ui-adapter/feedback';
import { SwitchField, TextAreaField, TextField } from '@community-go/ui-adapter/form-field';
import { ConfirmDialog } from '@community-go/ui-adapter/overlays';
import { useNodeManagement, type ProxyAccess } from '../../../src/node-management';
import { EditorDrawer } from './collection-controls';
import { ConsoleLink, useNodeQuery, useNodeText } from './common';
import ClientDeviceDownloads from './client-device-downloads';

type Client = ProxyAccess['clients'][number];
type Draft = {
  client: Client | undefined;
  name: string;
  users: string[];
  inbounds: string[];
  links: string;
};

function changed(items: string[], id: string, enabled: boolean): string[] {
  return enabled ? [...items, id] : items.filter((item) => item !== id);
}

export default function SharedClients({
  data,
  subscriptions,
  refresh,
}: {
  data: ProxyAccess;
  subscriptions: boolean;
  refresh: () => Promise<void>;
}) {
  const api = useNodeManagement();
  const t = useNodeText();
  const configuration = useNodeQuery(api.configuration);
  const [draft, setDraft] = useState<Draft>();
  const [downloadTarget, setDownloadTarget] = useState<string | null>();
  const [baseline, setBaseline] = useState<Draft>();
  const [confirm, setConfirm] = useState<'save' | 'delete'>();
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const inbounds = Object.entries(configuration.data?.config.management?.inbounds ?? {}).filter(
    ([, inbound]) => inbound.enabled && !['tunnel', 'tun'].includes(inbound.protocol ?? ''),
  );
  const edit = async (client?: Client) => {
    setBusy(true);
    setError('');
    try {
      const current = {
        client,
        name: client?.name ?? '',
        users: client?.usernames ?? [],
        inbounds: client?.inbounds ?? [],
        links: client ? (await api.clientLinks(client.id)).join('\n') : '',
      };
      setBaseline(current);
      setDraft(current);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  };
  const apply = async (remove: boolean) => {
    if (!draft) return;
    setError('');
    setBusy(true);
    try {
      if (remove && draft.client) {
        await api.changeProxyAccess({ action: 'delete-client', id: draft.client.id });
      } else {
        await api.changeProxyAccess({
          action: 'save-client',
          ...(draft.client ? { id: draft.client.id } : {}),
          name: draft.name.trim(),
          usernames: draft.users,
          inbounds: draft.inbounds,
          links: draft.links
            .split(/\r?\n/)
            .map((link) => link.trim())
            .filter(Boolean),
        });
      }
      setConfirm(undefined);
      setDraft(undefined);
      await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
      throw cause;
    } finally {
      setBusy(false);
    }
  };
  const dirty = JSON.stringify(draft) !== JSON.stringify(baseline);
  const revokes = Boolean(draft?.client?.usernames.some((name) => !draft.users.includes(name)));
  const downloadClient = data.clients.find((client) => client.id === downloadTarget);
  return (
    <>
      <Section
        title={t('sharedClients.definitionsTab')}
        description={t('sharedClients.description')}
        contentInset
        action={
          <Action
            disabled={busy || !data.enabled || !configuration.data}
            onPress={() => void edit()}
          >
            {t('catalogue.add')}
          </Action>
        }
      >
        {!data.enabled && <ConsoleLink to="dmit.panel">{t('console.authSettings')}</ConsoleLink>}
        {(configuration.error || (error && !draft)) && (
          <AlertBanner
            icon="!"
            tone="danger"
            title={t('common.failed')}
            description={configuration.error || error}
          />
        )}
        <DataTable
          label={t('sharedClients.definitionsTab')}
          rows={data.clients}
          emptyContent={t('common.empty')}
          columns={[
            {
              id: 'name',
              label: t('sharedClients.definition'),
              rowHeader: true,
              render: (client) => client.name,
            },
            {
              id: 'users',
              label: t('sharedClients.usersTab'),
              render: (client) => client.usernames.length,
            },
            {
              id: 'links',
              label: t('sharedClients.externalLinks'),
              render: (client) => client.link_count,
            },
            {
              id: 'edit',
              label: t('common.operation'),
              render: (client) => (
                <div className="flex flex-wrap gap-2">
                  <Action size="sm" disabled={busy} onPress={() => setDownloadTarget(client.id)}>
                    {t('sharedClients.deviceDownloads')}
                  </Action>
                  <Action
                    size="sm"
                    variant="secondary"
                    disabled={busy}
                    onPress={() => void edit(client)}
                  >
                    {t('console.edit')}
                  </Action>
                </div>
              ),
            },
          ]}
        />
      </Section>
      {data.users.length > 0 && (
        <Section
          title={t('sharedClients.legacy')}
          description={t('sharedClients.legacyDescription')}
          action={
            <Action variant="secondary" disabled={busy} onPress={() => setDownloadTarget(null)}>
              {t('sharedClients.deviceDownloads')}
            </Action>
          }
          children={null}
        />
      )}
      {(downloadTarget === null || downloadClient) && (
        <ClientDeviceDownloads
          key={downloadClient?.id ?? 'legacy'}
          client={downloadClient}
          data={data}
          subscriptions={subscriptions}
          refresh={refresh}
          onClose={() => setDownloadTarget(undefined)}
        />
      )}
      {draft && (
        <EditorDrawer
          title={t('sharedClients.definition')}
          description={t('sharedClients.builtins')}
          dirty={dirty}
          onClose={() => setDraft(undefined)}
        >
          <div className="grid gap-4">
            {error && (
              <AlertBanner icon="!" tone="danger" title={t('common.failed')} description={error} />
            )}
            {draft.client && <code className="break-all text-sm">{draft.client.id}</code>}
            <TextField
              label={t('sharedClients.name')}
              value={draft.name}
              disabled={busy}
              onChange={(event) => setDraft({ ...draft, name: event.target.value })}
            />
            <details>
              <summary className="cursor-pointer font-semibold">
                {t('sharedClients.inbounds')} · {draft.inbounds.length}
              </summary>
              <div className="mt-3 grid gap-3">
                {inbounds.map(([id, inbound]) => (
                  <SwitchField
                    key={id}
                    label={inbound.remark}
                    description=""
                    checked={draft.inbounds.includes(id)}
                    onCheckedChange={(enabled) =>
                      setDraft({ ...draft, inbounds: changed(draft.inbounds, id, enabled) })
                    }
                  />
                ))}
                {draft.inbounds
                  .filter((id) => !inbounds.some(([candidate]) => candidate === id))
                  .map((id) => (
                    <SwitchField
                      key={id}
                      label={id}
                      description={t('sharedClients.inboundUnavailable')}
                      checked
                      onCheckedChange={() =>
                        setDraft({ ...draft, inbounds: changed(draft.inbounds, id, false) })
                      }
                    />
                  ))}
              </div>
            </details>
            <details>
              <summary className="cursor-pointer font-semibold">
                {t('sharedClients.assignments')} · {draft.users.length}
              </summary>
              <div className="mt-3 grid gap-3">
                {data.users.map((user) => (
                  <SwitchField
                    key={user.username}
                    label={user.username}
                    description=""
                    checked={draft.users.includes(user.username)}
                    onCheckedChange={(enabled) =>
                      setDraft({ ...draft, users: changed(draft.users, user.username, enabled) })
                    }
                  />
                ))}
              </div>
            </details>
            <TextAreaField
              label={t('sharedClients.externalLinks')}
              hint={t('sharedClients.externalHint')}
              value={draft.links}
              onChange={(event) => setDraft({ ...draft, links: event.target.value })}
            />
            <div className="flex flex-wrap gap-3">
              <Action
                loading={busy}
                disabled={!dirty || !draft.name.trim() || !configuration.data}
                onPress={() => (revokes ? setConfirm('save') : void apply(false).catch(() => {}))}
              >
                {t('access.save')}
              </Action>
              {draft.client && (
                <Action variant="secondary" disabled={busy} onPress={() => setConfirm('delete')}>
                  {t('sharedClients.delete')}
                </Action>
              )}
            </div>
          </div>
          <ConfirmDialog
            isOpen={Boolean(confirm)}
            onOpenChange={(open) => {
              if (!open) setConfirm(undefined);
            }}
            triggerLabel={t('common.confirm')}
            title={t(
              confirm === 'delete' ? 'sharedClients.delete' : 'sharedClients.removeAssignments',
            )}
            description={t('sharedClients.revoke')}
            impact={draft.name}
            cancelLabel={t('common.cancel')}
            confirmLabel={t('common.confirm')}
            failureMessage={error || t('common.failed')}
            tone="danger"
            onConfirm={() => apply(confirm === 'delete')}
          />
        </EditorDrawer>
      )}
    </>
  );
}
