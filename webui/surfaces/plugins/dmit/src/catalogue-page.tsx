'use client';
import { lazy, Suspense, useState } from 'react';
import { Section } from '@community-go/surface-foundation/layout';
import { Action } from '@community-go/ui-adapter/action';
import { DataTable } from '@community-go/ui-adapter/data-display';
import { AlertBanner } from '@community-go/ui-adapter/feedback';
import { SwitchField } from '@community-go/ui-adapter/form-field';
import { ConfirmDialog } from '@community-go/ui-adapter/overlays';
import {
  useNodeManagement,
  type CatalogueEdit,
  type ConfigPlan,
  type JobResult,
  type ProxyAccess,
  type NodeConfiguration,
} from '../../../src/node-management';
import { NodePage, TaskResult, useNodeQuery, NodeLoading, useNodeText } from './common';
import { EditorDrawer, EnabledBadge, ListFilters, useListFilters } from './collection-controls';
import { protocols, toggle } from './catalogue-fields';
const PlanReview = lazy(() => import('./plan-review'));
const GroupForm = lazy(() =>
  import('./catalogue-forms').then((module) => ({ default: module.GroupForm })),
);
const HostForm = lazy(() =>
  import('./catalogue-forms').then((module) => ({ default: module.HostForm })),
);
const InboundForm = lazy(() =>
  import('./catalogue-forms').then((module) => ({ default: module.InboundForm })),
);
const RuleForm = lazy(() =>
  import('./egress-forms').then((module) => ({ default: module.RuleForm })),
);
const RuleMatch = lazy(() =>
  import('./egress-forms').then((module) => ({ default: module.RuleMatch })),
);
const UpstreamForm = lazy(() =>
  import('./egress-forms').then((module) => ({ default: module.UpstreamForm })),
);

const emptyServices = () => Promise.resolve([]);

type Kind = CatalogueEdit['kind'];
const names = {
  host: 'hosts',
  inbound: 'inbounds',
  group: 'groups',
  upstream: 'upstreams',
  rule: 'rules',
} as const;

function newItem(kind: Kind): CatalogueEdit {
  switch (kind) {
    case 'host':
      return {
        kind,
        id: null,
        value: {
          remark: '',
          description: '',
          node: 'local',
          inbound: 'xhttp',
          addresses: [],
          port: 0,
          tags: [],
          enabled: false,
          sni: '',
          alpn: [],
          host_header: '',
          path: '',
          fingerprint: '',
          order: 0,
          mihomo_ip_version: 'dual',
          mihomo_udp: true,
          formats: ['xray', 'mihomo'],
        },
      };
    case 'inbound':
      return {
        kind,
        id: null,
        value: { remark: '', protocol: 'xhttp', path: '', port: 0, enabled: false },
      };
    case 'upstream':
      return {
        kind,
        id: null,
        value: {
          name: '',
          enabled: false,
          protocol: 'socks5',
          address: '',
          port: 1080,
          server_name: '',
        },
      };
    case 'rule':
      return {
        kind,
        id: null,
        value: {
          name: '',
          enabled: false,
          order: 10,
          inbounds: [],
          domains: [],
          ips: [],
          outbound: 'direct',
        },
      };
    case 'group':
      return {
        kind,
        id: null,
        value: { name: '', description: '', enabled: true, inbounds: [], hosts: [] },
      };
  }
}

type Row = {
  id: string;
  name: string;
  detail: string;
  enabled: boolean;
  edit: CatalogueEdit | null;
};

function managedRows(config: NodeConfiguration, kind: Kind): Row[] {
  const m = config.management;
  switch (kind) {
    case 'inbound':
      return Object.entries(m?.inbounds ?? {}).map(([id, value]) => ({
        id,
        name: value.remark,
        detail: protocols[value.protocol] + ' · ' + (value.port || config.ports.https),
        enabled: value.enabled,
        edit: { id, kind, value },
      }));
    case 'host':
      return Object.entries(m?.hosts ?? {}).map(([id, value]) => ({
        id,
        name: value.remark,
        detail: value.addresses.join(', '),
        enabled: value.enabled,
        edit: { id, kind, value },
      }));
    case 'group':
      return Object.entries(m?.groups ?? {}).map(([id, value]) => ({
        id,
        name: value.name,
        detail: value.description,
        enabled: value.enabled,
        edit: { id, kind, value },
      }));
    case 'upstream':
      return Object.entries(m?.upstreams ?? {}).map(([id, value]) => ({
        id,
        name: value.name,
        detail: value.protocol + ' · ' + value.address + ':' + value.port,
        enabled: value.enabled,
        edit: { id, kind, value },
      }));
    case 'rule':
      return Object.entries(m?.rules ?? {})
        .sort(([, a], [, b]) => a.order - b.order)
        .map(([id, value]) => ({
          id,
          name: value.name,
          detail: String(value.order),
          enabled: value.enabled,
          edit: { id, kind, value },
        }));
  }
}

export default function CataloguePage({ kind }: { kind: Kind }) {
  const api = useNodeManagement();
  const query = useNodeQuery(api.configuration);
  const serviceView = useNodeQuery(kind === 'upstream' ? api.services : emptyServices);
  const filters = useListFilters();
  const t = useNodeText();
  const [edit, setEdit] = useState<CatalogueEdit | null>(null);
  const [baseline, setBaseline] = useState<{ base: string; edit: CatalogueEdit } | null>(null);
  const stale = Boolean(baseline && query.data?.base !== baseline.base);
  const [group, setGroup] = useState<string | null>(null);
  const [plan, setPlan] = useState<ConfigPlan | null>(null);
  const [probe, setProbe] = useState<JobResult | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const config = query.data?.config;
  const beginEdit = (draft: CatalogueEdit) => {
    if (!query.data) return;
    setEdit(draft);
    setBaseline({ base: query.data.base, edit: draft });
    setPlan(null);
    setError('');
  };
  const visibleError = error && (
    <AlertBanner icon="!" tone="danger" title={t('common.failed')} description={error} />
  );
  const testUpstream = async (id: string) => {
    setBusy(true);
    setError('');
    setProbe(null);
    try {
      setProbe(await api.testUpstream(id));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  const preview = async (change: CatalogueEdit) => {
    if (!baseline || stale) return;
    setBusy(true);
    setError('');
    setPlan(null);
    try {
      setPlan(await api.previewCatalogue(change, baseline.base));
      setEdit(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  const rows: Row[] = !config
    ? []
    : [
        ...(kind === 'inbound'
          ? Object.entries(protocols).map(([id, name]) => ({
              id,
              name,
              detail: String(id === 'reality' ? config.ports.reality : config.ports.https),
              enabled: true,
              edit: null,
            }))
          : []),
        ...(kind === 'upstream'
          ? [
              {
                id: 'direct',
                name: t('egress.direct'),
                detail: t('egress.native'),
                enabled: true,
                edit: null,
              },
              {
                id: 'block',
                name: t('egress.block'),
                detail: t('egress.reject'),
                enabled: true,
                edit: null,
              },
              ...(['usque-warp', 'usque-cn'] as const).map((id) => {
                const service = serviceView.data?.find((item) => item.name === id);
                return {
                  id,
                  name: t(id === 'usque-warp' ? 'egress.warp' : 'egress.cn-warp'),
                  detail: service?.state?.ActiveState ?? t('common.unavailable'),
                  enabled: service?.enabled ?? false,
                  edit: null,
                };
              }),
            ]
          : []),
        ...managedRows(config, kind),
      ];
  return (
    <NodePage
      name={names[kind]}
      loading={query.loading}
      refreshing={query.refreshing || serviceView.refreshing}
      error={query.error}
      refresh={async () => {
        await Promise.all([query.refresh(), serviceView.refresh()]);
      }}
    >
      <TaskResult result={probe} />
      {!edit && visibleError}
      {config && (
        <>
          <Section
            title={t('nav.' + names[kind])}
            action={
              <Action disabled={busy} onPress={() => beginEdit(newItem(kind))}>
                {t('catalogue.add')}
              </Action>
            }
          >
            <div className="px-5 py-3">
              <ListFilters filters={filters} />
            </div>
            <DataTable
              label={t('nav.' + names[kind])}
              rows={rows.filter((row) =>
                filters.matches(row.enabled, row.name, row.detail, row.id),
              )}
              emptyContent={t(filters.active ? 'console.noMatches' : 'common.empty')}
              columns={[
                {
                  id: 'name',
                  label: t('catalogue.remark'),
                  rowHeader: true,
                  render: (row) => row.name,
                },
                { id: 'detail', label: t('catalogue.details'), render: (row) => row.detail },
                {
                  id: 'enabled',
                  label: t('nodes.status'),
                  render: (row) => <EnabledBadge enabled={row.enabled} />,
                },
                {
                  id: 'actions',
                  label: t('access.actions'),
                  render: (row) =>
                    row.edit ? (
                      <div className="flex flex-wrap gap-2">
                        <Action
                          variant="secondary"
                          disabled={busy}
                          onPress={() => {
                            if (row.edit) beginEdit(row.edit);
                          }}
                        >
                          {t('console.edit')}
                        </Action>
                        {kind === 'upstream' && row.enabled && (
                          <Action
                            variant="secondary"
                            disabled={busy}
                            onPress={() => void testUpstream(row.id)}
                          >
                            {t('egress.test')}
                          </Action>
                        )}
                        {kind === 'group' && (
                          <Action
                            variant="secondary"
                            disabled={busy}
                            onPress={() => {
                              setGroup(row.id);
                              setEdit(null);
                              setPlan(null);
                            }}
                          >
                            {t('catalogue.members')}
                          </Action>
                        )}
                      </div>
                    ) : (
                      t('catalogue.builtin')
                    ),
                },
              ]}
            />
          </Section>
          <Suspense fallback={<NodeLoading />}>
            {edit?.value && (
              <EditorDrawer
                title={
                  t(edit.id ? 'console.edit' : 'catalogue.add') + ' · ' + t('nav.' + names[kind])
                }
                description={t(names[kind] + '.description')}
                dirty={JSON.stringify(edit) !== JSON.stringify(baseline?.edit)}
                busy={busy}
                onClose={() => {
                  setEdit(null);
                  setError('');
                }}
              >
                {visibleError}
                {stale && query.data && (
                  <>
                    <AlertBanner
                      icon="!"
                      tone="warning"
                      title={t('console.staleDraft')}
                      description={t('console.draftConflict')}
                    />
                    <Action
                      variant="secondary"
                      onPress={() => {
                        const current = edit.id
                          ? rows.find((row) => row.id === edit.id)?.edit
                          : baseline?.edit;
                        if (!current || !baseline || !query.data) return;
                        const previous = Object.entries(baseline.edit.value ?? {});
                        const changed = Object.fromEntries(
                          Object.entries(edit.value ?? {}).filter(
                            ([field, value]) =>
                              JSON.stringify(value) !==
                              JSON.stringify(previous.find(([name]) => name === field)?.[1]),
                          ),
                        );
                        setEdit({
                          ...edit,
                          value: { ...current.value, ...changed },
                        } as CatalogueEdit);
                        setBaseline({ base: query.data.base, edit: current });
                      }}
                    >
                      {t('console.rebaseDraft')}
                    </Action>
                    {edit.id && !rows.some((row) => row.id === edit.id) && (
                      <p role="status">{t('common.unavailable')}</p>
                    )}
                  </>
                )}
                {edit.kind === 'host' && (
                  <HostForm
                    key={edit.id ?? 'new'}
                    config={config}
                    data={edit.value}
                    update={(value) => setEdit({ ...edit, value })}
                  />
                )}
                {edit.kind === 'inbound' && (
                  <InboundForm
                    httpsPort={config.ports.https}
                    data={edit.value}
                    update={(value) => setEdit({ ...edit, value })}
                  />
                )}
                {edit.kind === 'group' && (
                  <GroupForm
                    config={config}
                    data={edit.value}
                    update={(value) => setEdit({ ...edit, value })}
                  />
                )}
                {edit.kind === 'upstream' && (
                  <UpstreamForm
                    data={edit.value}
                    update={(value) =>
                      setEdit(
                        value.protocol === edit.value?.protocol
                          ? { ...edit, value }
                          : { id: edit.id, kind: edit.kind, value },
                      )
                    }
                    writeCredential={(credential, clear_credential) =>
                      setEdit({
                        id: edit.id,
                        kind: edit.kind,
                        value: edit.value,
                        ...(credential ? { credential } : {}),
                        clear_credential,
                      })
                    }
                  />
                )}
                {edit.kind === 'rule' && (
                  <RuleForm
                    config={config}
                    data={edit.value}
                    update={(value) => setEdit({ ...edit, value })}
                  />
                )}
                <div className="mt-4 flex flex-wrap gap-3">
                  <Action
                    loading={busy}
                    disabled={busy || stale}
                    onPress={() => void preview(edit)}
                  >
                    {t('catalogue.preview')}
                  </Action>
                  {edit.id && (
                    <Action
                      variant="secondary"
                      disabled={busy || stale}
                      onPress={() => void preview({ id: edit.id, kind: edit.kind, value: null })}
                    >
                      {t('catalogue.delete')}
                    </Action>
                  )}
                </div>
              </EditorDrawer>
            )}
            {kind === 'rule' && <RuleMatch config={config} />}
            {group && <Members key={group} id={group} onClose={() => setGroup(null)} />}
            {plan && (
              <PlanReview
                key={plan.plan}
                plan={plan}
                onApplied={async () => {
                  setPlan(null);
                  await query.refresh();
                }}
              />
            )}
          </Suspense>
        </>
      )}
    </NodePage>
  );
}

function Members({ id, onClose }: { id: string; onClose: () => void }) {
  const api = useNodeManagement();
  const query = useNodeQuery(api.proxyAccess);
  const t = useNodeText();
  return query.data ? (
    <MemberEditor id={id} initial={query.data} onClose={onClose} />
  ) : (
    <EditorDrawer
      title={t('catalogue.members')}
      description={t('catalogue.membersRisk')}
      dirty={false}
      onClose={onClose}
    >
      {query.error ? (
        <>
          <AlertBanner
            icon="!"
            tone="danger"
            title={t('common.failed')}
            description={query.error}
          />
          <Action onPress={() => void query.refresh()}>{t('common.refresh')}</Action>
        </>
      ) : (
        <NodeLoading kind="form" />
      )}
    </EditorDrawer>
  );
}

function MemberEditor({
  id,
  initial,
  onClose,
}: {
  id: string;
  initial: ProxyAccess;
  onClose: () => void;
}) {
  const api = useNodeManagement();
  const t = useNodeText();
  const [members, setMembers] = useState(() =>
    initial.users.filter((user) => user.groups.includes(id)).map((user) => user.username),
  );
  const [error, setError] = useState('');
  const [baseline, setBaseline] = useState(members);
  const dirty = JSON.stringify([...baseline].sort()) !== JSON.stringify([...members].sort());
  const [saved, setSaved] = useState(false);
  return (
    <EditorDrawer
      title={t('catalogue.members')}
      description={t('catalogue.membersRisk')}
      dirty={dirty}
      onClose={onClose}
    >
      {error && (
        <AlertBanner icon="!" tone="danger" title={t('common.failed')} description={error} />
      )}
      {saved && <p role="status">{t('common.complete')}</p>}
      {initial.users.map((user) => (
        <SwitchField
          key={user.username}
          label={user.username}
          description=""
          presentation="row"
          checked={members.includes(user.username)}
          onCheckedChange={(checked) => {
            setSaved(false);
            setMembers(toggle(members, user.username, checked));
          }}
        />
      ))}
      <ConfirmDialog
        title={t('catalogue.members')}
        description={t('catalogue.membersRisk')}
        confirmLabel={t('access.save')}
        triggerLabel={t('access.save')}
        cancelLabel={t('common.cancel')}
        impact={null}
        failureMessage={t('common.failed')}
        confirmDisabled={!dirty}
        onConfirm={async () => {
          setError('');
          try {
            await api.changeProxyAccess({ action: 'group-members', group: id, usernames: members });
            setBaseline(members);
            setSaved(true);
          } catch (e) {
            setError(e instanceof Error ? e.message : String(e));
            throw e;
          }
        }}
      />
    </EditorDrawer>
  );
}
