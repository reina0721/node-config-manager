'use client';
import { useState, lazy, Suspense } from 'react';
const PlanReview = lazy(() => import('./plan-review'));
import { Section } from '@community-go/surface-foundation/layout';
import { Action } from '@community-go/ui-adapter/action';
import { TextField, TextAreaField, PasswordField } from '@community-go/ui-adapter/form-field';
import { AlertBanner, Badge } from '@community-go/ui-adapter/feedback';
import {
  useNodeManagement,
  nodeConfigurationSchema,
  type ConfigurationView,
  type ConfigPlan,
} from '../../../src/node-management';
import { NodePage, Details, useNodeQuery, NodeLoading, useNodeText } from './common';
const assetFields = ['domain', 'reality_domain', 'ipv4', 'ipv6'] as const;
const weightFields = ['xhttp_weight', 'ws_weight', 'reality_weight'] as const;

function isConfigurationObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

// Preserve newer fields that the administrator did not edit. Arrays are edited as a unit.
function mergeConfigDraft(base: unknown, draft: unknown, latest: unknown): unknown {
  if (JSON.stringify(draft) === JSON.stringify(base)) return latest;
  if (
    !isConfigurationObject(base) ||
    !isConfigurationObject(draft) ||
    !isConfigurationObject(latest)
  )
    return draft;
  const fields = new Set([...Object.keys(base), ...Object.keys(draft), ...Object.keys(latest)]);
  return Object.fromEntries(
    [...fields].flatMap((field) => {
      const value = mergeConfigDraft(base[field], draft[field], latest[field]);
      return value === undefined ? [] : [[field, value]];
    }),
  );
}

function validDomain(value: string) {
  return (
    value !== '' &&
    value.length <= 253 &&
    value.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label))
  );
}

function ConfigEditor({
  view,
  refresh,
}: Readonly<{ view: ConfigurationView; refresh: () => Promise<void> }>) {
  const api = useNodeManagement();
  const t = useNodeText();
  const [baseline, setBaseline] = useState(view);
  const [applied, setApplied] = useState(false);
  const [draft, setDraft] = useState(view.config);
  const [aliases, setAliases] = useState(view.config.node.aliases.join('\n'));
  const [weights, setWeights] = useState(() =>
    weightFields.map((field) => String(view.config.clients[field])),
  );
  const [token, setToken] = useState('');
  const [ticket, setTicket] = useState<string | undefined>();
  const [advanced, setAdvanced] = useState(false);
  const [raw, setRaw] = useState('');
  const [rawError, setRawError] = useState('');
  const [plan, setPlan] = useState<ConfigPlan | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState('');
  const validWeights = weights.map((weight) => /^\d{1,3}$/.test(weight) && Number(weight) <= 100);
  const total = weights.reduce((sum, weight) => sum + Number(weight), 0);
  const weightsValid = validWeights.every(Boolean) && total === 100;
  const assetErrors = assetFields.map((field) => {
    const value = draft.node[field];
    if (field === 'ipv4')
      return (
        !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value) ||
        value.split('.').some((part) => Number(part) > 255 || String(Number(part)) !== part)
      );
    if (field === 'ipv6') {
      if (!value) return false;
      if (!/^[a-f0-9:.]+$/i.test(value)) return true;
      try {
        return !new URL('http://[' + value + ']').hostname.startsWith('[');
      } catch {
        return true;
      }
    }
    return !validDomain(value);
  });
  const aliasError = draft.node.aliases.some(
    (value) => !validDomain(value) || value === draft.node.reality_domain,
  );
  const validAssets = !assetErrors.some(Boolean) && !aliasError;
  const aliasesChanged = aliases !== baseline.config.node.aliases.join('\n');
  const changedAssets = assetFields.filter(
    (field) => draft.node[field] !== baseline.config.node[field],
  );
  const changedWeights = weightFields.map(
    (field, index) => weights[index] !== String(baseline.config.clients[field]),
  );
  const dirty =
    advanced || aliasesChanged || changedAssets.length > 0 || changedWeights.some(Boolean);
  const stale = view.base !== baseline.base;
  if (stale && (applied || !dirty)) {
    setBaseline(view);
    setDraft(view.config);
    setAliases(view.config.node.aliases.join('\n'));
    setWeights(weightFields.map((field) => String(view.config.clients[field])));
    setPlan(null);
    setApplied(false);
    setAdvanced(false);
    setRaw('');
    setTicket(undefined);
  }
  const withWeights = () => ({
    ...draft,
    clients: {
      ...draft.clients,
      xhttp_weight: Number(weights[0]),
      ws_weight: Number(weights[1]),
      reality_weight: Number(weights[2]),
    },
  });
  const changed = () => {
    setApplied(false);
    setPlan(null);
    setError('');
  };
  const run = async (work: () => Promise<void>) => {
    setPending(true);
    setError('');
    try {
      await work();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      throw e;
    } finally {
      setPending(false);
    }
  };
  const preview = () =>
    run(async () => {
      let candidate = withWeights();
      if (advanced) {
        try {
          candidate = nodeConfigurationSchema.parse(JSON.parse(raw));
        } catch {
          setRawError(t('config.parseError'));
          return;
        }
      }
      const latest = await api.configuration();
      if (latest.base !== baseline.base) {
        await refresh();
        throw new Error(t('console.staleDraftDescription'));
      }
      const grant = ticket;
      setTicket(undefined);
      const next = await api.preview(candidate, grant);
      setDraft(candidate);
      setWeights(weightFields.map((field) => String(candidate.clients[field])));
      setPlan(next);
    });
  return (
    <>
      {stale && dirty && (
        <AlertBanner
          icon="!"
          tone="warning"
          title={t('console.staleDraft')}
          description={t(advanced ? 'console.draftConflict' : 'console.staleDraftDescription')}
          actionLabel={t('console.rebaseDraft')}
          onAction={() => {
            if (advanced) {
              try {
                const parsed = nodeConfigurationSchema.parse(JSON.parse(raw));
                const merged = nodeConfigurationSchema.parse(
                  mergeConfigDraft(baseline.config, parsed, view.config),
                );
                setRaw(JSON.stringify(merged, null, 2));
                setRawError('');
              } catch {
                setRawError(t('config.parseError'));
                return;
              }
            }
            const next = { ...view.config.node };
            for (const field of changedAssets) next[field] = draft.node[field];
            if (aliasesChanged) next.aliases = draft.node.aliases;
            else setAliases(next.aliases.join('\n'));
            setDraft({ ...view.config, node: next });
            setWeights(
              weightFields.map((field, index) =>
                changedWeights[index] ? (weights[index] ?? '') : String(view.config.clients[field]),
              ),
            );
            setBaseline(view);
            setPlan(null);
            setError('');
          }}
        />
      )}
      <Section title={t('config.assets')} description={t('config.assetsDescription')} contentInset>
        <div className="grid gap-5 md:grid-cols-2">
          {assetFields.map((field, index) => (
            <TextField
              key={field}
              label={t('config.' + (field === 'reality_domain' ? 'reality' : field))}
              value={draft.node[field]}
              error={assetErrors[index] ? t('console.assetError') : ''}
              disabled={advanced || pending}
              onChange={(e) => {
                changed();
                setDraft({ ...draft, node: { ...draft.node, [field]: e.target.value } });
              }}
            />
          ))}
        </div>
        <div className="mt-5">
          <TextAreaField
            label={t('config.aliases')}
            hint={t('config.aliasHint')}
            rows={3}
            value={aliases}
            error={aliasError ? t('console.assetError') : ''}
            disabled={advanced || pending}
            onChange={(e) => {
              setAliases(e.target.value);
              changed();
              setDraft({
                ...draft,
                node: {
                  ...draft.node,
                  aliases: e.target.value
                    .split('\n')
                    .map((v) => v.trim())
                    .filter(Boolean),
                },
              });
            }}
          />
        </div>
      </Section>
      <Section
        title={t('config.protocolWeights')}
        description={t('config.weightHint')}
        contentInset
      >
        <div className="grid gap-5 md:grid-cols-3">
          {weightFields.map((field, index) => (
            <TextField
              key={field}
              label={t('config.' + field)}
              value={weights[index] ?? ''}
              error={!validWeights[index] ? t('console.weightError') : ''}
              disabled={advanced || pending}
              onChange={(e) => {
                changed();
                setWeights(
                  weights.map((weight, position) => (position === index ? e.target.value : weight)),
                );
              }}
            />
          ))}
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-3" role="status">
          <Badge tone={weightsValid ? 'success' : 'warning'}>
            {t('console.weightTotal')} · {validWeights.every(Boolean) ? total + '%' : '—'}
          </Badge>
          {!advanced && !weightsValid && (
            <span className="text-sm text-danger">{t('config.weightError')}</span>
          )}
        </div>
      </Section>
      <Section
        title={t('config.baseline')}
        description={t('config.baselineDescription')}
        contentInset
      >
        <Details
          label={t('config.baseline')}
          items={[
            ['TLS', view.config.tls.protocols.join(', ')],
            [
              'HTTP/2 · HTTP/3',
              String(view.config.tls.http2) + ' · ' + String(view.config.tls.http3),
            ],
            [
              'HTTP / HTTPS / REALITY',
              [view.config.ports.http, view.config.ports.https, view.config.ports.reality].join(
                ' / ',
              ),
            ],
            [t('network.warp'), t(view.config.warp.enabled ? 'common.enabled' : 'common.disabled')],
            [
              t('network.cn'),
              t(view.config.cn_warp?.enabled ? 'common.enabled' : 'common.disabled'),
            ],
            [
              t('dns.certificates'),
              view.config.tls.domain_cert_dir + ' · ' + view.config.tls.ip_cert_dir,
            ],
          ]}
        />
      </Section>
      <Section title={t('config.advanced')} description={t('config.advancedRisk')} contentInset>
        <div className="grid gap-4">
          <PasswordField
            label={t('config.adminToken')}
            purpose="current"
            showLabel={t('common.show')}
            hideLabel={t('common.hide')}
            value={token}
            disabled={pending}
            onChange={(e) => setToken(e.target.value)}
          />
          <div>
            <Action
              variant="secondary"
              disabled={!token || pending || (!advanced && !weightsValid)}
              loading={pending}
              onPress={() => {
                void run(async () => {
                  const grant = await api.unlock(token);
                  setToken('');
                  setTicket(grant);
                  if (!advanced) setRaw(JSON.stringify(withWeights(), null, 2));
                  setAdvanced(true);
                  changed();
                }).catch(() => {});
              }}
            >
              {t('config.unlock')}
            </Action>
          </div>
          {advanced ? (
            <TextAreaField
              label={t('config.advancedConfig')}
              hint={t('config.advancedHint')}
              rows={16}
              value={raw}
              error={rawError || ''}
              disabled={pending}
              onChange={(e) => {
                setRaw(e.target.value);
                setRawError('');
                changed();
              }}
            />
          ) : (
            <Badge>{t('config.locked')}</Badge>
          )}
        </div>
      </Section>
      <div className="flex flex-wrap gap-3">
        <Action
          loading={pending}
          disabled={pending || stale || (advanced ? !ticket : !weightsValid || !validAssets)}
          onPress={() => {
            void preview().catch(() => {});
          }}
        >
          {t('common.preview')}
        </Action>
        {advanced && !ticket ? (
          <p className="text-sm text-ink-muted">{t('config.unlock')}</p>
        ) : null}
      </div>
      {error ? (
        <AlertBanner
          icon="!"
          tone="danger"
          title={t('common.failed')}
          description={error}
          announcement="urgent"
        />
      ) : null}
      {plan && !stale ? (
        <Suspense fallback={<NodeLoading />}>
          <PlanReview
            key={plan.plan}
            plan={plan}
            onApplied={async () => {
              setPlan(null);
              setApplied(true);
              await refresh();
            }}
          />
        </Suspense>
      ) : null}
    </>
  );
}
export default function ConfigPage() {
  const api = useNodeManagement();
  const q = useNodeQuery(api.configuration);
  return (
    <NodePage
      name="config"
      loading={q.loading}
      refreshing={q.refreshing}
      error={q.error}
      refresh={q.refresh}
    >
      {q.data ? <ConfigEditor view={q.data} refresh={q.refresh} /> : null}
    </NodePage>
  );
}
