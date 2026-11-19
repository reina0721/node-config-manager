'use client';
import { useState, lazy, Suspense } from 'react';
const PlanReview = lazy(() => import('./plan-review'));
import { Section } from '@community-go/surface-foundation/layout';
import { DataTable } from '@community-go/ui-adapter/data-display';
import { Action } from '@community-go/ui-adapter/action';
import { TextField, PasswordField } from '@community-go/ui-adapter/form-field';
import { AlertBanner, Badge } from '@community-go/ui-adapter/feedback';
import { useNodeManagement, type JobResult, type ConfigPlan } from '../../../src/node-management';
import {
  NodePage,
  Code,
  OperationButton,
  TaskResult,
  useNodeQuery,
  NodeLoading,
  useNodeText,
} from './common';
export default function DnsPage() {
  const api = useNodeManagement();
  const q = useNodeQuery(api.dns);
  const t = useNodeText();
  const [result, setResult] = useState<JobResult | null>(null);
  const [zone, setZone] = useState('');
  const [token, setToken] = useState('');
  const validZone = /^[0-9a-f]{32}$/i.test(zone.trim());
  const [renewalError, setRenewalError] = useState('');
  const [error, setError] = useState('');
  const [saved, setSaved] = useState(false);
  const [pending, setPending] = useState(false);
  const [renewal, setRenewal] = useState<ConfigPlan | null>(null);
  const save = async () => {
    if (!validZone || !token.trim() || pending) return;
    setPending(true);
    setSaved(false);
    setError('');
    try {
      await api.credentials(zone.trim(), token.trim());
      setToken('');
      setSaved(true);
      setError('');
      void q.refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setPending(false);
    }
  };
  return (
    <NodePage
      name="dns"
      loading={q.loading}
      refreshing={q.refreshing}
      error={q.error}
      refresh={q.refresh}
    >
      {q.data ? (
        <>
          <Section title={t('dns.records')}>
            <DataTable
              label={t('dns.records')}
              rows={q.data.records.map((r) => ({ ...r, id: r.name }))}
              emptyContent={t('common.empty')}
              columns={[
                { id: 'name', label: t('dns.record'), rowHeader: true, render: (r) => r.name },
                { id: 'A', label: t('dns.a'), render: (r) => r.A },
                { id: 'AAAA', label: t('dns.aaaa'), render: (r) => r.AAAA || '—' },
                { id: 'proxy', label: t('dns.proxy'), render: () => t('dns.direct') },
              ]}
            />
            <div className="p-5">
              <OperationButton
                label={t('dns.verify')}
                risk={t('dns.verifyRisk')}
                input={{ operation: 'dns-check' }}
                onResult={setResult}
              />
            </div>
          </Section>
          <Section title={t('dns.certificates')} contentInset>
            <div className="grid gap-5 md:grid-cols-2">
              {q.data.certificates.map((c) => (
                <div key={c.kind} className="min-w-0">
                  <h3 className="mb-3 font-semibold">{t('dns.' + c.kind)}</h3>
                  <Badge tone={c.valid_24h ? 'success' : 'warning'}>
                    {t(c.valid_24h ? 'dns.valid' : 'common.attention')}
                  </Badge>
                  <div className="mt-3">
                    <Code>{c.details ?? t('common.unavailable')}</Code>
                  </div>
                </div>
              ))}
            </div>
            <div className="mt-5">
              <OperationButton
                label={t('dns.renew')}
                risk={t('dns.renewRisk')}
                input={{ operation: 'renew-certificates' }}
                onResult={(r) => {
                  setResult(r);
                  void q.refresh();
                }}
              />
            </div>
          </Section>
        </>
      ) : null}
      <Section
        title={t('dns.renewalPlan')}
        description={t('dns.renewalPlanDescription')}
        contentInset
      >
        <Action
          loading={pending}
          disabled={pending}
          onPress={() => {
            setPending(true);
            setRenewalError('');
            void api
              .configuration()
              .then((view) => api.preview(view.config))
              .then(setRenewal)
              .catch((e) => setRenewalError(e instanceof Error ? e.message : String(e)))
              .finally(() => setPending(false));
          }}
        >
          {t('common.preview')}
        </Action>
        {renewalError && (
          <AlertBanner
            icon="!"
            tone="danger"
            title={t('common.failed')}
            description={renewalError}
          />
        )}
      </Section>
      {renewal ? (
        <Suspense fallback={<NodeLoading />}>
          <PlanReview
            key={renewal.plan}
            plan={renewal}
            initialManualCertificates={false}
            onApplied={async () => {
              setRenewal(null);
              await q.refresh();
            }}
          />
        </Suspense>
      ) : null}
      <Section
        title={t('dns.credentials')}
        description={t('dns.credentialsDescription')}
        contentInset
      >
        <Badge tone={q.data?.credentials_configured ? 'success' : 'neutral'}>
          {t(q.data?.credentials_configured ? 'dns.configured' : 'dns.missing')}
        </Badge>
        <form
          className="mt-5 grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            void save();
          }}
        >
          <TextField
            label={t('dns.zone')}
            value={zone}
            error={zone && !validZone ? t('console.zoneError') : ''}
            placeholder={q.data?.zone ?? ''}
            onChange={(e) => setZone(e.target.value)}
          />
          <PasswordField
            label={t('dns.token')}
            purpose="new"
            showLabel={t('common.show')}
            hideLabel={t('common.hide')}
            value={token}
            onChange={(e) => setToken(e.target.value)}
          />
          <div>
            <Action
              type="submit"
              loading={pending}
              disabled={!validZone || !token.trim() || pending}
            >
              {t('dns.save')}
            </Action>
          </div>
        </form>
        {error ? (
          <AlertBanner icon="!" tone="danger" title={t('common.failed')} description={error} />
        ) : null}
        {saved ? (
          <p role="status" className="mt-4 text-success">
            {t('dns.saved')}
          </p>
        ) : null}
      </Section>
      <TaskResult result={result} />
    </NodePage>
  );
}
