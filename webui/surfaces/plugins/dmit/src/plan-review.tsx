'use client';
import { useState } from 'react';
import { Section } from '@community-go/surface-foundation/layout';
import { Action } from '@community-go/ui-adapter/action';
import { TextField, SwitchField } from '@community-go/ui-adapter/form-field';
import { ConfirmDialog } from '@community-go/ui-adapter/overlays';
import { AlertBanner, Badge } from '@community-go/ui-adapter/feedback';
import { DataTable } from '@community-go/ui-adapter/data-display';
import { useNodeManagement, type ConfigPlan, type JobResult } from '../../../src/node-management';
import { Details, Code, useNodeText } from './common';

function ChangeValue({ value }: { value: unknown }) {
  if (value === null || value === undefined) return <>—</>;
  if (typeof value === 'object') {
    return (
      <details>
        <summary className="cursor-pointer">{'{…}'}</summary>
        <Code>{JSON.stringify(value, null, 2)}</Code>
      </details>
    );
  }
  return <code className="break-all text-xs">{JSON.stringify(value)}</code>;
}
export default function PlanReview({
  plan,
  onApplied,
  onBack,
  allowDeployment = false,
  resourceReview = false,
  initialManualCertificates = true,
  copy,
}: Readonly<{
  plan: ConfigPlan;
  onApplied: () => Promise<void>;
  onBack?: () => void;
  allowDeployment?: boolean;
  resourceReview?: boolean;
  initialManualCertificates?: boolean;
  copy?: { node: string; onApply: () => void };
}>) {
  const api = useNodeManagement();
  const t = useNodeText();
  const [confirm, setConfirm] = useState('');
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<JobResult | null>(null);
  const [manual, setManual] = useState(initialManualCertificates);
  const [skip, setSkip] = useState(true);
  const [email, setEmail] = useState('');
  const [ca, setCa] = useState(false);
  const [warp, setWarp] = useState(false);
  const deployment = typeof result?.deployment === 'object' ? result.deployment : null;
  const checked = result?.plan === plan.plan && (result.checked === true || deployment !== null);
  const ready = checked && !pending && (resourceReview || confirm.trim() === plan.plan);
  const applyLabel = t(resourceReview ? 'config.applyResource' : 'common.apply');
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
  const preparationChanged = () => {
    setResult(null);
    setConfirm('');
  };
  return (
    <>
      {error ? (
        <AlertBanner icon="!" tone="danger" title={t('common.failed')} description={error} />
      ) : null}
      {plan ? (
        <>
          <Section
            title={t('config.review')}
            description={resourceReview ? t('config.resourceReview') : plan.risk}
            action={
              onBack && (
                <Action variant="secondary" disabled={pending} onPress={onBack}>
                  {t('catalogue.backToEdit')}
                </Action>
              )
            }
          >
            <div className="grid gap-4 p-5">
              <ol
                className="flex flex-wrap items-center gap-3"
                aria-label={t('console.reviewSteps')}
              >
                <li>
                  <Badge tone="success">1. {t('console.previewDone')}</Badge>
                </li>
                <li aria-current={checked ? undefined : 'step'}>
                  <Badge tone={checked ? 'success' : 'info'}>2. {t('console.checkStep')}</Badge>
                </li>
                <li aria-current={checked ? 'step' : undefined}>
                  <Badge tone={checked ? 'info' : 'neutral'}>3. {t('console.applyStep')}</Badge>
                </li>
              </ol>
              <Details
                label={t('config.review')}
                items={[
                  [
                    t('config.plan'),
                    <span className="break-all font-mono text-xs" key="plan">
                      {plan.plan}
                    </span>,
                  ],
                  [t('common.safe'), t(plan.advanced ? 'common.protected' : 'common.asset')],
                ]}
              />
            </div>
            <DataTable
              label={t('config.review')}
              rows={plan.changes.map((c) => ({ ...c, id: c.field }))}
              emptyContent={t('common.empty')}
              columns={[
                {
                  id: 'field',
                  label: t('common.field'),
                  rowHeader: true,
                  render: (c) => (
                    <span className="break-all">
                      {c.field}
                      <span className="ml-2">
                        <Badge tone={c.protected ? 'warning' : 'info'}>
                          {t(c.protected ? 'common.protected' : 'common.asset')}
                        </Badge>
                      </span>
                    </span>
                  ),
                },
                {
                  id: 'before',
                  label: t('common.before'),
                  render: (c) => <ChangeValue value={c.before} />,
                },
                {
                  id: 'after',
                  label: t('common.after'),
                  render: (c) => <ChangeValue value={c.after} />,
                },
              ]}
            />
            <div className="p-5">
              <details>
                <summary className="cursor-pointer font-semibold">{t('config.diff')}</summary>
                <Code>{plan.diff}</Code>
              </details>
            </div>
          </Section>
          <Section title={t('common.check')} contentInset>
            <Action
              loading={pending && !confirmOpen}
              disabled={pending}
              onPress={() => {
                void run(async () => {
                  preparationChanged();
                  setResult(await api.check(plan.plan, copy?.node));
                }).catch(() => {});
              }}
            >
              {t('common.check')}
            </Action>
            {allowDeployment && !copy && !plan.restores_identity && (
              <details className="mt-5">
                <summary className="cursor-pointer font-semibold">{t('config.deployment')}</summary>
                <p className="mt-3 text-sm text-ink-muted">{t('config.deploymentDescription')}</p>
                <div className="mt-4 grid gap-4 md:grid-cols-2">
                  <SwitchField
                    label={t('config.manualCertificates')}
                    description=""
                    checked={manual}
                    onCheckedChange={(v) => {
                      setManual(v);
                      preparationChanged();
                    }}
                  />
                  <SwitchField
                    label={t('config.skipDependencies')}
                    description=""
                    checked={skip}
                    onCheckedChange={(v) => {
                      setSkip(v);
                      preparationChanged();
                    }}
                  />
                  <SwitchField
                    label={t('config.caTerms')}
                    description=""
                    checked={ca}
                    onCheckedChange={(v) => {
                      setCa(v);
                      preparationChanged();
                    }}
                  />
                  <SwitchField
                    label={t('config.warpTerms')}
                    description=""
                    checked={warp}
                    onCheckedChange={(v) => {
                      setWarp(v);
                      preparationChanged();
                    }}
                  />
                </div>
                <div className="mt-4">
                  <TextField
                    label={t('config.email')}
                    value={email}
                    onChange={(e) => {
                      setEmail(e.target.value);
                      preparationChanged();
                    }}
                  />
                </div>
                <div className="mt-4">
                  <Action
                    variant="secondary"
                    disabled={pending}
                    onPress={() => {
                      void run(async () => {
                        preparationChanged();
                        setResult(
                          await api.prepareDeployment(plan.plan, {
                            manual_certificates: manual,
                            skip_dependencies: skip,
                            accept_ca_terms: ca,
                            accept_warp_terms: warp,
                            ...(email ? { acme_email: email } : {}),
                          }),
                        );
                      }).catch(() => {});
                    }}
                  >
                    {t('config.prepareDeployment')}
                  </Action>
                </div>
              </details>
            )}
          </Section>
          {deployment ? (
            <Section title={t('config.deployPlan')} contentInset>
              <Details
                label={t('config.deployPlan')}
                items={[
                  [t('config.deploymentDigest'), result?.deployment_digest],
                  [t('common.phase'), deployment.stages.join(' → ')],
                ]}
              />
              <ul className="mt-4 list-disc space-y-2 pl-5 text-sm text-warning">
                {deployment.recovery_limits.map((r) => (
                  <li key={r}>{r}</li>
                ))}
              </ul>
              {deployment.dns_changes.length ? (
                <div className="mt-4">
                  <Code>{JSON.stringify(deployment.dns_changes, null, 2)}</Code>
                </div>
              ) : null}
            </Section>
          ) : null}
          <Section
            title={applyLabel}
            description={t(resourceReview ? 'config.resourceConfirmHint' : 'config.confirmHint')}
            contentInset
          >
            <div className="grid gap-4">
              {checked ? (
                <Badge tone={deployment ? 'info' : 'success'}>
                  {t(deployment ? 'config.deploymentPrepared' : 'config.checked')}
                </Badge>
              ) : null}
              {checked && !resourceReview && (
                <div className="grid gap-3">
                  <Code>{plan.plan}</Code>
                  <TextField
                    label={t('config.confirmation')}
                    value={confirm}
                    disabled={pending}
                    error={
                      confirm && confirm.trim() !== plan.plan ? t('config.confirmMismatch') : ''
                    }
                    onChange={(e) => setConfirm(e.target.value)}
                  />
                </div>
              )}
              <div>
                <Action variant="danger" disabled={!ready} onPress={() => setConfirmOpen(true)}>
                  {applyLabel}
                </Action>
              </div>
              <ConfirmDialog
                isOpen={confirmOpen}
                onOpenChange={setConfirmOpen}
                triggerLabel={applyLabel}
                title={applyLabel}
                description={t(deployment ? 'config.deploymentApplyRisk' : 'config.applyRisk')}
                impact={<Code>{plan.plan}</Code>}
                cancelLabel={t('common.cancel')}
                confirmLabel={t('common.confirm')}
                confirmDisabled={!ready}
                failureMessage={error || t('common.failed')}
                tone="danger"
                onConfirm={() =>
                  run(async () => {
                    copy?.onApply();
                    await api.apply(plan.plan, plan.plan, copy?.node);
                    await onApplied();
                  })
                }
              />
            </div>
          </Section>
        </>
      ) : null}
    </>
  );
}
