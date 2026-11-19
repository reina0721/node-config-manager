'use client';
/* eslint-disable react-refresh/only-export-components */
import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { useFrontendTranslation, formatDate, formatNumber } from '@community-go/i18n';
import { Page, PageHeader, Section } from '@community-go/surface-foundation/layout';
import { Action } from '@community-go/ui-adapter/action';
import {
  PageLoadingSurface,
  type PageLoadingKind,
} from '@community-go/surface-foundation/states-operations';
import { RouteLink, route } from '@community-go/plugin-framework/plugin';
import { AlertBanner, Badge } from '@community-go/ui-adapter/feedback';
import { ConfirmDialog } from '@community-go/ui-adapter/overlays';
import { DescriptionList } from '@community-go/ui-adapter/description-list';
import {
  useNodeManagement,
  type OperationInput,
  type JobResult,
} from '../../../src/node-management';
export function useNodeText() {
  const { t } = useFrontendTranslation();
  return (key: string) => t('dmit.' + key);
}
export function useNodeQuery<T>(load: () => Promise<T>, interval = 0) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const generation = useRef(0);
  const pending = useRef<{ promise: Promise<void>; foreground: boolean } | null>(null);
  const request = useCallback(
    (mode: 'initial' | 'refresh' | 'background') => {
      if (mode === 'refresh') setRefreshing(true);
      if (pending.current) {
        if (mode === 'refresh') pending.current.foreground = true;
        return pending.current.promise;
      }
      const current = generation.current;
      const entry = {
        foreground: mode !== 'background',
        promise: Promise.resolve()
          .then(load)
          .then((value) => {
            if (generation.current !== current) return;
            setData(value);
            setError('');
          })
          .catch((cause: unknown) => {
            if (generation.current === current && entry.foreground)
              setError(cause instanceof Error ? cause.message : String(cause));
          })
          .finally(() => {
            if (generation.current !== current) return;
            pending.current = null;
            setLoading(false);
            setRefreshing(false);
          }),
      };
      pending.current = entry;
      return entry.promise;
    },
    [load],
  );
  const refresh = useCallback(() => request('refresh'), [request]);
  useEffect(() => {
    const current = generation.current;
    void Promise.resolve().then(() => {
      if (current === generation.current) void request('initial');
    });
    const timer = interval ? setInterval(() => void request('background'), interval) : undefined;
    return () => {
      generation.current += 1;
      pending.current = null;
      if (timer) clearInterval(timer);
    };
  }, [interval, request]);
  return { data, error, loading, refreshing, refresh };
}

export function NodeLoading({ kind = 'page' }: Readonly<{ kind?: PageLoadingKind }>) {
  const t = useNodeText();
  return <PageLoadingSurface label={t('common.loading')} kind={kind} />;
}

export function ConsoleLink({ to, children }: Readonly<{ to: string; children: ReactNode }>) {
  return (
    <RouteLink target={route(to)} className="font-semibold text-brand underline underline-offset-4">
      {children}
    </RouteLink>
  );
}

export function NodePage({
  name,
  loading,
  refreshing,
  error,
  refresh,
  actions,
  children,
}: Readonly<{
  name: string;
  loading?: boolean;
  refreshing?: boolean;
  error?: string;
  refresh: () => Promise<void>;
  actions?: ReactNode;
  children: ReactNode;
}>) {
  const t = useNodeText();
  const kind = [
    'hosts',
    'inbounds',
    'groups',
    'clients',
    'upstreams',
    'rules',
    'services',
    'fleet',
  ].includes(name)
    ? 'collection'
    : name === 'config'
      ? 'form'
      : name === 'overview'
        ? 'catalog'
        : 'page';

  if (loading && !error) return <NodeLoading kind={kind} />;

  return (
    <Page>
      <PageHeader
        title={t(name + '.title')}
        description={t(name + '.description')}
        actions={
          <>
            {actions}
            <Action
              variant="secondary"
              loading={refreshing === true}
              disabled={refreshing === true}
              onPress={() => void refresh()}
            >
              {t(refreshing ? 'common.refreshing' : 'common.refresh')}
            </Action>
          </>
        }
      />
      {error ? (
        <AlertBanner
          icon="!"
          tone="danger"
          title={t('common.error')}
          description={error}
          actionLabel={t('common.retry')}
          onAction={() => void refresh()}
          announcement="urgent"
        />
      ) : null}
      {children}
    </Page>
  );
}
export function Details({
  label,
  items,
}: Readonly<{ label: string; items: readonly (readonly [string, ReactNode])[] }>) {
  return (
    <DescriptionList
      label={label}
      columns={2}
      items={items.map(([term, description], i) => ({ id: String(i), term, description }))}
    />
  );
}
export function Code({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all rounded-control border border-border bg-surface-inset p-4 text-xs leading-6 text-ink">
      {children}
    </pre>
  );
}
export function Timestamp({ value }: Readonly<{ value: number }>) {
  return (
    <time dateTime={new Date(value * 1000).toISOString()}>
      {formatDate('zh-CN', value * 1000, { dateStyle: 'short', timeStyle: 'medium' })}
    </time>
  );
}
export function number(value: number) {
  return formatNumber('zh-CN', value, { maximumFractionDigits: 1 });
}
export function bytes(value: number | null | undefined) {
  if (value === null || value === undefined) return '—';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i++;
  }
  return number(value) + ' ' + units[i];
}
export function OperationButton({
  label,
  risk,
  input,
  onResult,
  disabled = false,
}: Readonly<{
  label: string;
  risk: string;
  input: Omit<OperationInput, 'confirm'>;
  onResult?: (result: JobResult) => void;
  disabled?: boolean;
}>) {
  const api = useNodeManagement();
  const t = useNodeText();
  const [error, setError] = useState('');
  const [pending, setPending] = useState(false);
  const operation = { ...input, confirm: input.operation };
  const run = () =>
    new Promise<void>((resolve, reject) => {
      setPending(true);
      setError('');
      // Token rotation returns a one-time value. Keep its confirmation in place until the value arrives.
      const onAccepted = input.operation === 'subscription-rotate' ? undefined : resolve;
      void api
        .operate(operation, onAccepted)
        .then((result) => {
          onResult?.(result);
          resolve();
        })
        .catch((cause: unknown) => {
          const error = cause instanceof Error ? cause : new Error(String(cause));
          setError(error.message);
          reject(error);
        })
        .finally(() => setPending(false));
    });
  return (
    <div className="grid gap-3">
      {disabled ? (
        <Action disabled variant="secondary">
          {label}
        </Action>
      ) : (
        <ConfirmDialog
          triggerLabel={label}
          title={label}
          description={risk}
          impact={<Badge tone="warning">{input.service ?? input.operation}</Badge>}
          cancelLabel={t('common.cancel')}
          confirmLabel={t('common.confirm')}
          failureMessage={error || t('common.failed')}
          confirmDisabled={pending}
          onConfirm={run}
        />
      )}
      {error ? (
        <p role="alert" className="text-sm text-danger">
          {error}
        </p>
      ) : null}
    </div>
  );
}
export function TaskResult({ result }: Readonly<{ result: JobResult | null }>) {
  const t = useNodeText();
  if (
    !result ||
    (!result.message &&
      !result.token &&
      result.log === undefined &&
      !result.checks &&
      !result.diagnostics &&
      !result.backup)
  )
    return null;
  return (
    <Section title={t('common.details')} contentInset>
      {result.message ? <p className="mb-4 text-sm leading-7">{result.message}</p> : null}
      {result.token ? (
        <div className="grid gap-3">
          <strong>{t('nodes.token')}</strong>
          <Code>{result.token}</Code>
          <p className="text-sm text-warning">{t('nodes.saveToken')}</p>
        </div>
      ) : null}
      {result.log !== undefined ? (
        <details>
          <summary className="cursor-pointer font-medium">{t('operations.logs')}</summary>
          <Code>{result.log}</Code>
        </details>
      ) : null}
      {result.checks ? (
        <div className="grid gap-3">
          {result.checks.map((check) => (
            <div key={check.name} className="border-b border-border pb-3">
              <Badge tone={check.ok ? 'success' : 'danger'}>{check.name}</Badge>
              <p className="mt-2 text-sm text-ink-muted">
                {check.ok ? check.detail : check.remedy}
              </p>
            </div>
          ))}
        </div>
      ) : null}
      {result.diagnostics ? (
        <Details
          label={t('network.results')}
          items={result.diagnostics.map((d) => [
            d.name,
            <span key={d.name}>
              <Badge tone={d.ok ? 'success' : 'danger'}>
                {t(d.ok ? 'common.healthy' : 'common.attention')}
              </Badge>
              <Code>{d.trace ?? '—'}</Code>
            </span>,
          ])}
        />
      ) : null}
      {result.backup ? <Code>{result.backup}</Code> : null}
    </Section>
  );
}
