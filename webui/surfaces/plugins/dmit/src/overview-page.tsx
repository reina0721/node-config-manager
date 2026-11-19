'use client';
import { Section } from '@community-go/surface-foundation/layout';
import { Card, CardContent, CardHeader } from '@community-go/ui-adapter/card';
import { ProgressMeter } from '@community-go/ui-adapter/progress-meter';
import { AlertBanner, Badge } from '@community-go/ui-adapter/feedback';
import { useNodeManagement } from '../../../src/node-management';
import { NodePage, Details, bytes, number, ConsoleLink, useNodeQuery, useNodeText } from './common';
export default function OverviewPage() {
  const api = useNodeManagement();
  const q = useNodeQuery(api.overview, 5000);
  const entrances = useNodeQuery(api.nodes);
  const t = useNodeText();
  const d = q.data;
  const m = d?.metrics;
  const healthy =
    d?.services.filter((service) => service.enabled && service.state?.ActiveState === 'active') ??
    [];
  const anomalies =
    d?.services.filter(
      (service) => service.enabled !== (service.state?.ActiveState === 'active'),
    ) ?? [];
  const configured = d?.services.filter((service) => service.enabled).length ?? 0;
  return (
    <NodePage
      name="overview"
      loading={q.loading}
      refreshing={q.refreshing || entrances.refreshing}
      error={q.error}
      refresh={async () => {
        await Promise.all([q.refresh(), entrances.refresh()]);
      }}
    >
      {d?.recovery_required ? (
        <AlertBanner
          icon="!"
          tone="danger"
          title={t('overview.recovery')}
          description={t('overview.recoveryDescription')}
        />
      ) : null}
      {d && !d.configured ? (
        <AlertBanner
          icon="!"
          tone="warning"
          title={t('overview.notConfigured')}
          description={t('overview.setup')}
        />
      ) : null}
      {m ? (
        <>
          <div className="grid gap-5 md:grid-cols-3">
            <Card>
              <CardHeader title={t('overview.cpu')} />
              <CardContent>
                {m.cpu_percent === null ? (
                  <p className="text-ink-muted">{t('overview.twoSamples')}</p>
                ) : (
                  <ProgressMeter
                    label={t('overview.cpu')}
                    value={Math.round(m.cpu_percent * 10) / 10}
                  />
                )}
              </CardContent>
            </Card>
            <Card>
              <CardHeader title={t('overview.memory')} />
              <CardContent>
                {m.memory ? (
                  <>
                    <p className="mb-3 text-sm text-ink-muted">
                      {bytes(m.memory.used_bytes)} / {bytes(m.memory.total_bytes)}
                    </p>
                    <ProgressMeter
                      label={t('overview.memory')}
                      value={Math.round((100 * m.memory.used_bytes) / m.memory.total_bytes)}
                    />
                  </>
                ) : (
                  t('common.unavailable')
                )}
              </CardContent>
            </Card>
            <Card>
              <CardHeader title={t('overview.disk')} />
              <CardContent>
                {m.disk ? (
                  <>
                    <p className="mb-3 text-sm text-ink-muted">
                      {bytes(m.disk.total_bytes - m.disk.available_bytes)} /{' '}
                      {bytes(m.disk.total_bytes)}
                    </p>
                    <ProgressMeter
                      label={t('overview.disk')}
                      value={Math.round(
                        (100 * (m.disk.total_bytes - m.disk.available_bytes)) / m.disk.total_bytes,
                      )}
                    />
                  </>
                ) : (
                  t('common.unavailable')
                )}
              </CardContent>
            </Card>
          </div>
        </>
      ) : null}
      {d ? (
        <>
          <Section title={t('overview.services')} contentInset>
            <div className="grid gap-4">
              <div className="flex flex-wrap items-center gap-3">
                <Badge tone={anomalies.length ? 'warning' : 'success'}>
                  {healthy.length} / {configured} · {t('console.runningServices')}
                </Badge>
                <ConsoleLink to="dmit.services">{t('nav.services')}</ConsoleLink>
              </div>
              {anomalies.length > 0 && (
                <ul className="grid gap-2">
                  {anomalies.map((service) => (
                    <li key={service.name} className="flex flex-wrap items-center gap-2">
                      <strong>{service.name}</strong>
                      <Badge tone="warning">
                        {t(service.enabled ? 'common.attention' : 'overview.unexpectedService')}
                      </Badge>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </Section>
          {entrances.data && (
            <Section
              title={t('nodes.protocols')}
              contentInset
              action={<ConsoleLink to="dmit.nodes">{t('nav.nodes')}</ConsoleLink>}
            >
              <ul className="flex flex-wrap gap-3">
                {entrances.data.protocols.map((protocol) => (
                  <li key={protocol.name}>
                    <Badge tone="info">
                      {protocol.name} · {protocol.port}
                    </Badge>
                  </li>
                ))}
              </ul>
            </Section>
          )}
          <Section title={t('common.current')} contentInset>
            <Details
              label={t('common.current')}
              items={[
                [t('common.current'), d.current ?? '—'],
                [t('common.version'), d.version],
                [t('overview.integrity'), t(d.integrity ? 'common.healthy' : 'common.attention')],
                [
                  t('overview.uptime'),
                  m?.uptime_seconds === null || m?.uptime_seconds === undefined
                    ? '—'
                    : number(m.uptime_seconds / 3600) + ' h',
                ],
              ]}
            />
            <div className="mt-4 flex flex-wrap gap-4">
              <ConsoleLink to="dmit.network">{t('nav.network')}</ConsoleLink>
            </div>
          </Section>
        </>
      ) : null}
    </NodePage>
  );
}
