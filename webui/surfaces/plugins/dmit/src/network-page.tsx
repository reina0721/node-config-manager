'use client';
import { useState } from 'react';
import { Section } from '@community-go/surface-foundation/layout';
import { DataTable } from '@community-go/ui-adapter/data-display';
import { useNodeManagement, type JobResult } from '../../../src/node-management';
import {
  NodePage,
  Details,
  Timestamp,
  bytes,
  Code,
  OperationButton,
  TaskResult,
  useNodeQuery,
  useNodeText,
} from './common';
export default function NetworkPage() {
  const api = useNodeManagement();
  const q = useNodeQuery(api.network);
  const metrics = useNodeQuery(api.overview, 5000);
  const t = useNodeText();
  const [result, setResult] = useState<JobResult | null>(null);
  const d = q.data;
  const sample = metrics.data?.metrics;
  const counters = new Map(sample?.network?.map((row) => [row.interface, row]));
  const interfaces = (d?.interfaces ?? []).map((row) => ({
    ...row,
    id: row.ifname,
    counters: counters.get(row.ifname),
  }));
  return (
    <NodePage
      name="network"
      loading={q.loading}
      refreshing={q.refreshing || metrics.refreshing}
      error={q.error || metrics.error}
      refresh={async () => {
        await Promise.all([q.refresh(), metrics.refresh()]);
      }}
    >
      {d ? (
        <>
          <Section title={t('network.native')} contentInset>
            <Details
              label={t('network.native')}
              items={[
                [t('config.ipv4'), d.native.ipv4],
                [t('config.ipv6'), d.native.ipv6 || '—'],
                [t('network.warp'), t(d.warp.enabled ? 'common.enabled' : 'common.disabled')],
                [t('network.cn'), t(d.cn_warp?.enabled ? 'common.enabled' : 'common.disabled')],
              ]}
            />
            <div className="mt-5">
              <OperationButton
                label={t('network.diagnose')}
                risk={t('network.diagnoseRisk')}
                input={{ operation: 'network-check' }}
                onResult={setResult}
              />
            </div>
          </Section>
          <Section title={t('network.interfaces')}>
            <DataTable
              label={t('network.interfaces')}
              rows={interfaces}
              emptyContent={t('common.unavailable')}
              columns={[
                {
                  id: 'name',
                  label: t('overview.interface'),
                  rowHeader: true,
                  render: (i) => i.ifname,
                },
                { id: 'state', label: t('network.state'), render: (i) => i.operstate ?? '—' },
                { id: 'mtu', label: t('network.mtu'), render: (i) => i.mtu ?? '—' },
                {
                  id: 'address',
                  label: t('network.address'),
                  render: (i) =>
                    i.addr_info?.map((a) => a.local + '/' + a.prefixlen).join(' · ') ?? '—',
                },
                {
                  id: 'traffic',
                  label: t('console.networkTraffic'),
                  render: (row) =>
                    row.counters ? (
                      <div className="grid gap-1 whitespace-nowrap text-sm">
                        {(
                          [
                            [
                              'overview.rx',
                              row.counters.rx_bytes,
                              row.counters.rx_bytes_per_second,
                            ],
                            [
                              'overview.tx',
                              row.counters.tx_bytes,
                              row.counters.tx_bytes_per_second,
                            ],
                          ] as const
                        ).map(([label, total, rate]) => (
                          <span key={label}>
                            {t(label)} {bytes(total)}
                            {rate !== null && ' · ' + bytes(rate) + '/s'}
                          </span>
                        ))}
                      </div>
                    ) : (
                      '—'
                    ),
                },
              ]}
            />
            {sample && (
              <p className="px-5 py-3 text-xs text-ink-muted">
                {t('overview.source')} · {sample.source} · <Timestamp value={sample.sample_unix} />
              </p>
            )}
          </Section>
          <Section title={t('network.policy')} contentInset>
            {d.cn_warp ? (
              <Details
                label={t('network.cn')}
                items={[
                  [t('overview.interface'), d.cn_warp.interface],
                  ['Routing table', d.cn_warp.routing_table],
                  ['Rule priority', d.cn_warp.rule_priority],
                  ['Socket mark', d.cn_warp.socket_mark],
                ]}
              />
            ) : (
              <p className="text-sm text-ink-muted">{t('network.noCn')}</p>
            )}
            <div className="mt-5 grid gap-3">
              {(
                [
                  [t('network.routes') + ' · IPv4', d.routes_v4],
                  [t('network.routes') + ' · IPv6', d.routes_v6],
                  [t('network.rules') + ' · IPv4', d.rules],
                  [t('network.rules') + ' · IPv6', d.rules_v6],
                ] as const
              ).map(([title, content]) => (
                <details key={title}>
                  <summary className="cursor-pointer font-semibold">{title}</summary>
                  <Code>{content ?? t('common.unavailable')}</Code>
                </details>
              ))}
            </div>
          </Section>
        </>
      ) : null}
      <TaskResult result={result} />
    </NodePage>
  );
}
