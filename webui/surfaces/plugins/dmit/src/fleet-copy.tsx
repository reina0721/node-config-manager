'use client';

import { useState } from 'react';
import { Section } from '@community-go/surface-foundation/layout';
import { Action } from '@community-go/ui-adapter/action';
import { AlertBanner, Badge } from '@community-go/ui-adapter/feedback';
import { SelectField, SwitchField } from '@community-go/ui-adapter/form-field';
import {
  useNodeManagement,
  type CopyPreview,
  type CopyResource,
  type CopySource,
  type ManagedJob,
} from '../../../src/node-management';
import { useNodeText } from './common';
import PlanReview from './plan-review';

type NodeOption = { value: string; label: string };
const lastJobKey = 'nodectl-last-copy-job';
const resourceKey = ({ kind, id }: CopyResource) => kind + '/' + id;

function resourcesOf(catalogue: CopySource['catalogue']) {
  const labelled = <T,>(
    kind: CopyResource['kind'],
    items: Record<string, T> | undefined,
    name: (item: T) => string,
  ) => Object.entries(items ?? {}).map(([id, item]) => ({ kind, id, name: name(item) }));
  return [
    ...labelled('inbound', catalogue.inbounds, (item) => item.remark),
    ...labelled('host', catalogue.hosts, (item) => item.remark),
    ...labelled('group', catalogue.groups, (item) => item.name),
    ...labelled('upstream', catalogue.upstreams, (item) => item.name),
    ...labelled('rule', catalogue.rules, (item) => item.name),
  ];
}

export default function FleetCopy({ nodes }: Readonly<{ nodes: NodeOption[] }>) {
  const api = useNodeManagement();
  const t = useNodeText();
  const label = (key: string) => t('fleet.copy.' + key);
  const [source, setSource] = useState('local');
  const [target, setTarget] = useState('');
  const [revisions, setRevisions] = useState<{ source: CopySource; target: CopySource }>();
  const [selected, setSelected] = useState(new Set<string>());
  const [preview, setPreview] = useState<CopyPreview>();
  const [job, setJob] = useState<ManagedJob>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const run = async (work: () => Promise<void>) => {
    setBusy(true);
    setError('');
    try {
      await work();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  const reset = () => {
    setRevisions(undefined);
    setPreview(undefined);
    setSelected(new Set());
    setError('');
  };
  const recover = async () => {
    const saved = sessionStorage.getItem(lastJobKey)?.split('/');
    if (!saved?.[0] || !saved[1]) throw new Error(label('noJob'));
    setJob(await api.jobDetails(saved[1], saved[0]));
  };
  const rows = revisions ? resourcesOf(revisions.source.catalogue) : [];
  const targetName = nodes.find((node) => node.value === target)?.label;
  const previewing = !!preview?.review;
  return (
    <>
      <Section title={label('title')} description={label('description')} contentInset>
        <div className="grid gap-4">
          {error && (
            <AlertBanner icon="!" tone="danger" title={t('common.failed')} description={error} />
          )}
          <div className="grid gap-4 md:grid-cols-2">
            <SelectField
              label={label('source')}
              disabled={busy || previewing}
              value={source}
              options={nodes}
              onValueChange={(value) => {
                setSource(value);
                reset();
              }}
            />
            <SelectField
              label={label('target')}
              disabled={busy || previewing}
              value={target}
              options={[{ value: '', label: label('choose') }, ...nodes]}
              onValueChange={(value) => {
                setTarget(value);
                reset();
              }}
            />
          </div>
          <div className="flex flex-wrap gap-3">
            <Action
              variant="secondary"
              disabled={busy || previewing || source === target || !targetName}
              onPress={() =>
                void run(async () => {
                  reset();
                  const revisions = await Promise.all([
                    api.copySource(source),
                    api.copySource(target),
                  ]);
                  setRevisions({ source: revisions[0], target: revisions[1] });
                })
              }
            >
              {label('load')}
            </Action>
            <Action variant="secondary" disabled={busy} onPress={() => void run(recover)}>
              {label('recover')}
            </Action>
          </div>
          {job && (
            <AlertBanner
              tone={job.ok === true ? 'success' : job.ok === false ? 'danger' : 'info'}
              title={
                job.ok === true
                  ? t('common.complete')
                  : job.ok === false
                    ? t('common.failed')
                    : job.phase
              }
              icon={job.ok === true ? '✓' : '!'}
              description={job.result?.message ?? job.id}
            />
          )}
          {revisions && (
            <>
              {!rows.length && <p>{label('empty')}</p>}
              <div className="grid gap-2 md:grid-cols-2">
                {rows.map((row) => {
                  const key = resourceKey(row);
                  return (
                    <SwitchField
                      key={key}
                      label={row.name}
                      description={label(row.kind)}
                      checked={selected.has(key)}
                      disabled={busy || previewing}
                      onCheckedChange={(enabled) => {
                        setSelected((previous) => {
                          const next = new Set(previous);
                          if (enabled) next.add(key);
                          else next.delete(key);
                          return next;
                        });
                        setPreview(undefined);
                      }}
                    />
                  );
                })}
              </div>
              <div>
                <Action
                  disabled={busy || previewing || selected.size === 0 || !targetName}
                  onPress={() =>
                    void run(async () => {
                      setPreview(
                        await api.previewCopy({
                          source,
                          target,
                          source_base: revisions.source.base,
                          target_base: revisions.target.base,
                          request: globalThis.crypto.randomUUID(),
                          resources: rows
                            .filter((row) => selected.has(resourceKey(row)))
                            .map(({ kind, id }) => ({ kind, id })),
                        }),
                      );
                    })
                  }
                >
                  {t('common.preview')}
                </Action>
              </div>
            </>
          )}
          {preview && (
            <>
              <ul className="grid gap-2 text-sm">
                {preview.resources.map((row) => (
                  <li key={row.kind + '/' + row.source} className="break-all">
                    {label(row.kind)} · {row.name}{' '}
                    {row.dependency && <Badge tone="info">{label('dependency')}</Badge>}
                    <div className="text-xs font-mono">
                      {row.source} → {row.target}
                    </div>
                  </li>
                ))}
              </ul>
              {preview.conflicts.map((issue) => (
                <AlertBanner
                  key={[issue.code, issue.source, issue.field].join('/')}
                  icon="!"
                  tone="danger"
                  title={label(issue.code)}
                  description={[
                    preview.resources.find(
                      (row) => row.kind === issue.kind && row.source === issue.source,
                    )?.name,
                    issue.value,
                  ]
                    .filter((value) => value != null)
                    .join(' · ')}
                />
              ))}
            </>
          )}
        </div>
      </Section>
      {preview?.review && preview.apply_job && targetName && (
        <PlanReview
          key={preview.review.plan}
          plan={preview.review}
          onBack={() => setPreview(undefined)}
          copy={{
            node: target,
            onApply: () => sessionStorage.setItem(lastJobKey, target + '/' + preview.apply_job),
          }}
          onApplied={async () => {
            reset();
            await run(recover);
          }}
        />
      )}
    </>
  );
}
