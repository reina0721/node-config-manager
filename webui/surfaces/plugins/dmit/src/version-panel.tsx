'use client';
import { useState } from 'react';
import { Section } from '@community-go/surface-foundation/layout';
import { AlertBanner } from '@community-go/ui-adapter/feedback';
import { TextField } from '@community-go/ui-adapter/form-field';
import { Action } from '@community-go/ui-adapter/action';
import { type JobResult, type VersionsView } from '../../../src/node-management';
import { Details, OperationButton, useNodeText } from './common';

function compareVersions(a: string, b: string) {
  const [majorA = 0, minorA = 0, patchA = 0] = a.replace(/^v/, '').split('.').map(Number);
  const [majorB = 0, minorB = 0, patchB = 0] = b.replace(/^v/, '').split('.').map(Number);
  return majorA - majorB || minorA - minorB || patchA - patchB;
}

export default function VersionPanel({
  data,
  error,
  onResult,
}: Readonly<{
  data: VersionsView | null;
  error: string;
  onResult: (result: JobResult) => void;
}>) {
  const t = useNodeText();
  const [version, setVersion] = useState('');
  const valid = /^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(version);
  const minimum = data?.proxy_access_enabled ? 'v0.7.0' : 'v0.6.5';
  const pending = Boolean(data?.status && data.status.finished === null);
  const direction = valid && data ? compareVersions(version, data.running) : 0;
  const action = direction < 0 ? 'rollbackVersion' : direction > 0 ? 'upgrade' : 'update';

  return (
    <Section
      title={t('operations.versions')}
      description={t('operations.upgradeRisk')}
      contentInset
    >
      <div className="grid gap-4">
        <Details
          label={t('operations.versions')}
          items={[[t('operations.installedVersion'), data?.running ?? '—']]}
        />
        {error || data?.lookup_failed ? (
          <AlertBanner
            icon="!"
            tone="warning"
            title={t('operations.lookupFailed')}
            description={error}
          />
        ) : null}
        {data?.proxy_access_enabled ? (
          <p className="text-sm text-ink-muted">{t('operations.authVersion')}</p>
        ) : null}
        {data?.status ? (
          <AlertBanner
            icon={data.status.ok === false ? '!' : '↻'}
            tone={pending ? 'info' : data.status.ok ? 'success' : 'danger'}
            title={t(
              pending
                ? 'operations.switchPending'
                : data.status.ok
                  ? 'operations.switchComplete'
                  : 'operations.switchFailed',
            )}
            description={data.status.target}
          />
        ) : null}
        {data?.releases.some((tag) => compareVersions(tag, minimum) >= 0) ? (
          <div className="grid gap-2">
            <p className="text-sm text-ink-muted">{t('operations.releasedVersions')}</p>
            <div className="flex flex-wrap gap-2">
              {data.releases
                .filter((tag) => compareVersions(tag, minimum) >= 0)
                .map((tag) => (
                  <Action
                    key={tag}
                    variant="secondary"
                    disabled={pending}
                    onPress={() => setVersion(tag)}
                  >
                    {tag}
                  </Action>
                ))}
            </div>
          </div>
        ) : null}
        <TextField
          label={t('operations.upgradeVersion')}
          value={version}
          onChange={(e) => setVersion(e.target.value)}
        />
        <OperationButton
          label={t('operations.' + action)}
          risk={t('operations.upgradeRisk')}
          input={{ operation: 'upgrade', version }}
          disabled={!data || pending || !valid || compareVersions(version, minimum) < 0}
          onResult={onResult}
        />
      </div>
    </Section>
  );
}
