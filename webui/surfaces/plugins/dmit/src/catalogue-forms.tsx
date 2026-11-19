'use client';
import type { ReactNode } from 'react';
import { TabsView } from '@community-go/ui-adapter/data-display';
import { SelectField, SwitchField, TextField } from '@community-go/ui-adapter/form-field';
import type {
  ManagedGroup,
  ManagedHost,
  ManagedInbound,
  NodeConfiguration,
} from '../../../src/node-management';
import { useNodeText } from './common';

import { protocols, split, toggle } from './catalogue-fields';

export function HostForm({
  data,
  update,
  config,
}: {
  data: ManagedHost;
  update: (value: ManagedHost) => void;
  config: NodeConfiguration;
}) {
  const t = useNodeText();
  const label = (key: string) => t('catalogue.' + key);
  const text = (
    field: 'remark' | 'description' | 'sni' | 'path' | 'host_header',
    hint?: string,
  ) => (
    <TextField
      label={label(field)}
      {...(hint ? { hint } : {})}
      value={data[field]}
      error={field === 'remark' && !data.remark.trim() ? t('console.requiredField') : ''}
      onChange={(e) => update({ ...data, [field]: e.target.value })}
    />
  );
  const list = (field: 'addresses' | 'tags' | 'alpn') => (
    <TextField
      label={label(field)}
      defaultValue={data[field].join(', ')}
      error={field === 'addresses' && !data.addresses.length ? t('console.requiredField') : ''}
      onChange={(e) => update({ ...data, [field]: split(e.target.value) })}
    />
  );
  const number = (field: 'port' | 'order', hint?: string) => (
    <TextField
      label={label(field)}
      {...(hint ? { hint } : {})}
      value={String(data[field])}
      error={
        field === 'port' && (!Number.isInteger(data.port) || data.port < 0 || data.port > 65535)
          ? t('console.portError')
          : ''
      }
      onChange={(e) => update({ ...data, [field]: Number(e.target.value) })}
    />
  );
  const tab = (id: string, fields: ReactNode) => ({
    id,
    label: label(id),
    content: <div className="grid gap-4 py-4">{fields}</div>,
  });
  const inbounds = [
    ...Object.entries(protocols).map(([value, label]) => ({ value, label })),
    ...Object.entries(config.management?.inbounds ?? {}).map(([value, inbound]) => ({
      value,
      label: inbound.remark,
    })),
  ];
  return (
    <TabsView
      label={label('hostForm')}
      variant="section"
      items={[
        tab(
          'basic',
          <>
            {text('remark')}
            {text('description')}
            <SelectField
              label={label('node')}
              options={[{ value: 'local', label: config.node.domain }]}
              value={data.node}
            />
            <SelectField
              label={label('inbound')}
              options={inbounds}
              value={data.inbound}
              onValueChange={(inbound) => update({ ...data, inbound })}
            />
            {list('addresses')}
            {number('port', label('portHint'))}
            {list('tags')}
            <SwitchField
              label={label('enabled')}
              description=""
              checked={data.enabled}
              onCheckedChange={(enabled) => update({ ...data, enabled })}
            />
          </>,
        ),
        tab(
          'security',
          <>
            {text('sni', label('inherit'))}
            {list('alpn')}
          </>,
        ),
        tab(
          'advanced',
          <>
            {text('host_header', label('inherit'))}
            {text('path', label('inherit'))}
            <SelectField
              label={label('fingerprint')}
              options={[
                { value: 'inherit', label: label('inherit') },
                ...['chrome', 'ios', 'firefox', 'qq'].map((value) => ({ value, label: value })),
              ]}
              value={data.fingerprint || 'inherit'}
              onValueChange={(value) =>
                update({ ...data, fingerprint: value === 'inherit' ? '' : value })
              }
            />
            {number('order')}
          </>,
        ),
        tab(
          'mihomo',
          <>
            <SelectField
              label={label('ipVersion')}
              value={data.mihomo_ip_version}
              options={(['dual', 'ipv4', 'ipv6', 'ipv4-prefer', 'ipv6-prefer'] as const).map(
                (value) => ({ value, label: label(value) }),
              )}
              onValueChange={(value) =>
                update({ ...data, mihomo_ip_version: value as ManagedHost['mihomo_ip_version'] })
              }
            />
            <SwitchField
              label="UDP"
              description=""
              checked={data.mihomo_udp}
              onCheckedChange={(mihomo_udp) => update({ ...data, mihomo_udp })}
            />
            {(['mihomo', 'xray'] as const).map((format) => (
              <SwitchField
                key={format}
                label={label(format + 'Visible')}
                description=""
                checked={data.formats.includes(format)}
                onCheckedChange={(checked) =>
                  update({
                    ...data,
                    formats: checked
                      ? [...new Set([...data.formats, format])]
                      : data.formats.filter((item) => item !== format),
                  })
                }
              />
            ))}
          </>,
        ),
      ]}
    />
  );
}

export function InboundForm({
  data,
  update,
  httpsPort,
}: {
  data: ManagedInbound;
  update: (value: ManagedInbound) => void;
  httpsPort: number;
}) {
  const t = useNodeText();
  const reality = data.protocol === 'reality';
  return (
    <div className="grid gap-4">
      <TextField
        label={t('catalogue.remark')}
        value={data.remark}
        error={!data.remark.trim() ? t('console.requiredField') : ''}
        onChange={(e) => update({ ...data, remark: e.target.value })}
      />
      <SelectField
        label={t('nodes.protocol')}
        value={data.protocol}
        options={Object.entries(protocols).map(([value, label]) => ({ value, label }))}
        onValueChange={(value) => {
          const protocol = value as ManagedInbound['protocol'];
          update({ ...data, protocol, port: 0 });
        }}
      />
      <TextField
        label={t('catalogue.path')}
        value={data.path}
        error={!data.path.startsWith('/') ? t('console.pathError') : ''}
        onChange={(e) => update({ ...data, path: e.target.value })}
      />
      <TextField
        label={t('catalogue.port')}
        disabled={!reality}
        value={String(reality ? data.port : httpsPort)}
        error={
          reality && (!Number.isInteger(data.port) || data.port < 1 || data.port > 65535)
            ? t('console.portError')
            : ''
        }
        onChange={(e) => update({ ...data, port: Number(e.target.value) })}
      />
      <SwitchField
        label={t('catalogue.enabled')}
        description=""
        checked={data.enabled}
        onCheckedChange={(enabled) => update({ ...data, enabled })}
      />
    </div>
  );
}

export function GroupForm({
  data,
  update,
  config,
}: {
  data: ManagedGroup;
  update: (value: ManagedGroup) => void;
  config: NodeConfiguration;
}) {
  const t = useNodeText();
  return (
    <div className="grid gap-4">
      <TextField
        label={t('catalogue.groupName')}
        value={data.name}
        error={!data.name.trim() ? t('console.requiredField') : ''}
        onChange={(e) => update({ ...data, name: e.target.value })}
      />
      <TextField
        label={t('catalogue.description')}
        value={data.description}
        onChange={(e) => update({ ...data, description: e.target.value })}
      />
      <SwitchField
        label={t('catalogue.enabled')}
        description=""
        checked={data.enabled}
        onCheckedChange={(enabled) => update({ ...data, enabled })}
      />
      {(['inbounds', 'hosts'] as const).map((resource) => (
        <div key={resource}>
          <h3 className="font-semibold">{t('nav.' + resource)}</h3>
          {Object.entries<{ remark: string }>(config.management?.[resource] ?? {}).map(
            ([id, entry]) => (
              <SwitchField
                key={id}
                label={entry.remark}
                description=""
                presentation="row"
                checked={data[resource].includes(id)}
                onCheckedChange={(checked) =>
                  update({ ...data, [resource]: toggle(data[resource], id, checked) })
                }
              />
            ),
          )}
        </div>
      ))}
    </div>
  );
}
