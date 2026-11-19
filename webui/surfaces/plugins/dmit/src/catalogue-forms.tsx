'use client';
import type { ReactNode } from 'react';
import { TabsView } from '@community-go/ui-adapter/data-display';
import { SelectField, SwitchField, TextField } from '@community-go/ui-adapter/form-field';
import type {
  InboundCombination,
  ManagedGroup,
  ManagedHost,
  ManagedInbound,
  NodeConfiguration,
} from '../../../src/node-management';
import { useNodeText } from './common';

import {
  fallbackParents,
  hasHttpPath,
  inboundStack,
  managedProtocol,
  managedProtocolNames,
  protocols,
  split,
  toggle,
  transportNames,
} from './catalogue-fields';

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
  const selected = config.management?.inbounds?.[data.inbound];
  const stack = inboundStack(
    selected ?? (data.inbound === 'ws' || data.inbound === 'reality' ? data.inbound : 'xhttp'),
  );
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
              onValueChange={(inbound) => {
                const target = config.management?.inbounds?.[inbound];
                const next = inboundStack(
                  target ?? (inbound === 'ws' || inbound === 'reality' ? inbound : 'xhttp'),
                );
                update({
                  ...data,
                  inbound,
                  path: !hasHttpPath(next.transport) ? '' : data.path,
                  alpn:
                    next.security === 'reality'
                      ? []
                      : data.alpn.filter(
                          (value) => next.transport !== 'ws' || value === 'http/1.1',
                        ),
                  host_header:
                    !hasHttpPath(next.transport) || next.security !== 'tls' ? '' : data.host_header,
                });
              }}
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
            {stack.security !== 'none' && text('sni', label('inherit'))}
            {stack.security === 'tls' && list('alpn')}
          </>,
        ),
        tab(
          'advanced',
          <>
            {hasHttpPath(stack.transport) &&
              stack.security === 'tls' &&
              text('host_header', label('inherit'))}
            {hasHttpPath(stack.transport) && text('path', label('inherit'))}
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
  config,
  combinations,
  errors,
}: Readonly<{
  data: ManagedInbound;
  update: (value: ManagedInbound) => void;
  config: NodeConfiguration;
  combinations: readonly InboundCombination[] | undefined;
  errors: Readonly<Record<string, string | undefined>>;
}>) {
  const t = useNodeText();
  const stack = inboundStack(data);
  const grpc = stack.transport === 'grpc';
  const dedicated = stack.listener === 'dedicated';
  const fallback = stack.listener === 'fallback';
  const ports = fallbackParents(config, data.enabled);
  const port = dedicated
    ? data.port
    : fallback
      ? (ports.find(([id]) => id === data.fallback_parent)?.[1].port ?? 0)
      : config.ports.https;
  const listenerLabels = {
    'shared-https': t('catalogue.sharedHttps'),
    dedicated: t(
      stack.transport === 'hysteria' || stack.transport === 'mkcp'
        ? 'catalogue.dedicatedUdp'
        : 'catalogue.dedicated',
    ),
    fallback: t('catalogue.samePortFallback'),
  };
  const protocol = managedProtocol(data.protocol);
  const supported = combinations?.filter((item) => item.protocol === protocol) ?? [];
  const selected = supported.filter((item) => item.transport === stack.transport);
  const securityLabels = {
    none: t('catalogue.noTransportSecurity'),
    tls: 'TLS',
    reality: 'REALITY',
  };
  const select = (selection: InboundCombination) => {
    const { xhttp_mode, flow, vless_encryption, fallback_parent, ...common } = data;
    update({
      ...common,
      ...(selection.protocol === 'vless' &&
      selection.transport === 'raw' &&
      selection.security === 'tls' &&
      vless_encryption !== undefined
        ? { vless_encryption }
        : {}),
      ...(selection.listener === 'fallback' && fallback_parent ? { fallback_parent } : {}),
      ...(xhttp_mode && selection.protocol === 'vless' && selection.transport === 'xhttp'
        ? { xhttp_mode }
        : {}),
      ...(flow && selection.protocol === 'vless' && selection.transport === 'raw' ? { flow } : {}),
      protocol: selection.protocol,
      transport: selection.transport,
      security: selection.security,
      listener: selection.listener,
      path:
        (selection.transport === 'grpc') !== grpc
          ? ''
          : hasHttpPath(selection.transport) || grpc
            ? data.path
            : '',
      port: selection.listener === 'dedicated' ? data.port : 0,
    });
  };
  return (
    <div className="grid gap-4">
      <TextField
        label={t('catalogue.remark')}
        value={data.remark}
        error={errors.remark ?? ''}
        onChange={(e) => update({ ...data, remark: e.target.value })}
      />
      {combinations?.length ? (
        <>
          <SelectField
            label={t('nodes.protocol')}
            value={protocol}
            options={[...new Set(combinations.map((item) => item.protocol))].map((value) => ({
              value,
              label: managedProtocolNames[value],
            }))}
            onValueChange={(value) => {
              const next = combinations.find((item) => item.protocol === value);
              if (next) select(next);
            }}
          />
          <SelectField
            label={t('catalogue.transport')}
            value={stack.transport}
            error={errors.transport ?? ''}
            options={[...new Set(supported.map((item) => item.transport))].map((value) => ({
              value,
              label: transportNames[value],
            }))}
            onValueChange={(value) => {
              const changes = supported.filter((item) => item.transport === value);
              const next = changes.find((item) => item.security === stack.security) ?? changes[0];
              if (next) select(next);
            }}
          />
          <SelectField
            label={t('catalogue.security')}
            value={stack.security}
            options={[...new Set(selected.map((item) => item.security))].map((value) => ({
              value,
              label: securityLabels[value],
            }))}
            onValueChange={(security) => {
              const next = selected.find((item) => item.security === security);
              if (next) select(next);
            }}
          />
          <SelectField
            label={t('catalogue.listener')}
            value={stack.listener}
            options={selected
              .filter((item) => item.security === stack.security)
              .map(({ listener }) => ({
                value: listener,
                label: listenerLabels[listener],
              }))}
            onValueChange={(listener) => {
              const next = selected.find(
                (item) => item.security === stack.security && item.listener === listener,
              );
              if (next) select(next);
            }}
          />
        </>
      ) : (
        <SelectField
          label={t('nodes.protocol')}
          value={data.protocol}
          options={Object.entries(protocols).map(([value, label]) => ({ value, label }))}
          onValueChange={(value) => {
            if (value === 'reality' || value === 'ws' || value === 'xhttp')
              update({ ...data, protocol: value, port: 0 });
          }}
        />
      )}
      {(hasHttpPath(stack.transport) || grpc) && (
        <TextField
          label={t(grpc ? 'catalogue.grpcService' : 'catalogue.path')}
          hint={t(
            grpc
              ? 'catalogue.grpcServiceError'
              : dedicated
                ? 'catalogue.dedicatedPathHint'
                : 'catalogue.sharedPathHint',
          )}
          value={data.path}
          error={errors.path ?? ''}
          onChange={(e) => update({ ...data, path: e.target.value })}
        />
      )}
      {fallback && (
        <SelectField
          label={t('catalogue.fallbackParent')}
          options={ports.map(([value, inbound]) => ({ value, label: inbound.remark }))}
          value={data.fallback_parent ?? ''}
          error={errors.fallback_parent ?? ''}
          onValueChange={(fallback_parent) => update({ ...data, fallback_parent })}
        />
      )}
      <TextField
        label={t('catalogue.port')}
        disabled={!dedicated}
        hint={t(
          dedicated
            ? 'catalogue.independentPortHint'
            : fallback
              ? 'catalogue.fallbackPortHint'
              : 'catalogue.inheritedPortHint',
        )}
        value={String(port)}
        error={errors.port ?? ''}
        onChange={(e) => update({ ...data, port: Number(e.target.value) })}
      />
      {combinations?.length &&
      data.protocol === 'vless' &&
      stack.transport === 'raw' &&
      stack.security === 'tls' ? (
        <SelectField
          label={t('catalogue.vlessEncryption')}
          error={errors.vless_encryption ?? ''}
          value={data.vless_encryption === undefined ? 'inherit' : String(data.vless_encryption)}
          options={[
            { value: 'inherit', label: t('catalogue.inherit') },
            { value: 'false', label: t('catalogue.tlsOnly') },
          ]}
          onValueChange={(value) => {
            const next = { ...data };
            if (value === 'inherit') delete next.vless_encryption;
            else next.vless_encryption = false;
            update(next);
          }}
        />
      ) : null}
      {combinations?.length && data.protocol === 'vless' && stack.transport === 'xhttp' ? (
        <SelectField
          label={t('catalogue.xhttpMode')}
          error={errors.xhttp_mode ?? ''}
          value={data.xhttp_mode ?? 'inherit'}
          options={['inherit', 'auto', 'packet-up', 'stream-up', 'stream-one'].map((value) => ({
            value,
            label: value === 'inherit' ? t('catalogue.inherit') : value,
          }))}
          onValueChange={(value) => {
            const next = { ...data };
            if (value === 'inherit') delete next.xhttp_mode;
            else next.xhttp_mode = value as NonNullable<ManagedInbound['xhttp_mode']>;
            update(next);
          }}
        />
      ) : null}
      {combinations?.length && data.protocol === 'vless' && stack.transport === 'raw' ? (
        <SelectField
          label={t('catalogue.vlessFlow')}
          error={errors.flow ?? ''}
          value={data.flow ?? 'inherit'}
          options={[
            { value: 'inherit', label: t('catalogue.inherit') },
            { value: 'none', label: t('catalogue.noFlow') },
            { value: 'vision', label: 'Vision' },
          ]}
          onValueChange={(value) => {
            const next = { ...data };
            if (value === 'inherit') delete next.flow;
            else if (value === 'none' || value === 'vision') next.flow = value;
            update(next);
          }}
        />
      ) : null}
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
