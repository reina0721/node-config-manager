'use client';
import { useState } from 'react';
import { Section } from '@community-go/surface-foundation/layout';
import { Action } from '@community-go/ui-adapter/action';
import { AlertBanner } from '@community-go/ui-adapter/feedback';
import {
  PasswordField,
  SelectField,
  SwitchField,
  TextField,
} from '@community-go/ui-adapter/form-field';
import {
  useNodeManagement,
  type ManagedRule,
  type ManagedUpstream,
  type NodeConfiguration,
  type RoutingMatch,
  type UpstreamCredential,
} from '../../../src/node-management';
import { Details, useNodeText } from './common';
import { protocols, split, toggle } from './catalogue-fields';

function inboundOptions(config: NodeConfiguration) {
  return [
    ...Object.entries(protocols).map(([value, label]) => ({ value, label })),
    ...Object.entries(config.management?.inbounds ?? {}).map(([value, inbound]) => ({
      value,
      label: inbound.remark,
    })),
  ];
}

export function UpstreamForm({
  data,
  update,
  writeCredential,
  id,
  config,
}: {
  data: ManagedUpstream;
  id: string | null;
  config: NodeConfiguration;
  update: (value: ManagedUpstream) => void;
  writeCredential: (credential: UpstreamCredential | undefined, clear: boolean) => void;
}) {
  const t = useNodeText();
  const label = (key: string) => t('egress.' + key);
  const [username, setUsername] = useState('');
  const [secret, setSecret] = useState('');
  const [clear, setClear] = useState(false);
  const protocol = data.protocol;
  const pool = protocol === 'round-robin';
  const choices = Object.entries(config.management?.upstreams ?? {})
    .filter(([value, entry]) => value !== id && entry.protocol !== 'round-robin')
    .map(([value, entry]) => ({ value, label: entry.name }));

  const needsUsername =
    protocol === 'socks5' || protocol === 'socks5-tls' || protocol === 'https-connect';
  const needsUuid = protocol === 'vless' || protocol === 'vmess';
  const needsSni =
    protocol !== 'socks5' && protocol !== 'shadowsocks' && protocol !== 'shadowsocks-2022';
  const setPassword = (value: string, user: string) => {
    setSecret(value);
    writeCredential(
      !value
        ? undefined
        : protocol === 'vless' || protocol === 'vmess'
          ? { kind: protocol, id: value }
          : needsUsername
            ? { kind: 'password', username: user, password: value }
            : { kind: 'secret', secret: value },
      false,
    );
  };
  return (
    <div className="grid gap-4">
      <TextField
        label={label('name')}
        value={data.name}
        error={!data.name.trim() ? t('console.requiredField') : ''}
        onChange={(e) => update({ ...data, name: e.target.value })}
      />
      <SelectField
        label={t('nodes.protocol')}
        value={data.protocol}
        options={[
          { value: 'socks5', label: 'SOCKS5' },
          { value: 'socks5-tls', label: 'SOCKS5 TLS' },
          { value: 'https-connect', label: 'HTTPS CONNECT' },
          { value: 'vless', label: 'VLESS TLS' },
          { value: 'vmess', label: 'VMess TLS' },
          { value: 'trojan', label: 'Trojan TLS' },
          { value: 'shadowsocks', label: 'Shadowsocks AES-256-GCM' },
          { value: 'shadowsocks-2022', label: 'Shadowsocks-2022 AES-128-GCM' },
          { value: 'hysteria2', label: 'Hysteria2' },
          { value: 'round-robin', label: label('roundRobin') },
        ]}
        onValueChange={(value) => {
          setSecret('');
          setUsername('');
          setClear(false);
          const { via, members, ...common } = data;
          update({
            ...common,
            protocol: value as ManagedUpstream['protocol'],
            server_name: '',
            ...(value === 'round-robin'
              ? { address: '', port: 0, members: members ?? [] }
              : { port: data.port || 1080, ...(via ? { via } : {}) }),
          });
          if (value === 'round-robin') writeCredential(undefined, true);
        }}
      />
      {pool ? (
        <fieldset className="grid gap-2">
          <legend className="font-semibold">{label('poolMembers')}</legend>
          {choices.map((choice) => (
            <SwitchField
              key={choice.value}
              label={choice.label}
              description=""
              checked={(data.members ?? []).includes(choice.value)}
              onCheckedChange={(checked) =>
                update({
                  ...data,
                  members: toggle(data.members ?? [], choice.value, checked),
                })
              }
            />
          ))}
        </fieldset>
      ) : (
        <>
          <SelectField
            label={label('via')}
            value={data.via ?? 'direct'}
            options={[{ value: 'direct', label: label('direct') }, ...choices]}
            onValueChange={(value) => {
              const next = { ...data };
              if (value === 'direct') delete next.via;
              else next.via = value;
              update(next);
            }}
          />
          <TextField
            label={label('address')}
            value={data.address}
            error={!data.address.trim() ? t('console.requiredField') : ''}
            onChange={(e) => update({ ...data, address: e.target.value })}
          />
          <TextField
            label={t('catalogue.port')}
            value={String(data.port)}
            error={
              !Number.isInteger(data.port) || data.port < 1 || data.port > 65535
                ? t('console.portError')
                : ''
            }
            onChange={(e) => update({ ...data, port: Number(e.target.value) })}
          />
          {needsSni && (
            <TextField
              label={t('catalogue.sni')}
              value={data.server_name}
              onChange={(e) => update({ ...data, server_name: e.target.value })}
            />
          )}
          <SwitchField
            label={label('clear')}
            description=""
            checked={clear}
            onCheckedChange={(checked) => {
              setClear(checked);
              setSecret('');
              setUsername('');
              writeCredential(undefined, checked);
            }}
          />
          {!clear && (
            <>
              {needsUsername && (
                <TextField
                  label={t('access.username')}
                  value={username}
                  onChange={(e) => {
                    setUsername(e.target.value);
                    setPassword(secret, e.target.value);
                  }}
                />
              )}
              <PasswordField
                purpose="current"
                showLabel={t('common.show')}
                hideLabel={t('common.hide')}
                label={needsUuid ? label('uuid') : t('access.password')}
                hint={label('credentialHint')}
                value={secret}
                onChange={(e) => setPassword(e.target.value, username)}
              />
            </>
          )}
        </>
      )}
      <SwitchField
        label={t('catalogue.enabled')}
        description=""
        checked={data.enabled}
        onCheckedChange={(enabled) => update({ ...data, enabled })}
      />
    </div>
  );
}

export function RuleForm({
  data,
  update,
  config,
}: {
  data: ManagedRule;
  update: (value: ManagedRule) => void;
  config: NodeConfiguration;
}) {
  const t = useNodeText();
  const label = (key: string) => t('egress.' + key);
  const builtins = ['direct', 'block', 'cn-warp'].map((value) => ({ value, label: label(value) }));
  const upstreams = Object.entries(config.management?.upstreams ?? {}).map(([value, upstream]) => ({
    value,
    label: upstream.name,
  }));
  return (
    <div className="grid gap-4">
      <TextField
        label={label('name')}
        value={data.name}
        error={!data.name.trim() ? t('console.requiredField') : ''}
        onChange={(e) => update({ ...data, name: e.target.value })}
      />
      <TextField
        label={label('order')}
        value={String(data.order)}
        onChange={(e) => update({ ...data, order: Number(e.target.value) })}
      />
      <SelectField
        label={t('nav.upstreams')}
        options={[...builtins, ...upstreams]}
        value={data.outbound}
        onValueChange={(outbound) => update({ ...data, outbound })}
      />
      <SelectField
        label={label('network')}
        options={[
          { value: 'any', label: label('any') },
          { value: 'tcp', label: 'TCP' },
          { value: 'udp', label: 'UDP' },
        ]}
        value={data.network ?? 'any'}
        onValueChange={(value) =>
          update({ ...data, network: value === 'any' ? null : (value as 'tcp' | 'udp') })
        }
      />
      <TextField
        label={label('domains')}
        defaultValue={data.domains.join(', ')}
        onChange={(e) => update({ ...data, domains: split(e.target.value) })}
      />
      <TextField
        label={label('ips')}
        defaultValue={data.ips.join(', ')}
        onChange={(e) => update({ ...data, ips: split(e.target.value) })}
      />
      <TextField
        label={label('portMin')}
        value={String(data.port_min ?? '')}
        onChange={(e) =>
          update({ ...data, port_min: e.target.value ? Number(e.target.value) : null })
        }
      />
      <TextField
        label={label('portMax')}
        value={String(data.port_max ?? '')}
        onChange={(e) =>
          update({ ...data, port_max: e.target.value ? Number(e.target.value) : null })
        }
      />
      <h3 className="font-semibold">{label('inbounds')}</h3>
      {inboundOptions(config).map(({ value, label }) => (
        <SwitchField
          key={value}
          label={label}
          description=""
          presentation="row"
          checked={data.inbounds.includes(value)}
          onCheckedChange={(checked) =>
            update({ ...data, inbounds: toggle(data.inbounds, value, checked) })
          }
        />
      ))}
      <SwitchField
        label={t('catalogue.enabled')}
        description=""
        checked={data.enabled}
        onCheckedChange={(enabled) => update({ ...data, enabled })}
      />
    </div>
  );
}

export function RuleMatch({ config }: { config: NodeConfiguration }) {
  const api = useNodeManagement();
  const t = useNodeText();
  const label = (key: string) => t('egress.' + key);
  const [inbound, setInbound] = useState('xhttp');
  const [domain, setDomain] = useState('');
  const [ip, setIp] = useState('');
  const [port, setPort] = useState('443');
  const [network, setNetwork] = useState<'tcp' | 'udp'>('tcp');
  const [result, setResult] = useState<RoutingMatch | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const match = async () => {
    setBusy(true);
    setError('');
    setResult(null);
    try {
      setResult(
        await api.matchRoute({
          inbound,
          port: Number(port),
          network,
          ...(domain ? { domain } : {}),
          ...(ip ? { ip } : {}),
        }),
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Section title={label('match')} description={label('matchHint')} contentInset>
      <div className="grid gap-4">
        <SelectField
          label={t('catalogue.inbound')}
          options={inboundOptions(config)}
          value={inbound}
          onValueChange={setInbound}
        />
        <TextField
          label={label('domain')}
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
        />
        <TextField label="IP" value={ip} onChange={(e) => setIp(e.target.value)} />
        <TextField
          label={t('catalogue.port')}
          value={port}
          onChange={(e) => setPort(e.target.value)}
        />
        <SelectField
          label={label('network')}
          options={[
            { value: 'tcp', label: 'TCP' },
            { value: 'udp', label: 'UDP' },
          ]}
          value={network}
          onValueChange={(value) => setNetwork(value === 'udp' ? 'udp' : 'tcp')}
        />
        <div>
          <Action disabled={busy} onPress={() => void match()}>
            {label('match')}
          </Action>
        </div>
        {error && (
          <AlertBanner icon="!" tone="danger" title={t('common.failed')} description={error} />
        )}
        {result && (
          <Details
            label={label('match')}
            items={[
              [
                t('nav.rules'),
                result.rule
                  ? (config.management?.rules?.[result.rule]?.name ?? result.rule)
                  : label('noMatch'),
              ],
              [
                t('nav.upstreams'),
                result.outbound.startsWith('upstream-')
                  ? (Object.entries(config.management?.upstreams ?? {}).find(
                      ([id]) => 'upstream-' + id.replaceAll('-', '') === result.outbound,
                    )?.[1].name ?? result.outbound)
                  : label(result.outbound),
              ],
              [label('cn-warp'), label(result.cn_precedence ? 'cnFirst' : 'cnOff')],
            ]}
          />
        )}
      </div>
    </Section>
  );
}
