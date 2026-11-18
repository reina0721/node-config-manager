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
}: {
  data: ManagedUpstream;
  update: (value: ManagedUpstream) => void;
  writeCredential: (credential: UpstreamCredential | undefined, clear: boolean) => void;
}) {
  const t = useNodeText();
  const label = (key: string) => t('egress.' + key);
  const [username, setUsername] = useState('');
  const [secret, setSecret] = useState('');
  const [clear, setClear] = useState(false);
  const setPassword = (value: string, user: string) => {
    setSecret(value);
    writeCredential(
      value
        ? data.protocol === 'vless'
          ? { kind: 'vless', id: value }
          : { kind: 'password', username: user, password: value }
        : undefined,
      false,
    );
  };
  return (
    <div className="grid gap-4">
      <TextField
        label={label('name')}
        value={data.name}
        onChange={(e) => update({ ...data, name: e.target.value })}
      />
      <SelectField
        label={t('nodes.protocol')}
        value={data.protocol}
        options={[
          { value: 'socks5', label: 'SOCKS5' },
          { value: 'https-connect', label: 'HTTPS CONNECT' },
          { value: 'vless', label: 'VLESS TLS' },
        ]}
        onValueChange={(value) => {
          setSecret('');
          setUsername('');
          setClear(false);
          update({ ...data, protocol: value as ManagedUpstream['protocol'], server_name: '' });
        }}
      />
      <TextField
        label={label('address')}
        value={data.address}
        onChange={(e) => update({ ...data, address: e.target.value })}
      />
      <TextField
        label={t('catalogue.port')}
        value={String(data.port)}
        onChange={(e) => update({ ...data, port: Number(e.target.value) })}
      />
      {data.protocol !== 'socks5' && (
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
          {data.protocol !== 'vless' && (
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
            label={data.protocol === 'vless' ? label('uuid') : t('access.password')}
            hint={label('credentialHint')}
            value={secret}
            onChange={(e) => setPassword(e.target.value, username)}
          />
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
