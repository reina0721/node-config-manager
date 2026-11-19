import type {
  InboundCombination,
  ManagedInbound,
  NodeConfiguration,
} from '../../../src/node-management';

type InboundStack = Pick<InboundCombination, 'transport' | 'security' | 'listener'>;

export const protocols = {
  xhttp: 'VLESS XHTTP',
  ws: 'VLESS WebSocket',
  reality: 'VLESS REALITY',
} as const;

export const managedProtocolNames: Record<InboundCombination['protocol'], string> = {
  vless: 'VLESS',
  vmess: 'VMess',
  trojan: 'Trojan',
  shadowsocks: 'Shadowsocks',
  'shadowsocks-2022': 'Shadowsocks-2022',
  http: 'HTTP CONNECT',
  mixed: 'Mixed (HTTP / SOCKS5)',
  hysteria2: 'Hysteria2',
};
export const transportNames: Record<InboundStack['transport'], string> = {
  raw: 'Raw TCP',
  xhttp: 'XHTTP',
  ws: 'WebSocket',
  hysteria: 'QUIC (Hysteria2)',
  grpc: 'gRPC',
  httpupgrade: 'HTTPUpgrade',
  mkcp: 'mKCP',
};

export function hasHttpPath(transport: InboundStack['transport']) {
  return transport === 'xhttp' || transport === 'ws' || transport === 'httpupgrade';
}

export function managedProtocol(
  protocol: ManagedInbound['protocol'],
): InboundCombination['protocol'] {
  return protocol === 'xhttp' || protocol === 'ws' || protocol === 'reality' ? 'vless' : protocol;
}

const legacyStacks = {
  xhttp: { transport: 'xhttp', security: 'tls', listener: 'shared-https' },
  ws: { transport: 'ws', security: 'tls', listener: 'shared-https' },
  reality: { transport: 'xhttp', security: 'reality', listener: 'dedicated' },
} as const satisfies Record<keyof typeof protocols, InboundStack>;

export function inboundStack(inbound: ManagedInbound | keyof typeof protocols): InboundStack {
  if (typeof inbound === 'string') return legacyStacks[inbound];
  if (inbound.protocol === 'xhttp' || inbound.protocol === 'ws' || inbound.protocol === 'reality') {
    return legacyStacks[inbound.protocol];
  }
  return {
    transport: inbound.transport ?? 'xhttp',
    security: inbound.security ?? 'tls',
    listener: inbound.listener ?? 'shared-https',
  };
}

export function inboundLabel(inbound: ManagedInbound) {
  const stack = inboundStack(inbound);
  const protocol = managedProtocolNames[managedProtocol(inbound.protocol)];
  return [
    protocol,
    transportNames[stack.transport],
    stack.security === 'none' ? '' : stack.security.toUpperCase(),
  ]
    .filter(Boolean)
    .join(' · ');
}

export function fallbackParents(config: NodeConfiguration, enabled: boolean) {
  return Object.entries(config.management?.inbounds ?? {}).filter(([, inbound]) => {
    const stack = inboundStack(inbound);
    return (
      inbound.protocol === 'vless' &&
      stack.transport === 'raw' &&
      stack.security === 'tls' &&
      stack.listener === 'dedicated' &&
      !(inbound.vless_encryption ?? config.vless?.encryption) &&
      (!enabled || inbound.enabled)
    );
  });
}

export function inboundErrors(
  inbound: ManagedInbound,
  config: NodeConfiguration,
  id: string | null,
) {
  const stack = inboundStack(inbound);
  const errors: Partial<Record<'remark' | 'path' | 'port' | 'fallback_parent', string>> = {};
  if (
    !inbound.remark.trim() ||
    new TextEncoder().encode(inbound.remark).length > 120 ||
    /\p{Cc}/u.test(inbound.remark)
  )
    errors.remark = 'catalogue.remarkError';
  const others = Object.entries(config.management?.inbounds ?? {}).filter(
    ([other]) => other !== id,
  );
  if (
    stack.listener === 'fallback' &&
    (!fallbackParents(config, inbound.enabled).some(([key]) => key === inbound.fallback_parent) ||
      others.some(([, entry]) => entry.fallback_parent === inbound.fallback_parent))
  )
    errors.fallback_parent = 'catalogue.fallbackParentError';
  if (stack.listener === 'dedicated') {
    const reserved = [
      config.ports.http,
      config.ports.https,
      config.ports.reality,
      22,
      9080,
      9443,
      19081,
      19443,
      config.web_services?.librespeed_port,
      config.web_services?.openlist_port,
      ...others
        .filter(([, entry]) => inboundStack(entry).listener === 'dedicated')
        .map(([, entry]) => entry.port),
    ];
    if (!Number.isInteger(inbound.port) || inbound.port < 1024 || inbound.port > 65535) {
      errors.port = 'catalogue.independentPortError';
    } else if (reserved.includes(inbound.port)) {
      errors.port = 'catalogue.portConflict';
    }
  }
  if (stack.transport === 'grpc') {
    if (!/^[a-zA-Z0-9_.-]{1,128}$/.test(inbound.path)) errors.path = 'catalogue.grpcServiceError';
    return errors;
  }
  if (
    !hasHttpPath(stack.transport) ||
    (stack.listener === 'dedicated' && inbound.protocol === 'vless' && inbound.path === '/')
  )
    return errors;
  const location = inbound.path;
  if (
    !location.startsWith('/') ||
    location.length > 256 ||
    !/^[a-z0-9/_.-]+$/i.test(location) ||
    location.includes('//') ||
    location.split('/').filter(Boolean).length < 2 ||
    location.split('/').some((part) => part === '.' || part === '..') ||
    /vless|xhttp|splithttp|websocket|reality/i.test(location) ||
    (stack.transport === 'xhttp' && !location.endsWith('/'))
  ) {
    errors.path = 'catalogue.managedPathError';
  } else if (stack.listener === 'shared-https' || inbound.protocol !== 'vless') {
    const actual = location.replace(/\/+$/, '');
    const reserved = [
      config.transport.xhttp.path,
      config.transport.ws.path,
      config.transport.reality.path,
      ...config.website.reserved_paths,
      '/nodes/',
      '/librespeed/',
      '/downloads/',
      '/admin/',
      '/.well-known/',
      ...others
        .filter(
          ([, entry]) =>
            inboundStack(entry).listener === 'shared-https' || entry.protocol !== 'vless',
        )
        .map(([, entry]) => entry.path),
    ];
    if (
      reserved
        .map((path) => path.replace(/\/+$/, ''))
        .some(
          (path) =>
            path === actual || path.startsWith(actual + '/') || actual.startsWith(path + '/'),
        )
    ) {
      errors.path = 'catalogue.pathConflict';
    }
  }
  return errors;
}

export function split(value: string) {
  return value
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
}

export function toggle(values: string[], value: string, selected: boolean) {
  return selected ? [...new Set([...values, value])] : values.filter((item) => item !== value);
}
