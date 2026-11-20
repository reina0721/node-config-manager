'use client';
/* eslint-disable react-refresh/only-export-components */
import { createContext, useContext, type ReactNode } from 'react';
import type {
  ConfigurationView,
  CatalogueEdit,
  ConfigPlan,
  CopySource,
  CopyRequest,
  CopyPreview,
  DnsView,
  JobResult,
  ManagedJob,
  ManagedService,
  NetworkView,
  NodeConfiguration,
  NodeOverview,
  NodesView,
  OperationInput,
  OperationsView,
  ProvisionOptions,
  ProxyAccess,
  ProxyAccessChange,
  RoutingQuery,
  RoutingMatch,
  Fleet,
  PeerRegistration,
  PeerGrant,
  PanelSettings,
  XrayView,
  VersionsView,
} from './node-model';
export * from './node-model';
export type ClientExportFormat = 'xray' | 'mihomo' | 'mihomo-weighted';
export type DeviceExportFormat = 'mihomo-weighted' | 'subscriptions' | 'xray-config';
export type ClientBootstrap = {
  nodectl: { version: 1; origin: string; client: string; enrollment: string; name: string };
};
export type NodeManagementPort = Readonly<{
  overview: () => Promise<NodeOverview>;
  configuration: () => Promise<ConfigurationView>;
  nodes: () => Promise<NodesView>;
  network: () => Promise<NetworkView>;
  dns: () => Promise<DnsView>;
  services: () => Promise<readonly ManagedService[]>;
  operations: () => Promise<OperationsView>;
  jobDetails: (id: string, node?: string) => Promise<ManagedJob>;
  versions: () => Promise<VersionsView>;
  proxyAccess: () => Promise<ProxyAccess>;
  clientDetails: (id: string) => Promise<{
    links: string[];
    claim_url: string | null;
    bootstrap: ClientBootstrap | null;
    bootstrap_unsupported: string[];
  }>;
  downloadClientBootstrap: (config: ClientBootstrap) => void;
  copyClientClaimLink: (url: string) => Promise<void>;
  newClaimRequest: () => string;
  claimClient: (id: string, request: string) => Promise<string>;
  changeProxyAccess: (input: ProxyAccessChange) => Promise<ProxyAccess>;
  downloadProxyUsers: () => Promise<void>;
  importProxyUsers: () => Promise<ProxyAccess | null>;
  downloadProxyProfile: (device: string, format: DeviceExportFormat) => Promise<void>;
  unlock: (token: string) => Promise<string>;
  preview: (config: NodeConfiguration, unlock?: string) => Promise<ConfigPlan>;
  previewCatalogue: (edit: CatalogueEdit, base: string) => Promise<ConfigPlan>;
  matchRoute: (input: RoutingQuery) => Promise<RoutingMatch>;
  testUpstream: (id: string) => Promise<JobResult>;
  fleet: () => Promise<Fleet>;
  copySource: (node: string) => Promise<CopySource>;
  previewCopy: (input: CopyRequest) => Promise<CopyPreview>;
  registerPeer: (registration: PeerRegistration) => Promise<void>;
  grantPeer: (grant: PeerGrant) => Promise<string>;
  removePeer: (id: string, grant: boolean) => Promise<void>;
  selectNode: (id: string, name: string) => void;
  selectedNode: { id: string; name: string };
  panel: () => Promise<PanelSettings>;
  xray: () => Promise<XrayView>;
  openApi: () => Promise<Record<string, unknown>>;
  restoreBackup: (backup: string, token: string) => Promise<ConfigPlan>;
  check: (plan: string, node?: string) => Promise<JobResult>;
  prepareDeployment: (plan: string, options: ProvisionOptions) => Promise<JobResult>;
  apply: (plan: string, confirm: string, node?: string) => Promise<JobResult>;
  operate: (input: OperationInput, onAccepted?: () => void) => Promise<JobResult>;
  credentials: (zone: string, token: string) => Promise<void>;
  exportClients: (format: ClientExportFormat) => Promise<string>;
  downloadClients: (format: ClientExportFormat, content: string) => void;
  job: ManagedJob | null;
}>;
const Context = createContext<NodeManagementPort | null>(null);
export function NodeManagementProvider({
  port,
  children,
}: Readonly<{ port: NodeManagementPort; children: ReactNode }>) {
  return <Context.Provider value={port}>{children}</Context.Provider>;
}
export function useNodeManagement() {
  const port = useContext(Context);
  if (!port) throw new Error('NodeManagementProvider is required');
  return port;
}
