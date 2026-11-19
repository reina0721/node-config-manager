'use client';
import { lazy, Suspense, useMemo, useState, type ReactNode } from 'react';
import Link, { useLinkStatus } from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { resolveRouteTarget } from '@community-go/plugin-framework';
import {
  PluginNavigationProvider,
  type PluginNavigationPort,
} from '@community-go/plugin-framework/plugin';
import { useFrontendTranslation } from '@community-go/i18n';
import { generatedSurfaceRegistry } from '@community-go/surface/generated/composition';
import { useNodeManagement } from '@community-go/surface/node-management';
import {
  convertRegistryToShellNavigation,
  navigationIconVocabulary,
} from '@community-go/surface/shell';
import { NavigationIcon } from '@community-go/surface/icon-presentation';
import { DrawerSurface } from '@community-go/ui-adapter/overlays';
import { ShellNavigation, ShellRoot } from '@community-go/surface-foundation/shell-navigation';
import { Action } from '@community-go/ui-adapter/action';
import { SkipLink } from '@community-go/ui-adapter/accessibility';
import { Badge } from '@community-go/ui-adapter/feedback';
import { RouteTransition } from '../host/route-transition';
import { useConsoleSession } from '../host/console-runtime';
function normalized(path: string) {
  const clean = path.replace(/^\/admin(?=\/|$)/, '').replace(/\/+$/, '');
  return clean || '/dmit';
}

function LinkPending() {
  const { pending } = useLinkStatus();
  const { t } = useFrontendTranslation();
  return pending ? (
    <span role="status" className="text-xs text-ink-muted">
      {t('nodeShell.switching')}
    </span>
  ) : null;
}

const ConsoleSearch = lazy(() => import('./console-search'));
export function ConsoleShell({ children }: Readonly<{ children: ReactNode }>) {
  const { t } = useFrontendTranslation();
  const pathname = usePathname();
  const router = useRouter();
  const session = useConsoleSession();
  const { selectedNode, job } = useNodeManagement();
  const jobStatus =
    job &&
    t(
      job.finished === null
        ? 'nodeShell.taskPending'
        : job.ok
          ? 'nodeShell.taskDone'
          : 'nodeShell.taskFailed',
    );
  const groups = useMemo(() => convertRegistryToShellNavigation(generatedSurfaceRegistry), []);
  const [forwardTarget, setForwardTarget] = useState<string | null>(null);
  const [mobile, setMobile] = useState(false);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const query = search.trim().toLowerCase();
  const filtered = query
    ? groups.flatMap((group) => {
        const items = group.items.filter(
          (item) =>
            t(item.labelKey).toLowerCase().includes(query) ||
            item.id.toLowerCase().includes(query) ||
            (item.id === 'dmit.nodes' &&
              t('nodeShell.legacySubscriptions').toLowerCase().includes(query)) ||
            (item.id === 'dmit.fleet' &&
              t('nodeShell.legacyFleet').toLowerCase().includes(query)) ||
            (item.kind === 'branch' &&
              item.children.some((child) => t(child.labelKey).toLowerCase().includes(query))),
        );
        const [first, ...rest] = items;
        return first ? [{ ...group, items: [first, ...rest] as typeof group.items }] : [];
      })
    : groups;
  const path = normalized(pathname);
  const [previousPath, setPreviousPath] = useState(path);
  const [direction, setDirection] = useState<string | null>(null);
  if (path !== previousPath) {
    setPreviousPath(path);
    setDirection(forwardTarget === path ? path : null);
    setForwardTarget(null);
  }
  const navigate = (href: string) => {
    const destination = normalized(href.split(/[?#]/, 1)[0] ?? href);
    if (destination !== path) setForwardTarget(destination);
  };
  const navigationPort: PluginNavigationPort = {
    resolveHref: (target) => {
      const result = resolveRouteTarget(generatedSurfaceRegistry, target);
      if (result.diagnostics.length > 0) throw new Error(result.diagnostics[0]?.message);
      return result.href;
    },
    navigate: (href) => {
      navigate(href);
      router.push(href);
    },
    replace: (href) => {
      navigate(href);
      router.replace(href);
    },
    renderLink: ({ href, children, className, ariaLabel, title, onNavigate }) => (
      <Link
        href={href}
        className={className}
        aria-label={ariaLabel}
        title={title}
        onNavigate={() => {
          navigate(href);
          onNavigate?.();
        }}
      >
        {children}
      </Link>
    ),
  };
  const navigation = (close?: () => void) => (
    <div className="grid gap-3">
      <Suspense fallback={<p role="status">{t('nodeShell.loadingSearch')}</p>}>
        <ConsoleSearch label={t('nodeShell.search')} value={search} onChange={setSearch} />
      </Suspense>
      {filtered.length > 0 ? (
        <ShellNavigation
          groups={filtered}
          onNavigate={close}
          router={{
            currentPath: path === '/' ? '/dmit' : path,
            renderLink: (p) => (
              <Link
                href={p.href}
                className={p.className}
                aria-current={p.current ? 'page' : undefined}
                onNavigate={() => {
                  navigate(p.href);
                  p.onNavigate?.();
                }}
                key={p.href}
              >
                {p.children}
                <LinkPending />
              </Link>
            ),
          }}
          presenter={{
            translate: (key) => t(key),
            icon: (iconId) => {
              const id = navigationIconVocabulary.find((id) => id === iconId);
              return id ? <NavigationIcon iconId={id} /> : null;
            },
          }}
        />
      ) : (
        <p role="status" className="text-sm text-ink-muted">
          {t('nodeShell.noSearchResults')}
        </p>
      )}
    </div>
  );
  return (
    <PluginNavigationProvider port={navigationPort}>
      <SkipLink href="#main-content" label={t('nodeShell.skip')} />
      <ShellRoot>
        <aside className="hidden border-r border-border bg-surface p-5 lg:sticky lg:top-0 lg:block lg:h-screen lg:overflow-y-auto">
          <Link
            href="/dmit"
            onNavigate={() => navigate('/dmit')}
            className="flex items-center gap-3 text-ink"
          >
            <span className="grid size-10 place-items-center rounded-control bg-brand text-lg font-bold text-on-brand">
              D
            </span>
            <span>
              <strong className="block text-base">DMIT Console</strong>
              <span className="text-xs text-ink-muted">{t('nodeShell.subtitle')}</span>
            </span>
          </Link>
          <div className="mt-6">{navigation()}</div>
          <div className="mt-6 border-t border-border pt-4">
            <Badge tone="success">{t('nodeShell.safe')}</Badge>
            <p className="mt-3 text-xs leading-6 text-ink-muted">{t('nodeShell.protection')}</p>
          </div>
        </aside>
        <div className="min-w-0">
          <header className="sticky top-0 z-20 flex flex-wrap items-center justify-between gap-3 border-b border-border bg-surface px-6 py-4">
            <div className="flex items-center gap-3">
              <div className="lg:hidden">
                <Action variant="quiet" onPress={() => setMobile(true)}>
                  {t('nodeShell.navigation')}
                </Action>
                <DrawerSurface
                  triggerLabel={t('nodeShell.navigation')}
                  title="DMIT Console"
                  description={t('nodeShell.navigationDescription')}
                  closeLabel={t('nodeShell.closeNavigation')}
                  isOpen={mobile}
                  onOpenChange={setMobile}
                  composition="navigation"
                  placement="left"
                >
                  {navigation(() => setMobile(false))}
                </DrawerSurface>
              </div>
              {selectedNode.id === 'local' ? (
                <span className="text-sm text-ink-muted">{t('nodeShell.context')}</span>
              ) : (
                <Link
                  href="/dmit/fleet"
                  onNavigate={() => navigate('/dmit/fleet')}
                  className="text-sm font-semibold text-brand"
                >
                  {t('nodeShell.remote')} {selectedNode.name}
                </Link>
              )}
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {job && jobStatus && (
                <Link
                  href="/dmit/operations"
                  onNavigate={() => navigate('/dmit/operations')}
                  aria-label={jobStatus}
                  className="rounded-control focus-visible:outline-brand"
                >
                  <span role="status">
                    <Badge tone={job.finished === null ? 'info' : job.ok ? 'success' : 'danger'}>
                      {jobStatus}
                      {job.finished === null && ' · ' + job.phase}
                    </Badge>
                  </span>
                </Link>
              )}
              <Action variant="quiet" onPress={session.toggleTheme}>
                {t(session.theme === 'light' ? 'nodeShell.dark' : 'nodeShell.light')}
              </Action>
              <Action
                variant="secondary"
                onPress={() => {
                  void session
                    .logout()
                    .catch((e) => setError(e instanceof Error ? e.message : String(e)));
                }}
              >
                {t('nodeShell.logout')}
              </Action>
            </div>
          </header>
          {error ? (
            <p role="alert" className="p-4 text-danger">
              {error}
            </p>
          ) : null}
          <main id="main-content" className="mx-auto max-w-7xl p-5 sm:p-8" tabIndex={-1}>
            <RouteTransition pathname={path} forwardTarget={direction} node={selectedNode.id}>
              {children}
            </RouteTransition>
          </main>
        </div>
      </ShellRoot>
    </PluginNavigationProvider>
  );
}
