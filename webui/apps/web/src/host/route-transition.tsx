'use client';

import { Fragment, useLayoutEffect, useRef, type ReactNode } from 'react';

export function RouteTransition({
  pathname,
  forwardTarget,
  node,
  children,
}: Readonly<{
  pathname: string;
  forwardTarget: string | null;
  node: string;
  children: ReactNode;
}>) {
  const previous = useRef({ pathname, node });
  const region = useRef<HTMLDivElement>(null);

  useLayoutEffect(() => {
    const element = region.current;
    if (!element) return;
    const last = previous.current;
    previous.current = { pathname, node };
    if (last.pathname === pathname) {
      if (last.node !== node) {
        delete element.dataset.routeEnter;
        delete element.dataset.routeKind;
      }
      return;
    }
    element.dataset.routeEnter = 'true';
    element.dataset.routeKind = forwardTarget === pathname ? 'forward' : 'back';
    if (forwardTarget === pathname) {
      element.closest('main')?.focus({ preventScroll: true });
    }
  }, [forwardTarget, pathname, node]);

  return (
    <div ref={region} className="surface-route-content" data-route-content="">
      <Fragment key={pathname + ':' + node}>{children}</Fragment>
    </div>
  );
}
