'use client';
/* eslint-disable react-refresh/only-export-components */
import { useState, type ReactNode } from 'react';
import { FilterBar } from '@community-go/surface-foundation/layout';
import { Badge } from '@community-go/ui-adapter/feedback';
import { SelectField, TextField } from '@community-go/ui-adapter/form-field';
import { ConfirmDialog, DrawerSurface } from '@community-go/ui-adapter/overlays';
import { useNodeText } from './common';

export function useListFilters() {
  const [query, setQuery] = useState('');
  const [status, setStatus] = useState('all');
  const search = query.trim().toLocaleLowerCase();
  return {
    query,
    setQuery,
    status,
    setStatus,
    active: Boolean(search) || status !== 'all',
    matches: (enabled: boolean, ...fields: string[]) =>
      (status === 'all' || (status === 'enabled') === enabled) &&
      (!search || fields.some((field) => field.toLocaleLowerCase().includes(search))),
  };
}

export function ListFilters({ filters }: { filters: ReturnType<typeof useListFilters> }) {
  const t = useNodeText();
  return (
    <FilterBar>
      <TextField
        label={t('console.searchRows')}
        value={filters.query}
        onChange={(event) => filters.setQuery(event.target.value)}
      />
      <SelectField
        label={t('console.rowStatus')}
        value={filters.status}
        onValueChange={filters.setStatus}
        options={[
          { value: 'all', label: t('console.all') },
          { value: 'enabled', label: t('common.enabled') },
          { value: 'disabled', label: t('common.disabled') },
        ]}
      />
    </FilterBar>
  );
}

export function EnabledBadge({ enabled }: { enabled: boolean }) {
  const t = useNodeText();
  return (
    <Badge tone={enabled ? 'success' : 'neutral'}>
      {t(enabled ? 'common.enabled' : 'common.disabled')}
    </Badge>
  );
}

export function EditorDrawer({
  title,
  description,
  dirty,
  busy,
  onClose,
  children,
}: Readonly<{
  title: string;
  description: string;
  dirty: boolean;
  busy?: boolean;
  onClose: () => void;
  children: ReactNode;
}>) {
  const t = useNodeText();
  const [discard, setDiscard] = useState(false);
  return (
    <DrawerSurface
      triggerLabel={title}
      title={title}
      description={description}
      closeLabel={t('console.close')}
      isOpen
      onOpenChange={(open) => {
        if (open || busy || discard) return;
        if (dirty) setDiscard(true);
        else onClose();
      }}
    >
      <div className="grid min-w-0 gap-4">{children}</div>
      {discard && (
        <ConfirmDialog
          triggerLabel={t('console.discard')}
          title={t('console.discard')}
          description={t('console.discardDescription')}
          cancelLabel={t('console.keepEditing')}
          confirmLabel={t('console.discard')}
          failureMessage={t('common.failed')}
          impact={null}
          isOpen
          onOpenChange={setDiscard}
          onConfirm={() => {
            onClose();
            return Promise.resolve();
          }}
        />
      )}
    </DrawerSurface>
  );
}
