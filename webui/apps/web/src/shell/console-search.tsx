'use client';
import { TextField } from '@community-go/ui-adapter/form-field';
export default function ConsoleSearch({
  label,
  value,
  onChange,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
}) {
  return <TextField label={label} value={value} onChange={(e) => onChange(e.target.value)} />;
}
