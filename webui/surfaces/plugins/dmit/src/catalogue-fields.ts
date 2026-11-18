export const protocols = {
  xhttp: 'VLESS XHTTP',
  ws: 'VLESS WebSocket',
  reality: 'VLESS REALITY',
} as const;

export function split(value: string) {
  return value
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
}

export function toggle(values: string[], value: string, selected: boolean) {
  return selected ? [...new Set([...values, value])] : values.filter((item) => item !== value);
}
