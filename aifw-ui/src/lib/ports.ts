/** Parse a port field value that may be a single port or a range (e.g. "80", "80-443"). */
export function parsePortField(value: string): { start?: number; end?: number } {
  const trimmed = value.trim();
  if (!trimmed) return {};

  if (trimmed.includes("-")) {
    const [s, e] = trimmed.split("-").map((p) => parseInt(p.trim(), 10));
    if (!isNaN(s) && !isNaN(e)) return { start: s, end: e };
    if (!isNaN(s)) return { start: s };
    return {};
  }

  const n = parseInt(trimmed, 10);
  return isNaN(n) ? {} : { start: n };
}
