export function printTable(headers: string[], rows: (string | number)[][]): void {
  const cols = headers.length;
  const widths = new Array(cols).fill(0).map((_, i) => {
    const cellWidths = rows.map((r) => String(r[i] ?? "").length);
    return Math.max(headers[i]?.length ?? 0, ...cellWidths);
  });

  const formatRow = (cells: (string | number)[]) =>
    "| " + cells.map((c, i) => String(c).padEnd(widths[i] ?? 0)).join(" | ") + " |";

  const separator = "| " + widths.map((w) => "-".repeat(w)).join(" | ") + " |";

  console.log(formatRow(headers));
  console.log(separator);
  for (const row of rows) console.log(formatRow(row));
}

export function fmtPct(x: number): string {
  return `${(x * 100).toFixed(2)}%`;
}
