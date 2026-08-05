import { writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

export function writeJson(path: string, data: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(data, null, 2), "utf-8");
}

export function writeCsv(path: string, headers: string[], rows: (string | number)[][]): void {
  mkdirSync(dirname(path), { recursive: true });
  const lines = [headers.join(","), ...rows.map((r) => r.join(","))];
  writeFileSync(path, lines.join("\n") + "\n", "utf-8");
}
