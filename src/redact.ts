import type { Finding } from "./scan";

export const REDACT_PLACEHOLDER = "[REDACTED]";

export function redactText(text: string, findings: Finding[]): string {
  const ordered = [...findings].sort((a, b) => b.start - a.start);
  let out = text;
  for (const finding of ordered) {
    out = out.slice(0, finding.start) + REDACT_PLACEHOLDER + out.slice(finding.end);
  }
  return out;
}
