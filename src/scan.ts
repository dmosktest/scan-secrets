export type FindingCategory =
  | "pem"
  | "token"
  | "jwt"
  | "uri"
  | "assignment"
  | "entropy";

export type Finding = {
  id: number;
  category: FindingCategory;
  rule: string;
  start: number;
  end: number;
  confidence: number;
  line: number;
  column: number;
  snippet: string;
  before: string;
  after: string;
};

type Candidate = {
  category: FindingCategory;
  rule: string;
  start: number;
  end: number;
  confidence: number;
};

const CONTEXT_CHARS = 36;
const SNIPPET_MAX = 64;

const PEM_FULL_RE =
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----/g;
const PEM_HEADER_RE = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----/g;

const TOKEN_RULES: { rule: string; re: RegExp }[] = [
  {
    rule: "GitHub token",
    re: /(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})(?![A-Za-z0-9_])/g,
  },
  {
    rule: "GitLab token",
    re: /(?<![A-Za-z0-9_-])glpat-[A-Za-z0-9_-]{20,}/g,
  },
  {
    rule: "Slack token",
    re: /(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{10,}/g,
  },
  {
    rule: "OpenAI key",
    re: /(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{20,}/g,
  },
  {
    rule: "AWS access key ID",
    re: /(?<![A-Za-z0-9])(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}(?![A-Za-z0-9])/g,
  },
];

const JWT_RE =
  /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}(?![A-Za-z0-9_-])/g;

const URI_CREDS_RE =
  /(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{1,24}:\/\/[^\s:\/?#@'"<>]+:([^\s\/?#@'"<>]+)@[^\s\/?#'"<>]+/gd;

const ASSIGNMENT_RE =
  /(["']?)([A-Za-z0-9_.-]*(?:password|passwd|secret|api[_-]?key|apikey|token|authorization)[A-Za-z0-9_.-]*)\1\s*[:=]\s*(?:(?:bearer|basic|token)\s+)?(?:"([^"\r\n]{3,})"|'([^'\r\n]{3,})'|([^\s,;"'`#<>(){}\[\]]{3,}))/gid;

const ASSIGNMENT_KEY_SKIP_RE =
  /(?:type|url|uri|path|file|name|length|count|ttl|expires?(?:_in|_at)?|field|header|label)$/i;

const ASSIGNMENT_VALUE_SKIP_RE =
  /^(?:true|false|null|none|nil|undefined|\d+|\[redacted\]|redacted)$/i;

const ENTROPY_RE =
  /(?<![A-Za-z0-9+\/=_-])[A-Za-z0-9+\/=_-]{32,}(?![A-Za-z0-9+\/=_-])/g;

const HEX_RE = /^[0-9a-f]+$/i;

function isPlaceholderValue(value: string): boolean {
  if (ASSIGNMENT_VALUE_SKIP_RE.test(value)) return true;
  if (/^[$%]/.test(value)) return true;
  if (/^\{\{.*\}\}$/.test(value)) return true;
  if (/^<[^<>]*>$/.test(value)) return true;
  if (/^\*+$/.test(value)) return true;
  if (/^x{3,}$/i.test(value)) return true;
  return false;
}

function shannonEntropy(value: string): number {
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function looksHighEntropy(value: string): boolean {
  if (HEX_RE.test(value)) return false;
  if (!/[a-z]/.test(value) || !/[A-Z]/.test(value) || !/[0-9]/.test(value)) {
    return false;
  }
  const digits = value.replace(/[^0-9]/g, "").length;
  if (digits / value.length < 0.1) return false;
  return shannonEntropy(value) >= 4.2;
}

function collectPem(text: string, out: Candidate[]): void {
  for (const re of [PEM_FULL_RE, PEM_HEADER_RE]) {
    for (const m of text.matchAll(re)) {
      out.push({
        category: "pem",
        rule: "Private key",
        start: m.index,
        end: m.index + m[0].length,
        confidence: 1,
      });
    }
  }
}

function collectTokens(text: string, out: Candidate[]): void {
  for (const { rule, re } of TOKEN_RULES) {
    for (const m of text.matchAll(re)) {
      out.push({
        category: "token",
        rule,
        start: m.index,
        end: m.index + m[0].length,
        confidence: 0.95,
      });
    }
  }
}

function collectJwt(text: string, out: Candidate[]): void {
  for (const m of text.matchAll(JWT_RE)) {
    out.push({
      category: "jwt",
      rule: "JWT",
      start: m.index,
      end: m.index + m[0].length,
      confidence: 0.9,
    });
  }
}

function collectUriCredentials(text: string, out: Candidate[]): void {
  for (const m of text.matchAll(URI_CREDS_RE)) {
    const range = m.indices?.[1];
    const password = m[1];
    if (!range || isPlaceholderValue(password)) continue;
    out.push({
      category: "uri",
      rule: "URI password",
      start: range[0],
      end: range[1],
      confidence: 0.85,
    });
  }
}

function collectAssignments(text: string, out: Candidate[]): void {
  for (const m of text.matchAll(ASSIGNMENT_RE)) {
    const key = m[2];
    if (ASSIGNMENT_KEY_SKIP_RE.test(key)) continue;
    const groupIndex = m[3] !== undefined ? 3 : m[4] !== undefined ? 4 : 5;
    const value = m[groupIndex];
    const range = m.indices?.[groupIndex];
    if (!range || value === undefined || isPlaceholderValue(value)) continue;
    out.push({
      category: "assignment",
      rule: key,
      start: range[0],
      end: range[1],
      confidence: 0.7,
    });
  }
}

function collectEntropy(text: string, out: Candidate[]): void {
  for (const m of text.matchAll(ENTROPY_RE)) {
    if (!looksHighEntropy(m[0])) continue;
    out.push({
      category: "entropy",
      rule: "High entropy",
      start: m.index,
      end: m.index + m[0].length,
      confidence: 0.5,
    });
  }
}

function dedupe(candidates: Candidate[]): Candidate[] {
  const ranked = [...candidates].sort(
    (a, b) =>
      b.end - b.start - (a.end - a.start) ||
      b.confidence - a.confidence ||
      a.start - b.start,
  );
  const accepted: Candidate[] = [];
  for (const candidate of ranked) {
    const overlaps = accepted.some(
      (other) => candidate.start < other.end && other.start < candidate.end,
    );
    if (!overlaps) accepted.push(candidate);
  }
  return accepted.sort((a, b) => a.start - b.start);
}

function lineStartOf(text: string, index: number): number {
  return text.lastIndexOf("\n", index - 1) + 1;
}

function lineEndOf(text: string, index: number): number {
  const end = text.indexOf("\n", index);
  return end === -1 ? text.length : end;
}

function buildSnippet(raw: string): string {
  const flat = raw.replace(/\s+/g, " ").trim();
  if (flat.length <= SNIPPET_MAX) return flat;
  const head = Math.ceil((SNIPPET_MAX - 1) * 0.7);
  const tail = SNIPPET_MAX - 1 - head;
  return `${flat.slice(0, head)}…${flat.slice(flat.length - tail)}`;
}

function buildContextSide(
  text: string,
  from: number,
  to: number,
  side: "before" | "after",
): string {
  const slice = text.slice(from, to).replace(/[\r\t]/g, " ");
  if (slice.length <= CONTEXT_CHARS) return slice;
  return side === "before"
    ? `…${slice.slice(slice.length - CONTEXT_CHARS)}`
    : `${slice.slice(0, CONTEXT_CHARS)}…`;
}

function toFinding(text: string, candidate: Candidate, id: number): Finding {
  const lineStart = lineStartOf(text, candidate.start);
  const line = text.slice(0, candidate.start).split("\n").length;
  return {
    id,
    category: candidate.category,
    rule: candidate.rule,
    start: candidate.start,
    end: candidate.end,
    confidence: candidate.confidence,
    line,
    column: candidate.start - lineStart + 1,
    snippet: buildSnippet(text.slice(candidate.start, candidate.end)),
    before: buildContextSide(text, lineStart, candidate.start, "before"),
    after: buildContextSide(
      text,
      candidate.end,
      lineEndOf(text, candidate.end),
      "after",
    ),
  };
}

export function scanText(text: string): Finding[] {
  const candidates: Candidate[] = [];
  collectPem(text, candidates);
  collectTokens(text, candidates);
  collectJwt(text, candidates);
  collectUriCredentials(text, candidates);
  collectAssignments(text, candidates);
  collectEntropy(text, candidates);
  return dedupe(candidates).map((candidate, index) =>
    toFinding(text, candidate, index),
  );
}
