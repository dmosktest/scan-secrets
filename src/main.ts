import "./style.css";
import { detectLocale, t, type MessageKey } from "./i18n";
import { redactText } from "./redact";
import { registerServiceWorker } from "./register-sw";
import { scanText, type Finding, type FindingCategory } from "./scan";
import type { Locale } from "./site-config";

const MAX_FILE_BYTES = 5 * 1024 * 1024;
const MAX_FILE_LABEL = "5 MB";

const CATEGORY_KEY: Record<FindingCategory, MessageKey> = {
  pem: "catPem",
  token: "catToken",
  jwt: "catJwt",
  uri: "catUri",
  assignment: "catAssignment",
  entropy: "catEntropy",
};

type AppState = {
  locale: Locale;
  findings: Finding[];
  selected: Set<number>;
};

const state: AppState = {
  locale: "ru",
  findings: [],
  selected: new Set(),
};

function byId<T extends HTMLElement>(id: string): T {
  return document.getElementById(id) as T;
}

function format(template: string, vars: Record<string, string | number>): string {
  return template.replace(/\{(\w+)\}/g, (_, name: string) => String(vars[name] ?? ""));
}

function setStatus(message: string, isError = false): void {
  const el = byId<HTMLParagraphElement>("status");
  el.textContent = message;
  el.classList.toggle("is-error", isError);
}

function selectedFindings(): Finding[] {
  return state.findings.filter((finding) => state.selected.has(finding.id));
}

function updateSummary(): void {
  byId<HTMLParagraphElement>("summary").textContent = format(
    t(state.locale, "summary"),
    { total: state.findings.length, selected: state.selected.size },
  );
  byId<HTMLButtonElement>("redact").disabled = state.selected.size === 0;
}

function renderFinding(finding: Finding): HTMLLIElement {
  const li = document.createElement("li");
  li.className = "finding";

  const label = document.createElement("label");
  label.className = "finding-label";

  const check = document.createElement("input");
  check.type = "checkbox";
  check.className = "finding-check";
  check.checked = state.selected.has(finding.id);
  check.dataset.id = String(finding.id);
  check.addEventListener("change", () => {
    if (check.checked) state.selected.add(finding.id);
    else state.selected.delete(finding.id);
    updateSummary();
  });

  const head = document.createElement("span");
  head.className = "finding-head";

  const category = document.createElement("span");
  category.className = "finding-category";
  category.textContent = t(state.locale, CATEGORY_KEY[finding.category]);

  const rule = document.createElement("span");
  rule.className = "finding-rule";
  rule.textContent = finding.rule;

  const pos = document.createElement("span");
  pos.className = "finding-pos";
  pos.textContent = format(t(state.locale, "position"), {
    line: finding.line,
    column: finding.column,
  });

  head.append(category, rule, pos);

  const context = document.createElement("span");
  context.className = "finding-context";
  const match = document.createElement("mark");
  match.className = "finding-match";
  match.textContent = finding.snippet;
  context.append(finding.before, match, finding.after);

  label.append(check, head, context);
  li.append(label);
  return li;
}

function renderResults(): void {
  const results = byId<HTMLElement>("results");
  const list = byId<HTMLUListElement>("findings");
  list.replaceChildren(...state.findings.map(renderFinding));
  results.hidden = false;
  updateSummary();
}

function hideResults(): void {
  state.findings = [];
  state.selected = new Set();
  byId<HTMLElement>("results").hidden = true;
  byId<HTMLUListElement>("findings").replaceChildren();
  byId<HTMLButtonElement>("redact").disabled = true;
}

function runScan(): void {
  const text = byId<HTMLTextAreaElement>("text-input").value;
  if (!text.trim()) {
    hideResults();
    setStatus(t(state.locale, "emptyInput"), true);
    return;
  }
  state.findings = scanText(text);
  state.selected = new Set(state.findings.map((finding) => finding.id));
  if (state.findings.length === 0) {
    hideResults();
    setStatus(t(state.locale, "noFindings"));
    return;
  }
  setStatus("");
  renderResults();
}

function redactSelected(): void {
  const input = byId<HTMLTextAreaElement>("text-input");
  const chosen = selectedFindings();
  if (chosen.length === 0) {
    setStatus(t(state.locale, "nothingSelected"), true);
    return;
  }
  input.value = redactText(input.value, chosen);
  runScan();
  const done = format(t(state.locale, "redactedDone"), { count: chosen.length });
  if (byId<HTMLElement>("results").hidden) {
    setStatus(
      `${done} ${t(state.locale, "noFindings")}`,
    );
  } else {
    setStatus(done);
  }
}

async function copyText(): Promise<void> {
  const text = byId<HTMLTextAreaElement>("text-input").value;
  if (!text) {
    setStatus(t(state.locale, "emptyInput"), true);
    return;
  }
  try {
    await navigator.clipboard.writeText(text);
    setStatus(t(state.locale, "copied"));
  } catch {
    setStatus(t(state.locale, "copyError"), true);
  }
}

function clearAll(): void {
  byId<HTMLTextAreaElement>("text-input").value = "";
  byId<HTMLInputElement>("text-file").value = "";
  hideResults();
  setStatus("");
}

async function loadFile(file: File): Promise<void> {
  if (file.size > MAX_FILE_BYTES) {
    setStatus(
      format(t(state.locale, "fileTooLarge"), { limit: MAX_FILE_LABEL }),
      true,
    );
    return;
  }
  try {
    byId<HTMLTextAreaElement>("text-input").value = await file.text();
  } catch {
    setStatus(t(state.locale, "fileReadError"), true);
    return;
  }
  runScan();
}

function setAllSelected(selected: boolean): void {
  state.selected = selected
    ? new Set(state.findings.map((finding) => finding.id))
    : new Set();
  for (const check of document.querySelectorAll<HTMLInputElement>(
    ".finding-check",
  )) {
    check.checked = selected;
  }
  updateSummary();
}

function bindLangMenu(): void {
  const langRoot = document.querySelector<HTMLDetailsElement>(".lang");
  if (!langRoot) return;
  document.addEventListener("click", (event) => {
    if (!langRoot.open) return;
    const target = event.target;
    if (target instanceof Node && !langRoot.contains(target)) {
      langRoot.open = false;
    }
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && langRoot.open) langRoot.open = false;
  });
}

function init(): void {
  state.locale = detectLocale();
  bindLangMenu();

  byId<HTMLButtonElement>("scan").addEventListener("click", runScan);
  byId<HTMLButtonElement>("redact").addEventListener("click", redactSelected);
  byId<HTMLButtonElement>("copy").addEventListener("click", () => {
    void copyText();
  });
  byId<HTMLButtonElement>("clear").addEventListener("click", clearAll);
  byId<HTMLButtonElement>("select-all").addEventListener("click", () =>
    setAllSelected(true),
  );
  byId<HTMLButtonElement>("select-none").addEventListener("click", () =>
    setAllSelected(false),
  );

  byId<HTMLTextAreaElement>("text-input").addEventListener("input", () => {
    if (state.findings.length === 0) return;
    hideResults();
    setStatus(t(state.locale, "staleHint"));
  });

  byId<HTMLInputElement>("text-file").addEventListener("change", (event) => {
    const file = (event.target as HTMLInputElement).files?.[0];
    if (file) void loadFile(file);
  });

  registerServiceWorker();
}

init();
