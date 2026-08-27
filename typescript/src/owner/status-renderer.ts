import { fetchKernelStatus, type KernelStatusFetch } from "./status-client.js";
import {
  deriveOwnerStatus,
  type OwnerHealth,
  type OwnerStatusView,
} from "./status-state.js";

export interface RenderNode {
  readonly tag: string;
  readonly attributes?: Readonly<Record<string, string>>;
  readonly children: readonly (RenderNode | string)[];
}

const SHAPES: Readonly<Record<OwnerHealth["state"], string>> = {
  ready: "●",
  degraded: "▲",
  failed: "■",
  unknown: "◆",
};

function node(
  tag: string,
  attributes: Readonly<Record<string, string>> | undefined,
  ...children: readonly (RenderNode | string)[]
): RenderNode {
  return attributes === undefined
    ? { tag, children }
    : { tag, attributes, children };
}

function healthText(health: OwnerHealth): RenderNode {
  return node(
    "span",
    { class: `health health--${health.state}` },
    node("span", { class: "health__shape", "aria-hidden": "true" }, SHAPES[health.state]),
    ` ${health.label}`,
  );
}

function definition(label: string, value: RenderNode | string): readonly RenderNode[] {
  return [
    node("dt", undefined, label),
    node("dd", undefined, value),
  ];
}

function hashValue(value: string): RenderNode {
  return node("code", { class: "hash" }, value);
}

export function createOwnerStatusTree(view: OwnerStatusView): RenderNode {
  const observed = view.observedAt === null
    ? "Unavailable"
    : node("time", { datetime: view.observedAt }, view.observedAt);
  const evidenceObserved = view.evidenceObservedAt === null
    ? "Unavailable"
    : node("time", { datetime: view.evidenceObservedAt }, view.evidenceObservedAt);
  return node(
    "section",
    {
      class: `owner-status owner-status--${view.overall}`,
      role: "status",
      "aria-live": "polite",
      "aria-atomic": "true",
    },
    node(
      "header",
      { class: "owner-status__header" },
      node("div", { class: "owner-status__identity" },
        node("span", { class: "identity-mark", "aria-hidden": "true" }, "S"),
        node("h2", undefined, view.productLabel),
      ),
      node("p", { class: "owner-status__lobes" }, view.lobeLabel),
      node(
        "p",
        { class: `overall overall--${view.overall}` },
        node("span", { class: "health__shape", "aria-hidden": "true" }, SHAPES[view.overall]),
        ` ${view.overallLabel}`,
      ),
      node("p", { class: "owner-status__explanation" }, view.explanation),
    ),
    node(
      "div",
      { class: "status-grid" },
      node(
        "section",
        { class: "status-card", "aria-labelledby": "authority-heading" },
        node("h2", { id: "authority-heading" }, "Authority"),
        node(
          "dl",
          { class: "fact-list" },
          ...definition("Writer identity", "Not exposed by status schema"),
          ...definition("Authority health", healthText(view.authority)),
          ...definition("Last command/result", "Not exposed by status schema"),
          ...definition("Journal disposition", view.journalDisposition),
          ...definition("Semantic state", hashValue(view.semanticStateHash)),
          ...definition("Journal state", hashValue(view.journalStateHash)),
          ...definition("Authority snapshot", hashValue(view.authoritySnapshotHash)),
        ),
      ),
      node(
        "section",
        { class: "status-card", "aria-labelledby": "process-heading" },
        node("h2", { id: "process-heading" }, "Processes"),
        node(
          "dl",
          { class: "fact-list" },
          ...definition("Reference authority", healthText(view.authority)),
          ...definition("Cognition", healthText(view.cognition)),
          ...definition("Status server", "Not exposed by status schema"),
          ...definition("Status evidence", healthText(view.evidenceReadiness)),
          ...definition("Evidence health", healthText(view.evidenceHealth)),
          ...definition("Evidence snapshot", hashValue(view.evidenceSnapshotSha256)),
          ...definition("Observed", observed),
        ),
      ),
      node(
        "section",
        { class: "status-card status-card--wide", "aria-labelledby": "evidence-heading" },
        node("h2", { id: "evidence-heading" }, "Evidence health"),
        node(
          "dl",
          { class: "fact-list" },
          ...definition("Readiness", healthText(view.evidenceHealth)),
          ...definition("Snapshot identity", hashValue(view.evidenceSnapshotSha256)),
          ...definition("Source state identity", hashValue(view.evidenceSourceStateSha256)),
          ...definition("Evidence observed", evidenceObserved),
        ),
        node(
          "table",
          { class: "evidence-table" },
          node("caption", undefined, "Nine bounded redacted evidence signals"),
          node(
            "thead",
            undefined,
            node(
              "tr",
              undefined,
              node("th", { scope: "col" }, "Signal"),
              node("th", { scope: "col" }, "State"),
              node("th", { scope: "col" }, "Value"),
              node("th", { scope: "col" }, "Unit"),
              node("th", { scope: "col" }, "Reason"),
            ),
          ),
          node(
            "tbody",
            undefined,
            ...view.evidenceSignals.map((signal) =>
              node(
                "tr",
                undefined,
                node("th", { scope: "row" }, signal.label),
                node("td", undefined, healthText(signal.health)),
                node("td", undefined, signal.value),
                node("td", undefined, signal.unit),
                node("td", undefined, signal.reasonCode),
              )
            ),
          ),
        ),
      ),
      node(
        "section",
        { class: "status-card status-card--wide", "aria-labelledby": "contract-heading" },
        node("h2", { id: "contract-heading" }, "Contract"),
        node(
          "dl",
          { class: "fact-list" },
          ...definition("Schema", view.schemaVersion),
          ...definition("Bundle identity", hashValue(view.bundleSha256)),
        ),
        node(
          "table",
          { class: "conformance-table" },
          node("caption", undefined, "Runtime conformance detail"),
          node(
            "tbody",
            undefined,
            ...view.contractRows.map((row) =>
              node(
                "tr",
                undefined,
                node("th", { scope: "row" }, row.name),
                node("td", undefined, row.disposition),
                node("td", undefined, row.detail),
              )
            ),
          ),
        ),
      ),
    ),
    node(
      "p",
      { class: "boundary-note" },
      "Private single-owner kernel. No customer funds, custody, advice, transmission, sportsbook execution, or trading capability.",
    ),
  );
}

function escapeText(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function serializeRenderTree(tree: RenderNode): string {
  if (!/^[a-z][a-z0-9-]*$/u.test(tree.tag)) {
    throw new Error("invalid_render_tag");
  }
  const attributes = Object.entries(tree.attributes ?? {})
    .map(([name, value]) => {
      if (!/^[a-z][a-z0-9-]*$/u.test(name)) {
        throw new Error("invalid_render_attribute");
      }
      return ` ${name}="${escapeText(value)}"`;
    })
    .join("");
  const children = tree.children
    .map((child) => typeof child === "string"
      ? escapeText(child)
      : serializeRenderTree(child))
    .join("");
  return `<${tree.tag}${attributes}>${children}</${tree.tag}>`;
}

export function renderOwnerStatus(view: OwnerStatusView): string {
  return serializeRenderTree(createOwnerStatusTree(view));
}

function materialize(documentValue: Document, tree: RenderNode): HTMLElement {
  const element = documentValue.createElement(tree.tag);
  for (const [name, value] of Object.entries(tree.attributes ?? {})) {
    element.setAttribute(name, value);
  }
  for (const child of tree.children) {
    element.append(
      typeof child === "string"
        ? documentValue.createTextNode(child)
        : materialize(documentValue, child),
    );
  }
  return element;
}

export function mountOwnerStatus(root: HTMLElement, view: OwnerStatusView): void {
  root.replaceChildren(materialize(root.ownerDocument, createOwnerStatusTree(view)));
}

export async function refreshOwnerStatus(
  root: HTMLElement,
  fetcher?: KernelStatusFetch,
): Promise<void> {
  root.setAttribute("aria-busy", "true");
  try {
    const result = fetcher === undefined
      ? await fetchKernelStatus()
      : await fetchKernelStatus(fetcher);
    mountOwnerStatus(root, deriveOwnerStatus(result));
  } finally {
    root.setAttribute("aria-busy", "false");
  }
}

export function startOwnerStatusPage(documentValue: Document = document): void {
  const root = documentValue.getElementById("status-output");
  const refresh = documentValue.getElementById("status-refresh");
  if (!(root instanceof HTMLElement) || !(refresh instanceof HTMLButtonElement)) return;
  refresh.addEventListener("click", () => {
    void refreshOwnerStatus(root);
  });
  void refreshOwnerStatus(root);
}

if (typeof document !== "undefined") {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => startOwnerStatusPage(), { once: true });
  } else {
    startOwnerStatusPage();
  }
}
