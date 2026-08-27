import assert from "node:assert/strict";
import { test } from "node:test";

import {
  fetchKernelStatus,
  validateKernelStatus,
  type KernelStatusFetch,
  type LoadedKernelStatus,
} from "../src/owner/status-client.js";
import {
  deriveOwnerStatus,
  type OwnerStatusView,
} from "../src/owner/status-state.js";
import {
  createOwnerStatusTree,
  renderOwnerStatus,
  serializeRenderTree,
} from "../src/owner/status-renderer.js";

const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);
const HASH_C = "c".repeat(64);
const HASH_D = "d".repeat(64);

function validStatus(overrides: Readonly<Record<string, unknown>> = {}): unknown {
  return {
    schema_version: "skeleton.kernel-status.v1",
    product_identity: "skeleton.private-single-owner",
    bundle_sha256: HASH_A,
    semantic_state_hash: HASH_B,
    journal_state_hash: HASH_C,
    authority_snapshot_hash: HASH_D,
    incomplete_journal_disposition: "idle",
    authority_process_health: "available",
    cognition_process_health: "unavailable",
    lobe_count: 0,
    capabilities: [],
    observed_at: "2026-07-30T17:45:18Z",
    ...overrides,
  };
}

function validStatusV2(overrides: Readonly<Record<string, unknown>> = {}): unknown {
  return {
    schema_version: "skeleton.kernel-status.v2",
    kernel_status_v1_sha256: HASH_A,
    evidence_health: {
      snapshot_sha256: HASH_B,
      source_state_sha256: HASH_C,
      readiness: "ready",
      observed_at: "2026-08-03T12:00:00Z",
      signals: {
        ingest_lag: { state: "ready", value: 1, reason_code: null },
        correction_rate: { state: "ready", value: 2, reason_code: null },
        sequence_gaps: { state: "ready", value: 3, reason_code: null },
        unresolved_identities: { state: "ready", value: 4, reason_code: null },
        exclusions: { state: "ready", value: 5, reason_code: null },
        rights_expiry: { state: "ready", value: 6, reason_code: null },
        deletion_backlog: { state: "ready", value: 7, reason_code: null },
        reproducibility_failures: { state: "ready", value: 8, reason_code: null },
        storage_pressure: { state: "ready", value: 9, reason_code: null },
      },
    },
    observed_at: "2026-08-03T12:00:00Z",
    ...overrides,
  };
}

function degradedStatusV2(): unknown {
  const status = structuredClone(validStatusV2()) as Record<string, unknown>;
  const health = status.evidence_health as Record<string, unknown>;
  const signals = health.signals as Record<string, unknown>;
  signals.ingest_lag = {
    state: "degraded",
    value: 31_536_000,
    reason_code: "threshold_exceeded",
  };
  signals.unresolved_identities = {
    state: "unknown",
    value: null,
    reason_code: "evidence_missing",
  };
  health.readiness = "degraded";
  return status;
}

function unknownStatusV2(): unknown {
  const status = structuredClone(validStatusV2()) as Record<string, unknown>;
  const health = status.evidence_health as Record<string, unknown>;
  const signals = health.signals as Record<string, unknown>;
  signals.unresolved_identities = {
    state: "unknown",
    value: null,
    reason_code: "evidence_missing",
  };
  health.readiness = "unknown";
  return status;
}

function loaded(
  overrides: Readonly<Record<string, unknown>> = {},
  readiness: LoadedKernelStatus["readiness"] = "ready",
): LoadedKernelStatus {
  const validation = validateKernelStatus(validStatus(overrides));
  assert.equal(validation.ok, true);
  if (!validation.ok) throw new Error("valid fixture rejected");
  return {
    kind: "loaded",
    status: validation.value,
    readiness,
    etag: `"${HASH_A}"`,
  };
}

test("valid zero-lobe response derives exact truthful owner labels", () => {
  const view = deriveOwnerStatus(loaded());

  assert.deepEqual(
    {
      overall: view.overall,
      overallLabel: view.overallLabel,
      lobeLabel: view.lobeLabel,
      authorityLabel: view.authority.label,
      cognitionLabel: view.cognition.label,
      readinessLabel: view.evidenceReadiness.label,
      bundle: view.bundleSha256,
    },
    {
      overall: "ready",
      overallLabel: "Kernel status ready",
      lobeLabel: "Zero lobes installed",
      authorityLabel: "Available",
      cognitionLabel: "Unavailable",
      readinessLabel: "Ready",
      bundle: HASH_A,
    },
  );

  const markup = renderOwnerStatus(view);
  for (const label of [
    "Skeleton — Universal Personal Cognition Kernel",
    "Zero lobes installed",
    "Authority health",
    "Available",
    "Writer identity",
    "Last command/result",
    "Cognition",
    "Unavailable",
    "Status server",
    "Not exposed by status schema",
    "Bundle identity",
    HASH_A,
    "No customer funds, custody, advice, transmission, sportsbook execution, or trading capability.",
  ]) {
    assert.match(markup, new RegExp(label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
});

test("unknown version, partial response, and fetch failure never derive ready", async () => {
  const unknown = validateKernelStatus(validStatus({
    schema_version: "skeleton.kernel-status.v3",
  }));
  assert.deepEqual(unknown, { ok: false, code: "unknown_schema" });

  const partial = validateKernelStatus({
    schema_version: "skeleton.kernel-status.v1",
    product_identity: "skeleton.private-single-owner",
  });
  assert.deepEqual(partial, { ok: false, code: "partial_status" });

  const fetchFailure = await fetchKernelStatus(async () => {
    throw new Error("host detail must not be echoed");
  });
  assert.deepEqual(fetchFailure, { kind: "failed", code: "fetch_failed" });

  for (const result of [
    { kind: "failed", code: "unknown_schema" },
    { kind: "failed", code: "partial_status" },
    fetchFailure,
  ] as const) {
    const view = deriveOwnerStatus(result);
    assert.notEqual(view.overall, "ready");
    assert.doesNotMatch(renderOwnerStatus(view), /host detail must not be echoed/);
  }
});

test("additive v2 validates exact health truth and v1 remains explicitly unavailable", () => {
  const v2 = validateKernelStatus(validStatusV2());
  assert.equal(v2.ok, true);
  if (!v2.ok) throw new Error("valid v2 rejected");
  const view = deriveOwnerStatus({
    kind: "loaded",
    status: v2.value,
    readiness: "ready",
    etag: `"${HASH_C}"`,
  });
  assert.equal(view.evidenceHealth.state, "ready");
  assert.equal(view.evidenceSnapshotSha256, HASH_B);
  assert.equal(view.evidenceSourceStateSha256, HASH_C);
  assert.equal(view.evidenceSignals.length, 9);
  const markup = renderOwnerStatus(view);
  for (const label of [
    "Ingest lag",
    "Correction rate",
    "Sequence gaps",
    "Unresolved identities",
    "Exclusions",
    "Rights expiry",
    "Deletion backlog",
    "Reproducibility failures",
    "Storage pressure",
    HASH_B,
    HASH_C,
  ]) {
    assert.match(markup, new RegExp(label));
  }

  const v1 = deriveOwnerStatus(loaded());
  assert.equal(v1.evidenceHealth.state, "unknown");
  assert.equal(v1.evidenceSnapshotSha256, "Unavailable in status v1");
  assert.equal(v1.evidenceSignals.length, 9);
  assert(v1.evidenceSignals.every((signal) => signal.value === "Unavailable"));

  const unknown = validateKernelStatus(unknownStatusV2());
  assert.equal(unknown.ok, true);
  if (!unknown.ok) throw new Error("valid unknown v2 rejected");
  const unknownView = deriveOwnerStatus({
    kind: "loaded",
    status: unknown.value,
    readiness: "unknown",
    etag: null,
  });
  assert.equal(unknownView.overall, "unknown");
  assert.equal(unknownView.evidenceSignals[3]?.reasonCode, "evidence_missing");
});

test("status v2 missing extra malformed unknown and protected values fail closed", async () => {
  const missingSignal = structuredClone(validStatusV2()) as Record<string, unknown>;
  const missingHealth = missingSignal.evidence_health as Record<string, unknown>;
  delete (missingHealth.signals as Record<string, unknown>).exclusions;

  const extraSignal = structuredClone(validStatusV2()) as Record<string, unknown>;
  const extraHealth = extraSignal.evidence_health as Record<string, unknown>;
  (extraHealth.signals as Record<string, unknown>).source_text = "secret fixture bytes";

  const malformedReason = structuredClone(validStatusV2()) as Record<string, unknown>;
  const malformedHealth = malformedReason.evidence_health as Record<string, unknown>;
  (malformedHealth.signals as Record<string, unknown>).ingest_lag = {
    state: "ready",
    value: 0,
    reason_code: "threshold_exceeded",
  };

  const unknownState = structuredClone(validStatusV2()) as Record<string, unknown>;
  const unknownHealth = unknownState.evidence_health as Record<string, unknown>;
  (unknownHealth.signals as Record<string, unknown>).storage_pressure = {
    state: "healthy<script>",
    value: 0,
    reason_code: null,
  };

  const inconsistentReadiness = structuredClone(validStatusV2()) as Record<string, unknown>;
  (inconsistentReadiness.evidence_health as Record<string, unknown>).readiness = "degraded";

  const outOfRange = structuredClone(validStatusV2()) as Record<string, unknown>;
  const rangeHealth = outOfRange.evidence_health as Record<string, unknown>;
  (rangeHealth.signals as Record<string, unknown>).correction_rate = {
    state: "ready",
    value: 1_000_001,
    reason_code: null,
  };

  for (const candidate of [
    validStatusV2({ evidence_health: { readiness: "ready" } }),
    missingSignal,
    validStatusV2({ extra: "forbidden" }),
    extraSignal,
    malformedReason,
    unknownState,
    inconsistentReadiness,
    outOfRange,
    validStatusV2({ observed_at: "2026-08-03T12:00:01Z" }),
    validStatusV2({ observed_at: "2026-02-31T12:00:00Z" }),
    validStatusV2({ source_text: "C:\\protected\\raw.txt" }),
  ]) {
    const result = validateKernelStatus(candidate);
    assert.equal(result.ok, false);
  }

  const duplicateState = JSON.stringify(validStatusV2()).replace(
    '"state":"ready"',
    '"state":"ready","state":"degraded"',
  );
  const duplicateResult = await fetchKernelStatus(async () => new Response(duplicateState, {
    status: 200,
    headers: { "X-Skeleton-Readiness": "ready" },
  }));
  assert.deepEqual(duplicateResult, { kind: "failed", code: "invalid_status" });
});

test("server readiness and process truth distinguish degraded, failed, and unknown", () => {
  const cases: ReadonlyArray<readonly [LoadedKernelStatus, OwnerStatusView["overall"], string]> = [
    [loaded({}, "degraded"), "degraded", "Kernel status degraded"],
    [loaded({}, "unknown"), "unknown", "Kernel status unknown"],
    [loaded({}, "unavailable"), "failed", "Kernel status unavailable"],
    [
      loaded({ authority_process_health: "unavailable" }, "ready"),
      "failed",
      "Kernel status unavailable",
    ],
  ];

  for (const [result, expectedState, expectedLabel] of cases) {
    const view = deriveOwnerStatus(result);
    assert.equal(view.overall, expectedState);
    assert.equal(view.overallLabel, expectedLabel);
  }
});

test("cognition-off remains explicit without overriding ready required roles", () => {
  const view = deriveOwnerStatus(loaded({
    cognition_process_health: "unavailable",
  }));
  assert.equal(view.overall, "ready");
  assert.equal(view.cognition.state, "failed");
  assert.equal(view.cognition.label, "Unavailable");
  assert.match(renderOwnerStatus(view), /Optional cognition is off; authority status remains readable\./);
});

test("client performs only one typed GET and accepts a truthful 503 snapshot", async () => {
  const calls: Array<readonly [RequestInfo | URL, RequestInit | undefined]> = [];
  const fakeFetch: KernelStatusFetch = async (input, init) => {
    calls.push([input, init]);
    return new Response(JSON.stringify(validStatus({
      authority_process_health: "unavailable",
    })), {
      status: 503,
      headers: {
        "Content-Type": "application/json",
        "ETag": `"${HASH_A}"`,
        "X-Skeleton-Readiness": "unavailable",
      },
    });
  };

  const result = await fetchKernelStatus(fakeFetch);
  assert.equal(result.kind, "loaded");
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0], [
    "/status",
    {
      method: "GET",
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
      referrerPolicy: "no-referrer",
      headers: { Accept: "application/json" },
    },
  ]);
  assert.equal(deriveOwnerStatus(result).overall, "failed");

  const readyV2 = await fetchKernelStatus(async () => new Response(
    JSON.stringify(validStatusV2()),
    { status: 200, headers: { "X-Skeleton-Readiness": "ready" } },
  ));
  assert.equal(readyV2.kind, "loaded");
  if (readyV2.kind === "loaded") assert.equal(deriveOwnerStatus(readyV2).overall, "ready");

  const degradedV2 = await fetchKernelStatus(async () => new Response(
    JSON.stringify(degradedStatusV2()),
    { status: 503, headers: { "X-Skeleton-Readiness": "degraded" } },
  ));
  assert.equal(degradedV2.kind, "loaded");
  if (degradedV2.kind === "loaded") {
    const degradedView = deriveOwnerStatus(degradedV2);
    assert.equal(degradedView.overall, "degraded");
    assert.equal(degradedView.evidenceSignals[0]?.health.label, "Degraded");
  }

  for (const mismatch of [
    new Response(JSON.stringify(validStatusV2()), {
      status: 503,
      headers: { "X-Skeleton-Readiness": "ready" },
    }),
    new Response(JSON.stringify(validStatusV2()), {
      status: 200,
      headers: { "X-Skeleton-Readiness": "degraded" },
    }),
    new Response(JSON.stringify(validStatusV2()), { status: 200 }),
  ]) {
    assert.deepEqual(
      await fetchKernelStatus(async () => mismatch),
      { kind: "failed", code: "invalid_status" },
    );
  }
});

test("renderer is deterministic, semantic, escaped, and mutation-control free", () => {
  const validation = validateKernelStatus(validStatusV2());
  assert.equal(validation.ok, true);
  if (!validation.ok) throw new Error("valid v2 rejected");
  const view = deriveOwnerStatus({
    kind: "loaded",
    status: validation.value,
    readiness: "ready",
    etag: null,
  });
  const first = renderOwnerStatus(view);
  const second = renderOwnerStatus(view);
  assert.equal(first, second);

  for (const semantic of [
    "<section",
    'role="status"',
    'aria-live="polite"',
    "<h2",
    "<table",
    "<caption",
    "<thead",
    '<th scope="row"',
    "<time",
  ]) {
    assert.match(first, new RegExp(semantic.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
  assert.doesNotMatch(
    first,
    /<(?:button|form|input|select|textarea|a)\b|on[a-z]+\s*=|data-action=/i,
  );

  const escaped = serializeRenderTree({
    tag: "p",
    children: ['<img src=x onerror="boom"> & "\''],
  });
  assert.equal(
    escaped,
    "<p>&lt;img src=x onerror=&quot;boom&quot;&gt; &amp; &quot;&#39;</p>",
  );
});

test("render tree uses only fixed element and attribute names", () => {
  const validation = validateKernelStatus(validStatusV2());
  assert.equal(validation.ok, true);
  if (!validation.ok) throw new Error("valid v2 rejected");
  const tree = createOwnerStatusTree(deriveOwnerStatus({
    kind: "loaded",
    status: validation.value,
    readiness: "ready",
    etag: null,
  }));
  const allowedTags = new Set([
    "section",
    "header",
    "div",
    "span",
    "h2",
    "p",
    "dl",
    "dt",
    "dd",
    "table",
    "caption",
    "thead",
    "tbody",
    "tr",
    "th",
    "td",
    "code",
    "time",
  ]);
  const walk = (node: typeof tree): void => {
    assert(allowedTags.has(node.tag));
    for (const name of Object.keys(node.attributes ?? {})) {
      assert.match(
        name,
        /^(?:id|class|role|aria-live|aria-atomic|aria-hidden|aria-labelledby|scope|datetime)$/,
      );
    }
    for (const child of node.children) {
      if (typeof child !== "string") walk(child);
    }
  };
  walk(tree);
});
