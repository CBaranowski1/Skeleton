import type {
  EvidenceHealthSignal,
  EvidenceSignalName,
  KernelStatusLoadResult,
  ServerReadiness,
  StatusLoadFailureCode,
} from "./status-client.js";

export type OwnerHealthState = "ready" | "degraded" | "failed" | "unknown";

export interface OwnerHealth {
  readonly state: OwnerHealthState;
  readonly label: string;
}

export interface OwnerContractRow {
  readonly name: "Python" | "Rust" | "TypeScript";
  readonly disposition: "Unknown";
  readonly detail: "Not exposed by status schema";
}

export interface OwnerEvidenceSignal {
  readonly name: EvidenceSignalName;
  readonly label: string;
  readonly unit: "seconds" | "parts per million" | "count";
  readonly health: OwnerHealth;
  readonly value: string;
  readonly reasonCode: string;
}

export interface OwnerStatusView {
  readonly overall: OwnerHealthState;
  readonly overallLabel: string;
  readonly explanation: string;
  readonly productLabel: "Skeleton — Universal Personal Cognition Kernel";
  readonly lobeLabel: string;
  readonly authority: OwnerHealth;
  readonly cognition: OwnerHealth;
  readonly evidenceReadiness: OwnerHealth;
  readonly evidenceHealth: OwnerHealth;
  readonly evidenceSnapshotSha256: string;
  readonly evidenceSourceStateSha256: string;
  readonly evidenceObservedAt: string | null;
  readonly evidenceSignals: readonly OwnerEvidenceSignal[];
  readonly bundleSha256: string;
  readonly semanticStateHash: string;
  readonly journalStateHash: string;
  readonly authoritySnapshotHash: string;
  readonly journalDisposition: string;
  readonly schemaVersion: string;
  readonly observedAt: string | null;
  readonly contractRows: readonly OwnerContractRow[];
}

const PRODUCT_LABEL = "Skeleton — Universal Personal Cognition Kernel" as const;
const UNKNOWN_ROWS: readonly OwnerContractRow[] = [
  {
    name: "Python",
    disposition: "Unknown",
    detail: "Not exposed by status schema",
  },
  {
    name: "Rust",
    disposition: "Unknown",
    detail: "Not exposed by status schema",
  },
  {
    name: "TypeScript",
    disposition: "Unknown",
    detail: "Not exposed by status schema",
  },
];

const OWNER_EVIDENCE_SIGNAL_NAMES = [
  "ingest_lag",
  "correction_rate",
  "sequence_gaps",
  "unresolved_identities",
  "exclusions",
  "rights_expiry",
  "deletion_backlog",
  "reproducibility_failures",
  "storage_pressure",
] as const satisfies readonly EvidenceSignalName[];

const SIGNAL_PRESENTATION: Readonly<Record<
  EvidenceSignalName,
  { readonly label: string; readonly unit: OwnerEvidenceSignal["unit"] }
>> = {
  ingest_lag: { label: "Ingest lag", unit: "seconds" },
  correction_rate: { label: "Correction rate", unit: "parts per million" },
  sequence_gaps: { label: "Sequence gaps", unit: "count" },
  unresolved_identities: { label: "Unresolved identities", unit: "count" },
  exclusions: { label: "Exclusions", unit: "count" },
  rights_expiry: { label: "Rights expiry", unit: "seconds" },
  deletion_backlog: { label: "Deletion backlog", unit: "count" },
  reproducibility_failures: { label: "Reproducibility failures", unit: "count" },
  storage_pressure: { label: "Storage pressure", unit: "parts per million" },
};

function processHealth(value: "available" | "degraded" | "unavailable"): OwnerHealth {
  if (value === "available") return { state: "ready", label: "Available" };
  if (value === "degraded") return { state: "degraded", label: "Degraded" };
  return { state: "failed", label: "Unavailable" };
}

function readinessHealth(value: ServerReadiness): OwnerHealth {
  if (value === "ready") return { state: "ready", label: "Ready" };
  if (value === "degraded") return { state: "degraded", label: "Degraded" };
  if (value === "unavailable") return { state: "failed", label: "Unavailable" };
  return { state: "unknown", label: "Unknown" };
}

function signalHealth(value: EvidenceHealthSignal["state"]): OwnerHealth {
  if (value === "ready") return { state: "ready", label: "Ready" };
  if (value === "degraded") return { state: "degraded", label: "Degraded" };
  if (value === "stale") return { state: "degraded", label: "Stale" };
  if (value === "unavailable") return { state: "failed", label: "Unavailable" };
  return { state: "unknown", label: "Unknown" };
}

function unavailableSignals(reason: string): readonly OwnerEvidenceSignal[] {
  return OWNER_EVIDENCE_SIGNAL_NAMES.map((name) => ({
    name,
    label: SIGNAL_PRESENTATION[name].label,
    unit: SIGNAL_PRESENTATION[name].unit,
    health: { state: "unknown", label: "Unknown" },
    value: "Unavailable",
    reasonCode: reason,
  }));
}

function evidenceSignals(
  signals: Readonly<Record<EvidenceSignalName, EvidenceHealthSignal>>,
): readonly OwnerEvidenceSignal[] {
  return OWNER_EVIDENCE_SIGNAL_NAMES.map((name) => {
    const signal = signals[name];
    return {
      name,
      label: SIGNAL_PRESENTATION[name].label,
      unit: SIGNAL_PRESENTATION[name].unit,
      health: signalHealth(signal.state),
      value: signal.value === null ? "Unavailable" : String(signal.value),
      reasonCode: signal.reason_code ?? "None",
    };
  });
}

function failureCopy(code: StatusLoadFailureCode): {
  readonly overall: OwnerHealthState;
  readonly label: string;
  readonly explanation: string;
} {
  switch (code) {
    case "unknown_schema":
      return {
        overall: "unknown",
        label: "Status version unknown",
        explanation: "The response version is not supported; no health claim is shown.",
      };
    case "partial_status":
      return {
        overall: "failed",
        label: "Status response incomplete",
        explanation: "Required server-owned status fields are missing.",
      };
    case "invalid_status":
    case "invalid_json":
      return {
        overall: "failed",
        label: "Status response invalid",
        explanation: "The response failed the frozen kernel-status contract.",
      };
    case "http_failed":
      return {
        overall: "failed",
        label: "Status endpoint unavailable",
        explanation: "The loopback status endpoint returned an unsupported response.",
      };
    case "fetch_failed":
      return {
        overall: "failed",
        label: "Status unavailable",
        explanation: "The loopback status endpoint could not be read.",
      };
  }
}

function overallHealth(
  readiness: OwnerHealth,
  authority: OwnerHealth,
): OwnerHealth {
  if (readiness.state === "failed" || authority.state === "failed") {
    return { state: "failed", label: "Kernel status unavailable" };
  }
  if (readiness.state === "unknown") {
    return { state: "unknown", label: "Kernel status unknown" };
  }
  if (readiness.state === "degraded" || authority.state === "degraded") {
    return { state: "degraded", label: "Kernel status degraded" };
  }
  return { state: "ready", label: "Kernel status ready" };
}

export function deriveOwnerStatus(result: KernelStatusLoadResult): OwnerStatusView {
  if (result.kind === "failed") {
    const failure = failureCopy(result.code);
    return {
      overall: failure.overall,
      overallLabel: failure.label,
      explanation: failure.explanation,
      productLabel: PRODUCT_LABEL,
      lobeLabel: "Lobe status unavailable",
      authority: { state: "unknown", label: "Unknown" },
      cognition: { state: "unknown", label: "Unknown" },
      evidenceReadiness: { state: "unknown", label: "Unknown" },
      evidenceHealth: { state: "unknown", label: "Unknown" },
      evidenceSnapshotSha256: "Unavailable",
      evidenceSourceStateSha256: "Unavailable",
      evidenceObservedAt: null,
      evidenceSignals: unavailableSignals("Status response unavailable"),
      bundleSha256: "Unavailable",
      semanticStateHash: "Unavailable",
      journalStateHash: "Unavailable",
      authoritySnapshotHash: "Unavailable",
      journalDisposition: "Unavailable",
      schemaVersion: "Unavailable",
      observedAt: null,
      contractRows: UNKNOWN_ROWS,
    };
  }

  if (result.status.schema_version === "skeleton.kernel-status.v2") {
    const evidenceHealth = readinessHealth(result.status.evidence_health.readiness);
    const serverReadiness = readinessHealth(result.readiness);
    const overall = overallHealth(serverReadiness, evidenceHealth);
    return {
      overall: overall.state,
      overallLabel: overall.label,
      explanation: "Rendered from one validated additive read-only status-v2 response.",
      productLabel: PRODUCT_LABEL,
      lobeLabel: "Lobe status unavailable in status v2",
      authority: { state: "unknown", label: "Bound to status v1 identity" },
      cognition: { state: "unknown", label: "Unavailable in status v2" },
      evidenceReadiness: serverReadiness,
      evidenceHealth,
      evidenceSnapshotSha256: result.status.evidence_health.snapshot_sha256,
      evidenceSourceStateSha256: result.status.evidence_health.source_state_sha256,
      evidenceObservedAt: result.status.evidence_health.observed_at,
      evidenceSignals: evidenceSignals(result.status.evidence_health.signals),
      bundleSha256: "Unavailable in status v2",
      semanticStateHash: "Unavailable in status v2",
      journalStateHash: "Unavailable in status v2",
      authoritySnapshotHash: "Unavailable in status v2",
      journalDisposition: "Unavailable in status v2",
      schemaVersion: result.status.schema_version,
      observedAt: result.status.observed_at,
      contractRows: UNKNOWN_ROWS,
    };
  }

  const authority = processHealth(result.status.authority_process_health);
  const cognition = processHealth(result.status.cognition_process_health);
  const evidenceReadiness = readinessHealth(result.readiness);
  const overall = overallHealth(evidenceReadiness, authority);
  const cognitionNote = cognition.state === "failed"
    ? " Optional cognition is off; authority status remains readable."
    : "";
  return {
    overall: overall.state,
    overallLabel: overall.label,
    explanation:
      `Rendered from one validated read-only status response.${cognitionNote}`,
    productLabel: PRODUCT_LABEL,
    lobeLabel: result.status.lobe_count === 0
      ? "Zero lobes installed"
      : `${result.status.lobe_count} lobes installed`,
    authority,
    cognition,
    evidenceReadiness,
    evidenceHealth: { state: "unknown", label: "Unavailable in status v1" },
    evidenceSnapshotSha256: "Unavailable in status v1",
    evidenceSourceStateSha256: "Unavailable in status v1",
    evidenceObservedAt: null,
    evidenceSignals: unavailableSignals("Unavailable in status v1"),
    bundleSha256: result.status.bundle_sha256 as string,
    semanticStateHash: result.status.semantic_state_hash as string,
    journalStateHash: result.status.journal_state_hash as string,
    authoritySnapshotHash: result.status.authority_snapshot_hash as string,
    journalDisposition: result.status.incomplete_journal_disposition,
    schemaVersion: result.status.schema_version,
    observedAt: result.status.observed_at,
    contractRows: UNKNOWN_ROWS,
  };
}
