import type { KernelStatus } from "../generated/contracts.js";

const EVIDENCE_SIGNAL_NAMES = [
  "ingest_lag",
  "correction_rate",
  "sequence_gaps",
  "unresolved_identities",
  "exclusions",
  "rights_expiry",
  "deletion_backlog",
  "reproducibility_failures",
  "storage_pressure",
] as const;

export type EvidenceSignalName = typeof EVIDENCE_SIGNAL_NAMES[number];
export type EvidenceSignalState =
  | "ready"
  | "degraded"
  | "unknown"
  | "stale"
  | "unavailable";
export type EvidenceSignalReason =
  | "threshold_exceeded"
  | "evidence_missing"
  | "evidence_stale"
  | "evidence_corrupt"
  | "evidence_partial";

export interface EvidenceHealthSignal {
  readonly state: EvidenceSignalState;
  readonly value: number | null;
  readonly reason_code: EvidenceSignalReason | null;
}

export interface EvidenceHealthSnapshot {
  readonly snapshot_sha256: string;
  readonly source_state_sha256: string;
  readonly readiness: ServerReadiness;
  readonly observed_at: string;
  readonly signals: Readonly<Record<EvidenceSignalName, EvidenceHealthSignal>>;
}

export interface KernelStatusV2 {
  readonly schema_version: "skeleton.kernel-status.v2";
  readonly kernel_status_v1_sha256: string;
  readonly evidence_health: EvidenceHealthSnapshot;
  readonly observed_at: string;
}

export type SupportedKernelStatus = KernelStatus | KernelStatusV2;

export type ServerReadiness = "ready" | "degraded" | "unavailable" | "unknown";

export type StatusValidationCode =
  | "unknown_schema"
  | "partial_status"
  | "invalid_status";

export type StatusValidationResult =
  | { readonly ok: true; readonly value: SupportedKernelStatus }
  | { readonly ok: false; readonly code: StatusValidationCode };

export interface LoadedKernelStatus {
  readonly kind: "loaded";
  readonly status: SupportedKernelStatus;
  readonly readiness: ServerReadiness;
  readonly etag: string | null;
}

export type StatusLoadFailureCode =
  | StatusValidationCode
  | "fetch_failed"
  | "http_failed"
  | "invalid_json";

export interface FailedKernelStatus {
  readonly kind: "failed";
  readonly code: StatusLoadFailureCode;
}

export type KernelStatusLoadResult = LoadedKernelStatus | FailedKernelStatus;

export type KernelStatusFetch = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

const STATUS_KEYS = [
  "schema_version",
  "product_identity",
  "bundle_sha256",
  "semantic_state_hash",
  "journal_state_hash",
  "authority_snapshot_hash",
  "incomplete_journal_disposition",
  "authority_process_health",
  "cognition_process_health",
  "lobe_count",
  "capabilities",
  "observed_at",
] as const;
const STATUS_V2_KEYS = [
  "schema_version",
  "kernel_status_v1_sha256",
  "evidence_health",
  "observed_at",
] as const;
const HEALTH_KEYS = [
  "snapshot_sha256",
  "source_state_sha256",
  "readiness",
  "observed_at",
  "signals",
] as const;
const SIGNAL_KEYS = ["state", "value", "reason_code"] as const;
const STATUS_KEY_SET = new Set<string>(STATUS_KEYS);
const STATUS_V2_KEY_SET = new Set<string>(STATUS_V2_KEYS);
const HEALTH_KEY_SET = new Set<string>(HEALTH_KEYS);
const SIGNAL_NAME_SET = new Set<string>(EVIDENCE_SIGNAL_NAMES);
const SIGNAL_KEY_SET = new Set<string>(SIGNAL_KEYS);
const SHA256 = /^[0-9a-f]{64}$/u;
const IDENTIFIER = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/u;
const TIMESTAMP =
  /^([0-9]{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])(?:\.[0-9]+)?Z$/u;
const JOURNAL_DISPOSITIONS = new Set([
  "idle",
  "RECEIVED",
  "EFFECT_COMMITTED",
  "RESULT_COMMITTED",
]);
const PROCESS_HEALTH = new Set(["available", "degraded", "unavailable"]);
const READINESS = new Set<ServerReadiness>([
  "ready",
  "degraded",
  "unavailable",
  "unknown",
]);
const SIGNAL_MAXIMUM: Readonly<Record<EvidenceSignalName, number>> = {
  ingest_lag: 31_536_000,
  correction_rate: 1_000_000,
  sequence_gaps: Number.MAX_SAFE_INTEGER,
  unresolved_identities: Number.MAX_SAFE_INTEGER,
  exclusions: Number.MAX_SAFE_INTEGER,
  rights_expiry: 31_536_000,
  deletion_backlog: Number.MAX_SAFE_INTEGER,
  reproducibility_failures: Number.MAX_SAFE_INTEGER,
  storage_pressure: 1_000_000,
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isSha256(value: unknown): value is string {
  return typeof value === "string" && SHA256.test(value);
}

function isIdentifier(value: unknown): value is string {
  return (
    typeof value === "string"
    && value.length >= 1
    && value.length <= 128
    && IDENTIFIER.test(value)
  );
}

function isTimestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const match = TIMESTAMP.exec(value);
  if (match === null) return false;
  const instant = new Date(value);
  return Number.isFinite(instant.getTime())
    && instant.getUTCFullYear() === Number(match[1])
    && instant.getUTCMonth() + 1 === Number(match[2])
    && instant.getUTCDate() === Number(match[3])
    && instant.getUTCHours() === Number(match[4])
    && instant.getUTCMinutes() === Number(match[5])
    && instant.getUTCSeconds() === Number(match[6]);
}

function hasExactKeys(
  value: Readonly<Record<string, unknown>>,
  keys: readonly string[],
  keySet: ReadonlySet<string>,
): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && actual.every((key) => keySet.has(key));
}

function validSignal(
  name: EvidenceSignalName,
  value: unknown,
): value is EvidenceHealthSignal {
  if (!isRecord(value) || !hasExactKeys(value, SIGNAL_KEYS, SIGNAL_KEY_SET)) {
    return false;
  }
  const signalValue = value.value;
  if (
    signalValue !== null
    && (
      typeof signalValue !== "number"
      || !Number.isSafeInteger(signalValue)
      || signalValue < 0
      || signalValue > SIGNAL_MAXIMUM[name]
    )
  ) {
    return false;
  }
  switch (value.state) {
    case "ready":
      return signalValue !== null && value.reason_code === null;
    case "degraded":
      return signalValue !== null && value.reason_code === "threshold_exceeded";
    case "unknown":
      return signalValue === null && value.reason_code === "evidence_missing";
    case "stale":
      return signalValue === null && value.reason_code === "evidence_stale";
    case "unavailable":
      return signalValue === null
        && (value.reason_code === "evidence_corrupt" || value.reason_code === "evidence_partial");
    default:
      return false;
  }
}

function readinessFromSignals(
  signals: Readonly<Record<EvidenceSignalName, EvidenceHealthSignal>>,
): ServerReadiness {
  const states = EVIDENCE_SIGNAL_NAMES.map((name) => signals[name].state);
  if (states.includes("unavailable")) return "unavailable";
  if (states.includes("degraded") || states.includes("stale")) return "degraded";
  if (states.includes("unknown")) return "unknown";
  return "ready";
}

function validateKernelStatusV2(value: Readonly<Record<string, unknown>>): StatusValidationResult {
  if (STATUS_V2_KEYS.some((key) => !(key in value))) {
    return { ok: false, code: "partial_status" };
  }
  if (!hasExactKeys(value, STATUS_V2_KEYS, STATUS_V2_KEY_SET)) {
    return { ok: false, code: "invalid_status" };
  }
  if (!isRecord(value.evidence_health)) {
    return { ok: false, code: "invalid_status" };
  }
  const health = value.evidence_health;
  if (HEALTH_KEYS.some((key) => !(key in health))) {
    return { ok: false, code: "partial_status" };
  }
  if (!hasExactKeys(health, HEALTH_KEYS, HEALTH_KEY_SET) || !isRecord(health.signals)) {
    return { ok: false, code: "invalid_status" };
  }
  const signals = health.signals;
  if (EVIDENCE_SIGNAL_NAMES.some((name) => !(name in signals))) {
    return { ok: false, code: "partial_status" };
  }
  if (!hasExactKeys(signals, EVIDENCE_SIGNAL_NAMES, SIGNAL_NAME_SET)) {
    return { ok: false, code: "invalid_status" };
  }
  for (const name of EVIDENCE_SIGNAL_NAMES) {
    if (!validSignal(name, signals[name])) {
      return { ok: false, code: "invalid_status" };
    }
  }
  if (
    !isSha256(value.kernel_status_v1_sha256)
    || !isSha256(health.snapshot_sha256)
    || !isSha256(health.source_state_sha256)
    || typeof health.readiness !== "string"
    || !READINESS.has(health.readiness as ServerReadiness)
    || !isTimestamp(health.observed_at)
    || !isTimestamp(value.observed_at)
    || value.observed_at !== health.observed_at
  ) {
    return { ok: false, code: "invalid_status" };
  }
  const typedSignals = signals as unknown as Readonly<Record<EvidenceSignalName, EvidenceHealthSignal>>;
  if (health.readiness !== readinessFromSignals(typedSignals)) {
    return { ok: false, code: "invalid_status" };
  }
  return { ok: true, value: value as unknown as KernelStatusV2 };
}

export function validateKernelStatus(value: unknown): StatusValidationResult {
  if (!isRecord(value)) return { ok: false, code: "invalid_status" };
  if (
    "schema_version" in value
    && value.schema_version !== "skeleton.kernel-status.v1"
    && value.schema_version !== "skeleton.kernel-status.v2"
  ) {
    return { ok: false, code: "unknown_schema" };
  }
  if (value.schema_version === "skeleton.kernel-status.v2") {
    return validateKernelStatusV2(value);
  }
  if (STATUS_KEYS.some((key) => !(key in value))) {
    return { ok: false, code: "partial_status" };
  }
  if (!hasExactKeys(value, STATUS_KEYS, STATUS_KEY_SET)) {
    return { ok: false, code: "invalid_status" };
  }
  if (
    value.schema_version !== "skeleton.kernel-status.v1"
    || value.product_identity !== "skeleton.private-single-owner"
    || !isSha256(value.bundle_sha256)
    || !isSha256(value.semantic_state_hash)
    || !isSha256(value.journal_state_hash)
    || !isSha256(value.authority_snapshot_hash)
    || typeof value.incomplete_journal_disposition !== "string"
    || !JOURNAL_DISPOSITIONS.has(value.incomplete_journal_disposition)
    || typeof value.authority_process_health !== "string"
    || !PROCESS_HEALTH.has(value.authority_process_health)
    || typeof value.cognition_process_health !== "string"
    || !PROCESS_HEALTH.has(value.cognition_process_health)
    || !Number.isInteger(value.lobe_count)
    || typeof value.lobe_count !== "number"
    || value.lobe_count < 0
    || value.lobe_count > 1024
    || !Array.isArray(value.capabilities)
    || value.capabilities.length > 1024
    || !value.capabilities.every(isIdentifier)
    || new Set(value.capabilities).size !== value.capabilities.length
    || !isTimestamp(value.observed_at)
  ) {
    return { ok: false, code: "invalid_status" };
  }
  return { ok: true, value: value as unknown as KernelStatus };
}

function parseJsonWithoutDuplicateKeys(raw: string): unknown {
  let offset = 0;
  const whitespace = (): void => {
    while (/[\t\n\r ]/u.test(raw[offset] ?? "")) offset += 1;
  };
  const stringToken = (): string => {
    const start = offset;
    if (raw[offset] !== '"') throw new Error("expected_string");
    offset += 1;
    while (offset < raw.length) {
      const character = raw[offset];
      if (character === '"') {
        offset += 1;
        return JSON.parse(raw.slice(start, offset)) as string;
      }
      if (character === "\\") {
        offset += 2;
      } else {
        if ((raw.charCodeAt(offset) || 0) <= 0x1f) throw new Error("invalid_string");
        offset += 1;
      }
    }
    throw new Error("unterminated_string");
  };
  const valueToken = (): void => {
    whitespace();
    if (raw[offset] === "{") {
      offset += 1;
      whitespace();
      const keys = new Set<string>();
      if (raw[offset] === "}") {
        offset += 1;
        return;
      }
      while (true) {
        const key = stringToken();
        if (keys.has(key)) throw new Error("duplicate_key");
        keys.add(key);
        whitespace();
        if (raw[offset] !== ":") throw new Error("expected_colon");
        offset += 1;
        valueToken();
        whitespace();
        if (raw[offset] === "}") {
          offset += 1;
          return;
        }
        if (raw[offset] !== ",") throw new Error("expected_comma");
        offset += 1;
        whitespace();
      }
    }
    if (raw[offset] === "[") {
      offset += 1;
      whitespace();
      if (raw[offset] === "]") {
        offset += 1;
        return;
      }
      while (true) {
        valueToken();
        whitespace();
        if (raw[offset] === "]") {
          offset += 1;
          return;
        }
        if (raw[offset] !== ",") throw new Error("expected_comma");
        offset += 1;
      }
    }
    if (raw[offset] === '"') {
      stringToken();
      return;
    }
    const start = offset;
    while (offset < raw.length && !/[\t\n\r ,\]}]/u.test(raw[offset] ?? "")) {
      offset += 1;
    }
    if (start === offset) throw new Error("expected_value");
    const primitive = JSON.parse(raw.slice(start, offset)) as unknown;
    if (typeof primitive === "object" && primitive !== null) {
      throw new Error("invalid_primitive");
    }
  };
  valueToken();
  whitespace();
  if (offset !== raw.length) throw new Error("trailing_data");
  return JSON.parse(raw) as unknown;
}

function parseStatusJson(raw: string): StatusValidationResult {
  let value: unknown;
  try {
    value = parseJsonWithoutDuplicateKeys(raw);
  } catch {
    return { ok: false, code: "invalid_status" };
  }
  return validateKernelStatus(value);
}

function readinessFromHeader(value: string | null): ServerReadiness {
  if (value !== null && READINESS.has(value as ServerReadiness)) {
    return value as ServerReadiness;
  }
  return "unknown";
}

export async function fetchKernelStatus(
  fetcher: KernelStatusFetch = globalThis.fetch.bind(globalThis),
): Promise<KernelStatusLoadResult> {
  let response: Response;
  try {
    response = await fetcher("/status", {
      method: "GET",
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
      referrerPolicy: "no-referrer",
      headers: { Accept: "application/json" },
    });
  } catch {
    return { kind: "failed", code: "fetch_failed" };
  }
  if (response.status !== 200 && response.status !== 503) {
    return { kind: "failed", code: "http_failed" };
  }

  let raw: string;
  try {
    raw = await response.text();
  } catch {
    return { kind: "failed", code: "fetch_failed" };
  }
  const parsed = parseStatusJson(raw);
  if (!parsed.ok) return { kind: "failed", code: parsed.code };

  const headerValue = response.headers.get("X-Skeleton-Readiness");
  let readiness = readinessFromHeader(headerValue);
  if (parsed.value.schema_version === "skeleton.kernel-status.v2") {
    const bodyReadiness = parsed.value.evidence_health.readiness;
    if (
      headerValue === null
      || !READINESS.has(headerValue as ServerReadiness)
      || headerValue !== bodyReadiness
      || (response.status === 200) !== (bodyReadiness === "ready")
    ) {
      return { kind: "failed", code: "invalid_status" };
    }
    readiness = bodyReadiness;
  }
  return {
    kind: "loaded",
    status: parsed.value,
    readiness,
    etag: response.headers.get("ETag"),
  };
}
