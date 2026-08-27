"use strict";
(() => {
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
];
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
];
const STATUS_V2_KEYS = [
    "schema_version",
    "kernel_status_v1_sha256",
    "evidence_health",
    "observed_at",
];
const HEALTH_KEYS = [
    "snapshot_sha256",
    "source_state_sha256",
    "readiness",
    "observed_at",
    "signals",
];
const SIGNAL_KEYS = ["state", "value", "reason_code"];
const STATUS_KEY_SET = new Set(STATUS_KEYS);
const STATUS_V2_KEY_SET = new Set(STATUS_V2_KEYS);
const HEALTH_KEY_SET = new Set(HEALTH_KEYS);
const SIGNAL_NAME_SET = new Set(EVIDENCE_SIGNAL_NAMES);
const SIGNAL_KEY_SET = new Set(SIGNAL_KEYS);
const SHA256 = /^[0-9a-f]{64}$/u;
const IDENTIFIER = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/u;
const TIMESTAMP = /^([0-9]{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])(?:\.[0-9]+)?Z$/u;
const JOURNAL_DISPOSITIONS = new Set([
    "idle",
    "RECEIVED",
    "EFFECT_COMMITTED",
    "RESULT_COMMITTED",
]);
const PROCESS_HEALTH = new Set(["available", "degraded", "unavailable"]);
const READINESS = new Set([
    "ready",
    "degraded",
    "unavailable",
    "unknown",
]);
const SIGNAL_MAXIMUM = {
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
function isRecord(value) {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}
function isSha256(value) {
    return typeof value === "string" && SHA256.test(value);
}
function isIdentifier(value) {
    return (typeof value === "string"
        && value.length >= 1
        && value.length <= 128
        && IDENTIFIER.test(value));
}
function isTimestamp(value) {
    if (typeof value !== "string")
        return false;
    const match = TIMESTAMP.exec(value);
    if (match === null)
        return false;
    const instant = new Date(value);
    return Number.isFinite(instant.getTime())
        && instant.getUTCFullYear() === Number(match[1])
        && instant.getUTCMonth() + 1 === Number(match[2])
        && instant.getUTCDate() === Number(match[3])
        && instant.getUTCHours() === Number(match[4])
        && instant.getUTCMinutes() === Number(match[5])
        && instant.getUTCSeconds() === Number(match[6]);
}
function hasExactKeys(value, keys, keySet) {
    const actual = Object.keys(value);
    return actual.length === keys.length && actual.every((key) => keySet.has(key));
}
function validSignal(name, value) {
    if (!isRecord(value) || !hasExactKeys(value, SIGNAL_KEYS, SIGNAL_KEY_SET)) {
        return false;
    }
    const signalValue = value.value;
    if (signalValue !== null
        && (typeof signalValue !== "number"
            || !Number.isSafeInteger(signalValue)
            || signalValue < 0
            || signalValue > SIGNAL_MAXIMUM[name])) {
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
function readinessFromSignals(signals) {
    const states = EVIDENCE_SIGNAL_NAMES.map((name) => signals[name].state);
    if (states.includes("unavailable"))
        return "unavailable";
    if (states.includes("degraded") || states.includes("stale"))
        return "degraded";
    if (states.includes("unknown"))
        return "unknown";
    return "ready";
}
function validateKernelStatusV2(value) {
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
    if (!isSha256(value.kernel_status_v1_sha256)
        || !isSha256(health.snapshot_sha256)
        || !isSha256(health.source_state_sha256)
        || typeof health.readiness !== "string"
        || !READINESS.has(health.readiness)
        || !isTimestamp(health.observed_at)
        || !isTimestamp(value.observed_at)
        || value.observed_at !== health.observed_at) {
        return { ok: false, code: "invalid_status" };
    }
    const typedSignals = signals;
    if (health.readiness !== readinessFromSignals(typedSignals)) {
        return { ok: false, code: "invalid_status" };
    }
    return { ok: true, value: value };
}
function validateKernelStatus(value) {
    if (!isRecord(value))
        return { ok: false, code: "invalid_status" };
    if ("schema_version" in value
        && value.schema_version !== "skeleton.kernel-status.v1"
        && value.schema_version !== "skeleton.kernel-status.v2") {
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
    if (value.schema_version !== "skeleton.kernel-status.v1"
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
        || !isTimestamp(value.observed_at)) {
        return { ok: false, code: "invalid_status" };
    }
    return { ok: true, value: value };
}
function parseJsonWithoutDuplicateKeys(raw) {
    let offset = 0;
    const whitespace = () => {
        while (/[\t\n\r ]/u.test(raw[offset] ?? ""))
            offset += 1;
    };
    const stringToken = () => {
        const start = offset;
        if (raw[offset] !== '"')
            throw new Error("expected_string");
        offset += 1;
        while (offset < raw.length) {
            const character = raw[offset];
            if (character === '"') {
                offset += 1;
                return JSON.parse(raw.slice(start, offset));
            }
            if (character === "\\") {
                offset += 2;
            }
            else {
                if ((raw.charCodeAt(offset) || 0) <= 0x1f)
                    throw new Error("invalid_string");
                offset += 1;
            }
        }
        throw new Error("unterminated_string");
    };
    const valueToken = () => {
        whitespace();
        if (raw[offset] === "{") {
            offset += 1;
            whitespace();
            const keys = new Set();
            if (raw[offset] === "}") {
                offset += 1;
                return;
            }
            while (true) {
                const key = stringToken();
                if (keys.has(key))
                    throw new Error("duplicate_key");
                keys.add(key);
                whitespace();
                if (raw[offset] !== ":")
                    throw new Error("expected_colon");
                offset += 1;
                valueToken();
                whitespace();
                if (raw[offset] === "}") {
                    offset += 1;
                    return;
                }
                if (raw[offset] !== ",")
                    throw new Error("expected_comma");
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
                if (raw[offset] !== ",")
                    throw new Error("expected_comma");
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
        if (start === offset)
            throw new Error("expected_value");
        const primitive = JSON.parse(raw.slice(start, offset));
        if (typeof primitive === "object" && primitive !== null) {
            throw new Error("invalid_primitive");
        }
    };
    valueToken();
    whitespace();
    if (offset !== raw.length)
        throw new Error("trailing_data");
    return JSON.parse(raw);
}
function parseStatusJson(raw) {
    let value;
    try {
        value = parseJsonWithoutDuplicateKeys(raw);
    }
    catch {
        return { ok: false, code: "invalid_status" };
    }
    return validateKernelStatus(value);
}
function readinessFromHeader(value) {
    if (value !== null && READINESS.has(value)) {
        return value;
    }
    return "unknown";
}
async function fetchKernelStatus(fetcher = globalThis.fetch.bind(globalThis)) {
    let response;
    try {
        response = await fetcher("/status", {
            method: "GET",
            cache: "no-store",
            credentials: "omit",
            redirect: "error",
            referrerPolicy: "no-referrer",
            headers: { Accept: "application/json" },
        });
    }
    catch {
        return { kind: "failed", code: "fetch_failed" };
    }
    if (response.status !== 200 && response.status !== 503) {
        return { kind: "failed", code: "http_failed" };
    }
    let raw;
    try {
        raw = await response.text();
    }
    catch {
        return { kind: "failed", code: "fetch_failed" };
    }
    const parsed = parseStatusJson(raw);
    if (!parsed.ok)
        return { kind: "failed", code: parsed.code };
    const headerValue = response.headers.get("X-Skeleton-Readiness");
    let readiness = readinessFromHeader(headerValue);
    if (parsed.value.schema_version === "skeleton.kernel-status.v2") {
        const bodyReadiness = parsed.value.evidence_health.readiness;
        if (headerValue === null
            || !READINESS.has(headerValue)
            || headerValue !== bodyReadiness
            || (response.status === 200) !== (bodyReadiness === "ready")) {
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

const PRODUCT_LABEL = "Skeleton — Universal Personal Cognition Kernel";
const UNKNOWN_ROWS = [
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
];
const SIGNAL_PRESENTATION = {
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
function processHealth(value) {
    if (value === "available")
        return { state: "ready", label: "Available" };
    if (value === "degraded")
        return { state: "degraded", label: "Degraded" };
    return { state: "failed", label: "Unavailable" };
}
function readinessHealth(value) {
    if (value === "ready")
        return { state: "ready", label: "Ready" };
    if (value === "degraded")
        return { state: "degraded", label: "Degraded" };
    if (value === "unavailable")
        return { state: "failed", label: "Unavailable" };
    return { state: "unknown", label: "Unknown" };
}
function signalHealth(value) {
    if (value === "ready")
        return { state: "ready", label: "Ready" };
    if (value === "degraded")
        return { state: "degraded", label: "Degraded" };
    if (value === "stale")
        return { state: "degraded", label: "Stale" };
    if (value === "unavailable")
        return { state: "failed", label: "Unavailable" };
    return { state: "unknown", label: "Unknown" };
}
function unavailableSignals(reason) {
    return OWNER_EVIDENCE_SIGNAL_NAMES.map((name) => ({
        name,
        label: SIGNAL_PRESENTATION[name].label,
        unit: SIGNAL_PRESENTATION[name].unit,
        health: { state: "unknown", label: "Unknown" },
        value: "Unavailable",
        reasonCode: reason,
    }));
}
function evidenceSignals(signals) {
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
function failureCopy(code) {
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
function overallHealth(readiness, authority) {
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
function deriveOwnerStatus(result) {
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
        explanation: `Rendered from one validated read-only status response.${cognitionNote}`,
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
        bundleSha256: result.status.bundle_sha256,
        semanticStateHash: result.status.semantic_state_hash,
        journalStateHash: result.status.journal_state_hash,
        authoritySnapshotHash: result.status.authority_snapshot_hash,
        journalDisposition: result.status.incomplete_journal_disposition,
        schemaVersion: result.status.schema_version,
        observedAt: result.status.observed_at,
        contractRows: UNKNOWN_ROWS,
    };
}

const SHAPES = {
    ready: "●",
    degraded: "▲",
    failed: "■",
    unknown: "◆",
};
function node(tag, attributes, ...children) {
    return attributes === undefined
        ? { tag, children }
        : { tag, attributes, children };
}
function healthText(health) {
    return node("span", { class: `health health--${health.state}` }, node("span", { class: "health__shape", "aria-hidden": "true" }, SHAPES[health.state]), ` ${health.label}`);
}
function definition(label, value) {
    return [
        node("dt", undefined, label),
        node("dd", undefined, value),
    ];
}
function hashValue(value) {
    return node("code", { class: "hash" }, value);
}
function createOwnerStatusTree(view) {
    const observed = view.observedAt === null
        ? "Unavailable"
        : node("time", { datetime: view.observedAt }, view.observedAt);
    const evidenceObserved = view.evidenceObservedAt === null
        ? "Unavailable"
        : node("time", { datetime: view.evidenceObservedAt }, view.evidenceObservedAt);
    return node("section", {
        class: `owner-status owner-status--${view.overall}`,
        role: "status",
        "aria-live": "polite",
        "aria-atomic": "true",
    }, node("header", { class: "owner-status__header" }, node("div", { class: "owner-status__identity" }, node("span", { class: "identity-mark", "aria-hidden": "true" }, "S"), node("h2", undefined, view.productLabel)), node("p", { class: "owner-status__lobes" }, view.lobeLabel), node("p", { class: `overall overall--${view.overall}` }, node("span", { class: "health__shape", "aria-hidden": "true" }, SHAPES[view.overall]), ` ${view.overallLabel}`), node("p", { class: "owner-status__explanation" }, view.explanation)), node("div", { class: "status-grid" }, node("section", { class: "status-card", "aria-labelledby": "authority-heading" }, node("h2", { id: "authority-heading" }, "Authority"), node("dl", { class: "fact-list" }, ...definition("Writer identity", "Not exposed by status schema"), ...definition("Authority health", healthText(view.authority)), ...definition("Last command/result", "Not exposed by status schema"), ...definition("Journal disposition", view.journalDisposition), ...definition("Semantic state", hashValue(view.semanticStateHash)), ...definition("Journal state", hashValue(view.journalStateHash)), ...definition("Authority snapshot", hashValue(view.authoritySnapshotHash)))), node("section", { class: "status-card", "aria-labelledby": "process-heading" }, node("h2", { id: "process-heading" }, "Processes"), node("dl", { class: "fact-list" }, ...definition("Reference authority", healthText(view.authority)), ...definition("Cognition", healthText(view.cognition)), ...definition("Status server", "Not exposed by status schema"), ...definition("Status evidence", healthText(view.evidenceReadiness)), ...definition("Evidence health", healthText(view.evidenceHealth)), ...definition("Evidence snapshot", hashValue(view.evidenceSnapshotSha256)), ...definition("Observed", observed))), node("section", { class: "status-card status-card--wide", "aria-labelledby": "evidence-heading" }, node("h2", { id: "evidence-heading" }, "Evidence health"), node("dl", { class: "fact-list" }, ...definition("Readiness", healthText(view.evidenceHealth)), ...definition("Snapshot identity", hashValue(view.evidenceSnapshotSha256)), ...definition("Source state identity", hashValue(view.evidenceSourceStateSha256)), ...definition("Evidence observed", evidenceObserved)), node("table", { class: "evidence-table" }, node("caption", undefined, "Nine bounded redacted evidence signals"), node("thead", undefined, node("tr", undefined, node("th", { scope: "col" }, "Signal"), node("th", { scope: "col" }, "State"), node("th", { scope: "col" }, "Value"), node("th", { scope: "col" }, "Unit"), node("th", { scope: "col" }, "Reason"))), node("tbody", undefined, ...view.evidenceSignals.map((signal) => node("tr", undefined, node("th", { scope: "row" }, signal.label), node("td", undefined, healthText(signal.health)), node("td", undefined, signal.value), node("td", undefined, signal.unit), node("td", undefined, signal.reasonCode)))))), node("section", { class: "status-card status-card--wide", "aria-labelledby": "contract-heading" }, node("h2", { id: "contract-heading" }, "Contract"), node("dl", { class: "fact-list" }, ...definition("Schema", view.schemaVersion), ...definition("Bundle identity", hashValue(view.bundleSha256))), node("table", { class: "conformance-table" }, node("caption", undefined, "Runtime conformance detail"), node("tbody", undefined, ...view.contractRows.map((row) => node("tr", undefined, node("th", { scope: "row" }, row.name), node("td", undefined, row.disposition), node("td", undefined, row.detail))))))), node("p", { class: "boundary-note" }, "Private single-owner kernel. No customer funds, custody, advice, transmission, sportsbook execution, or trading capability."));
}
function escapeText(value) {
    return value
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
}
function serializeRenderTree(tree) {
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
function renderOwnerStatus(view) {
    return serializeRenderTree(createOwnerStatusTree(view));
}
function materialize(documentValue, tree) {
    const element = documentValue.createElement(tree.tag);
    for (const [name, value] of Object.entries(tree.attributes ?? {})) {
        element.setAttribute(name, value);
    }
    for (const child of tree.children) {
        element.append(typeof child === "string"
            ? documentValue.createTextNode(child)
            : materialize(documentValue, child));
    }
    return element;
}
function mountOwnerStatus(root, view) {
    root.replaceChildren(materialize(root.ownerDocument, createOwnerStatusTree(view)));
}
async function refreshOwnerStatus(root, fetcher) {
    root.setAttribute("aria-busy", "true");
    try {
        const result = fetcher === undefined
            ? await fetchKernelStatus()
            : await fetchKernelStatus(fetcher);
        mountOwnerStatus(root, deriveOwnerStatus(result));
    }
    finally {
        root.setAttribute("aria-busy", "false");
    }
}
function startOwnerStatusPage(documentValue = document) {
    const root = documentValue.getElementById("status-output");
    const refresh = documentValue.getElementById("status-refresh");
    if (!(root instanceof HTMLElement) || !(refresh instanceof HTMLButtonElement))
        return;
    refresh.addEventListener("click", () => {
        void refreshOwnerStatus(root);
    });
    void refreshOwnerStatus(root);
}
if (typeof document !== "undefined") {
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", () => startOwnerStatusPage(), { once: true });
    }
    else {
        startOwnerStatusPage();
    }
}
})();
