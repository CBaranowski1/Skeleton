"""Closed, writer-owned artifact lineage and promotion authority."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
import sqlite3
import threading
from types import MappingProxyType
from typing import Any, Final, Mapping, Sequence

from .canonical import canonicalize, parse_raw_json, sha256_hex
from .evidence_store import EvidenceStore
from .store import KernelStore


_SHA256 = re.compile(r"^[0-9a-f]{64}$")

NODE_KINDS: Final[frozenset[str]] = frozenset(
    {
        "outcome",
        "decision",
        "proposal",
        "model",
        "procedure",
        "feature",
        "dataset",
        "partition",
        "canonical_event",
        "raw_evidence",
        "derived_artifact",
        "memory",
        "backup",
        "manifest",
        "export",
    }
)
EDGE_KINDS: Final[frozenset[str]] = frozenset(
    {
        "supported_by",
        "derived_from",
        "produced_by",
        "trained_on",
        "partition_of",
        "materialized_from",
        "backed_up_as",
        "manifested_by",
        "exported_as",
    }
)
AUTHENTICATION_STATES: Final[frozenset[str]] = frozenset(
    {"verified", "unverified", "unknown"}
)
QUARANTINE_STATES: Final[frozenset[str]] = frozenset(
    {"clean", "legacy", "synthetic", "stale", "revoked_rights", "contaminated"}
)

_CORE_TRANSITIONS: Final[Mapping[str, frozenset[tuple[str, str]]]] = MappingProxyType(
    {
        "supported_by": frozenset(
            {("outcome", "proposal"), ("decision", "proposal")}
        ),
        "produced_by": frozenset(
            {("proposal", "model"), ("model", "procedure")}
        ),
        "trained_on": frozenset(
            {
                ("model", "feature"),
                ("model", "dataset"),
                ("model", "partition"),
                ("model", "canonical_event"),
                ("model", "raw_evidence"),
            }
        ),
        "partition_of": frozenset({("partition", "dataset")}),
        "materialized_from": frozenset(
            {
                ("partition", "canonical_event"),
                ("canonical_event", "raw_evidence"),
            }
        ),
        "derived_from": frozenset(
            {
                ("procedure", "feature"),
                ("feature", "dataset"),
                ("dataset", "partition"),
                ("derived_artifact", "derived_artifact"),
                ("derived_artifact", "feature"),
                ("derived_artifact", "dataset"),
                ("derived_artifact", "partition"),
                ("derived_artifact", "canonical_event"),
                ("derived_artifact", "raw_evidence"),
                ("memory", "derived_artifact"),
                ("memory", "feature"),
                ("memory", "dataset"),
                ("memory", "model"),
                ("memory", "procedure"),
                ("memory", "canonical_event"),
                ("memory", "raw_evidence"),
            }
        ),
        "backed_up_as": frozenset(
            (kind, "backup") for kind in NODE_KINDS if kind != "backup"
        ),
        "manifested_by": frozenset(
            (kind, "manifest") for kind in NODE_KINDS if kind != "manifest"
        ),
        "exported_as": frozenset(
            (kind, "export") for kind in NODE_KINDS if kind != "export"
        ),
    }
)
ALLOWED_TRANSITIONS: Final[Mapping[str, frozenset[tuple[str, str]]]] = (
    _CORE_TRANSITIONS
)
ANCESTRY_EDGE_KINDS: Final[frozenset[str]] = frozenset(
    {
        "supported_by",
        "derived_from",
        "produced_by",
        "trained_on",
        "partition_of",
        "materialized_from",
    }
)
OUTPUT_EDGE_KINDS: Final[frozenset[str]] = frozenset(
    {"backed_up_as", "manifested_by", "exported_as"}
)
DESCENDANT_ARTIFACT_CLASSES: Final[frozenset[str]] = frozenset(
    {
        "raw_evidence",
        "derived_artifact",
        "memory",
        "backup",
        "manifest",
        "model",
        "export",
    }
)
_SINGULAR_EDGE_KINDS: Final[frozenset[str]] = frozenset(
    {
        "produced_by",
        "partition_of",
        "materialized_from",
        "backed_up_as",
        "manifested_by",
        "exported_as",
    }
)


class LineageDefect(ValueError):
    """Stable graph defect containing only a closed code and opaque identity."""

    def __init__(self, code: str, artifact_id: str | None = None) -> None:
        self.code = code
        self.artifact_id = artifact_id
        super().__init__(code)


def _require_sha256(value: object, code: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise LineageDefect(code)
    return value


@dataclass(frozen=True, slots=True)
class ArtifactNode:
    artifact_id: str
    node_kind: str
    content_sha256: str
    rights_record_sha256: str
    rights_decision_sha256: str
    authentication: str
    quarantine: str

    def __post_init__(self) -> None:
        _require_sha256(self.artifact_id, "lineage_artifact_id_invalid")
        if self.node_kind not in NODE_KINDS:
            raise LineageDefect("lineage_node_kind_unknown", self.artifact_id)
        _require_sha256(self.content_sha256, "lineage_content_identity_invalid")
        _require_sha256(self.rights_record_sha256, "lineage_rights_identity_invalid")
        _require_sha256(self.rights_decision_sha256, "lineage_rights_identity_invalid")
        if self.authentication not in AUTHENTICATION_STATES:
            raise LineageDefect("lineage_authentication_unknown", self.artifact_id)
        if self.quarantine not in QUARANTINE_STATES:
            raise LineageDefect("lineage_quarantine_unknown", self.artifact_id)

    @property
    def canonical_value(self) -> dict[str, str]:
        return {
            "artifact_id": self.artifact_id,
            "authentication": self.authentication,
            "content_sha256": self.content_sha256,
            "node_kind": self.node_kind,
            "quarantine": self.quarantine,
            "rights_decision_sha256": self.rights_decision_sha256,
            "rights_record_sha256": self.rights_record_sha256,
        }


@dataclass(frozen=True, slots=True)
class ArtifactEdge:
    edge_kind: str
    from_id: str
    from_kind: str
    to_id: str
    to_kind: str

    def __post_init__(self) -> None:
        if self.edge_kind not in EDGE_KINDS:
            raise LineageDefect("lineage_edge_kind_unknown")
        _require_sha256(self.from_id, "lineage_artifact_id_invalid")
        _require_sha256(self.to_id, "lineage_artifact_id_invalid")
        if self.from_kind not in NODE_KINDS or self.to_kind not in NODE_KINDS:
            raise LineageDefect("lineage_node_kind_unknown")

    @property
    def canonical_value(self) -> dict[str, str]:
        return {
            "edge_kind": self.edge_kind,
            "from": self.from_id,
            "from_kind": self.from_kind,
            "to": self.to_id,
            "to_kind": self.to_kind,
        }


@dataclass(frozen=True, slots=True)
class TraceResult:
    subject_id: str
    nodes: tuple[ArtifactNode, ...]
    edges: tuple[ArtifactEdge, ...]
    terminals: tuple[ArtifactNode, ...]
    terminal_kinds: frozenset[str]
    rights_record_sha256s: tuple[str, ...]
    rights_decision_sha256s: tuple[str, ...]
    complete: bool
    promotable: bool
    graph_snapshot_sha256: str
    canonical_bytes: bytes
    trace_sha256: str


@dataclass(frozen=True, slots=True)
class DescendantClosure:
    root_id: str
    nodes: tuple[ArtifactNode, ...]
    edges: tuple[ArtifactEdge, ...]
    descendant_classes: tuple[str, ...]
    rights_record_sha256s: tuple[str, ...]
    rights_decision_sha256s: tuple[str, ...]
    blockers: tuple[str, ...]
    complete: bool
    graph_snapshot_sha256: str
    canonical_bytes: bytes
    closure_sha256: str


def _digest_label(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


class LineageGraph:
    """One closed artifact DAG over the injected Phase 7 sole writer."""

    __slots__ = ("_store", "_lock", "_fixture_id", "subject_id")

    def __init__(self, writer: EvidenceStore | KernelStore | sqlite3.Connection) -> None:
        if isinstance(writer, EvidenceStore):
            store = writer
        elif isinstance(writer, (KernelStore, sqlite3.Connection)):
            store = EvidenceStore(writer)
        else:
            raise TypeError("writer_connection_required")
        self._store = store
        self._lock = threading.RLock()
        self._fixture_id: str | None = None
        self.subject_id: str | None = None
        self._assert_schema()

    @property
    def connection(self) -> sqlite3.Connection:
        """Expose only the injected writer identity for composition checks."""

        return self._store.connection

    @classmethod
    def from_fixture_records(
        cls,
        records: Sequence[Mapping[str, Any]],
        *,
        writer: EvidenceStore | KernelStore | sqlite3.Connection,
        subject_kind: str = "outcome",
    ) -> LineageGraph:
        if subject_kind not in {"outcome", "decision"}:
            raise LineageDefect("lineage_subject_kind_forbidden")
        graph = cls(writer)
        rights_record_id, rights_decision_id = graph._register_fixture_rights(records)
        kinds = (
            subject_kind,
            "proposal",
            "model",
            "procedure",
            "feature",
            "dataset",
            "partition",
            "canonical_event",
            "raw_evidence",
        )
        identifiers = {
            kind: _digest_label("skeleton.lineage.fixture.v1", subject_kind, kind)
            for kind in kinds
        }
        for kind in kinds:
            artifact_id = identifiers[kind]
            content_sha256 = (
                artifact_id
                if kind == "raw_evidence"
                else _digest_label("skeleton.lineage.content.v1", subject_kind, kind)
            )
            graph.add_node(
                ArtifactNode(
                    artifact_id=artifact_id,
                    node_kind=kind,
                    content_sha256=content_sha256,
                    rights_record_sha256=rights_record_id,
                    rights_decision_sha256=rights_decision_id,
                    authentication="verified",
                    quarantine="clean",
                )
            )
        transitions = (
            ("supported_by", subject_kind, "proposal"),
            ("produced_by", "proposal", "model"),
            ("produced_by", "model", "procedure"),
            ("derived_from", "procedure", "feature"),
            ("derived_from", "feature", "dataset"),
            ("derived_from", "dataset", "partition"),
            ("materialized_from", "partition", "canonical_event"),
            ("materialized_from", "canonical_event", "raw_evidence"),
        )
        for edge_kind, from_kind, to_kind in transitions:
            graph.add_edge(
                ArtifactEdge(
                    edge_kind=edge_kind,
                    from_id=identifiers[from_kind],
                    from_kind=from_kind,
                    to_id=identifiers[to_kind],
                    to_kind=to_kind,
                )
            )
        graph.subject_id = identifiers[subject_kind]
        graph._fixture_id = "lineage-record-valid"
        graph._persist_lineage_record()
        return graph

    @classmethod
    def from_existing_fixture(
        cls,
        *,
        writer: EvidenceStore | KernelStore | sqlite3.Connection,
        subject_kind: str = "outcome",
    ) -> LineageGraph:
        """Rebind the deterministic fixture graph without appending duplicate rows."""

        if subject_kind not in {"outcome", "decision"}:
            raise LineageDefect("lineage_subject_kind_forbidden")
        graph = cls(writer)
        subject_id = _digest_label(
            "skeleton.lineage.fixture.v1", subject_kind, subject_kind
        )
        if graph.connection.execute(
            "SELECT 1 FROM artifact_nodes WHERE artifact_id = ?", (subject_id,)
        ).fetchone() is None:
            raise LineageDefect("lineage_fixture_missing")
        graph.subject_id = subject_id
        graph._fixture_id = "lineage-record-valid"
        graph.trace(subject_id)
        return graph

    def add_node(self, node: ArtifactNode) -> None:
        if not isinstance(node, ArtifactNode):
            raise TypeError("artifact_node_required")
        with self._lock, self._store.transaction() as connection:
            self._insert_node(connection, node)

    def add_edge(self, edge: ArtifactEdge) -> None:
        if not isinstance(edge, ArtifactEdge):
            raise TypeError("artifact_edge_required")
        with self._lock, self._store.transaction() as connection:
            self._insert_edge(connection, edge)

    def add_node_and_edge(self, node: ArtifactNode, edge: ArtifactEdge) -> None:
        """Commit a linked node atomically so rejected edges leave no orphan."""

        if not isinstance(node, ArtifactNode):
            raise TypeError("artifact_node_required")
        if not isinstance(edge, ArtifactEdge):
            raise TypeError("artifact_edge_required")
        if node.artifact_id not in {edge.from_id, edge.to_id}:
            raise LineageDefect("lineage_edge_dangling", node.artifact_id)
        with self._lock, self._store.transaction() as connection:
            self._insert_node(connection, node)
            self._insert_edge(connection, edge)

    def _insert_node(
        self, connection: sqlite3.Connection, node: ArtifactNode
    ) -> None:
        if node.node_kind == "raw_evidence" and node.artifact_id != node.content_sha256:
            raise LineageDefect("lineage_raw_identity_mismatch", node.artifact_id)
        rights = connection.execute(
            "SELECT decision.rights_record_id, decision.disposition, record.status "
            "FROM rights_decisions AS decision "
            "JOIN rights_records AS record "
            "ON record.rights_record_id = decision.rights_record_id "
            "WHERE decision.decision_id = ?",
            (node.rights_decision_sha256,),
        ).fetchone()
        if rights is None:
            raise LineageDefect("lineage_rights_missing", node.artifact_id)
        if (
            str(rights[0]) != node.rights_record_sha256
            or str(rights[1]) != "permit"
            or str(rights[2]) != "active"
        ):
            raise LineageDefect("lineage_rights_mismatch", node.artifact_id)
        try:
            connection.execute(
                "INSERT INTO artifact_nodes VALUES (?, ?, ?, ?, ?, ?)",
                (
                    node.artifact_id,
                    node.node_kind,
                    node.content_sha256,
                    node.authentication,
                    node.quarantine,
                    canonicalize(node.canonical_value),
                ),
            )
            connection.execute(
                "INSERT INTO artifact_rights VALUES (?, ?, ?)",
                (
                    node.artifact_id,
                    node.rights_record_sha256,
                    node.rights_decision_sha256,
                ),
            )
        except sqlite3.IntegrityError as error:
            raise LineageDefect("lineage_node_duplicate", node.artifact_id) from error

    def _insert_edge(
        self, connection: sqlite3.Connection, edge: ArtifactEdge
    ) -> None:
        from_row = connection.execute(
            "SELECT node_kind FROM artifact_nodes WHERE artifact_id = ?",
            (edge.from_id,),
        ).fetchone()
        if from_row is None:
            raise LineageDefect("lineage_node_missing", edge.from_id)
        to_row = connection.execute(
            "SELECT node_kind FROM artifact_nodes WHERE artifact_id = ?",
            (edge.to_id,),
        ).fetchone()
        if to_row is None:
            raise LineageDefect("lineage_edge_dangling", edge.to_id)
        if str(from_row[0]) != edge.from_kind or str(to_row[0]) != edge.to_kind:
            raise LineageDefect("lineage_transition_forbidden", edge.from_id)
        duplicate = connection.execute(
            "SELECT 1 FROM artifact_edges "
            "WHERE parent_id = ? AND child_id = ? AND edge_kind = ?",
            (edge.from_id, edge.to_id, edge.edge_kind),
        ).fetchone()
        if duplicate is not None:
            raise LineageDefect("lineage_duplicate_edge", edge.from_id)
        if edge.edge_kind in _SINGULAR_EDGE_KINDS:
            ambiguous = connection.execute(
                "SELECT 1 FROM artifact_edges "
                "WHERE parent_id = ? AND edge_kind = ? AND child_id <> ?",
                (edge.from_id, edge.edge_kind, edge.to_id),
            ).fetchone()
            if ambiguous is not None:
                raise LineageDefect("lineage_ambiguous", edge.from_id)
        cycle = connection.execute(
            """
            WITH RECURSIVE reachable(artifact_id) AS (
                VALUES (?)
                UNION
                SELECT stored.child_id
                FROM artifact_edges AS stored
                JOIN reachable ON stored.parent_id = reachable.artifact_id
            )
            SELECT 1 FROM reachable WHERE artifact_id = ? LIMIT 1
            """,
            (edge.to_id, edge.from_id),
        ).fetchone()
        if cycle is not None:
            raise LineageDefect("lineage_cycle", edge.from_id)
        if (edge.from_kind, edge.to_kind) not in ALLOWED_TRANSITIONS[edge.edge_kind]:
            raise LineageDefect("lineage_transition_forbidden", edge.from_id)
        try:
            connection.execute(
                "INSERT INTO artifact_edges VALUES (?, ?, ?, ?)",
                (
                    edge.from_id,
                    edge.to_id,
                    edge.edge_kind,
                    canonicalize(edge.canonical_value),
                ),
            )
        except sqlite3.IntegrityError as error:
            raise LineageDefect("lineage_duplicate_edge", edge.from_id) from error

    def trace_fixture(self, fixture_id: str) -> TraceResult:
        if fixture_id != self._fixture_id or self.subject_id is None:
            raise LineageDefect("lineage_fixture_unknown")
        return self.trace(self.subject_id)

    def trace(self, subject_id: str) -> TraceResult:
        _require_sha256(subject_id, "lineage_artifact_id_invalid")
        nodes, edges = self._stored_ancestry(subject_id)
        self._validate_graph(subject_id, nodes, edges)
        outgoing = {node.artifact_id: 0 for node in nodes}
        for edge in edges:
            outgoing[edge.from_id] += 1
        terminals = tuple(
            node for node in nodes if outgoing[node.artifact_id] == 0
        )
        graph_value = {
            "edges": [edge.canonical_value for edge in edges],
            "nodes": [node.canonical_value for node in nodes],
        }
        graph_snapshot_sha256 = sha256_hex(canonicalize(graph_value))
        trace_value = {
            "complete": True,
            "edges": [edge.canonical_value for edge in edges],
            "graph_snapshot_sha256": graph_snapshot_sha256,
            "nodes": [node.canonical_value for node in nodes],
            "promotable": True,
            "rights_decision_sha256s": sorted(
                {node.rights_decision_sha256 for node in nodes}
            ),
            "rights_record_sha256s": sorted(
                {node.rights_record_sha256 for node in nodes}
            ),
            "subject_id": subject_id,
            "terminal_ids": [node.artifact_id for node in terminals],
        }
        canonical_bytes = canonicalize(trace_value)
        return TraceResult(
            subject_id=subject_id,
            nodes=nodes,
            edges=edges,
            terminals=terminals,
            terminal_kinds=frozenset(node.node_kind for node in terminals),
            rights_record_sha256s=tuple(trace_value["rights_record_sha256s"]),
            rights_decision_sha256s=tuple(trace_value["rights_decision_sha256s"]),
            complete=True,
            promotable=True,
            graph_snapshot_sha256=graph_snapshot_sha256,
            canonical_bytes=canonical_bytes,
            trace_sha256=sha256_hex(canonical_bytes),
        )

    def assert_promotable(self, subject_id: str) -> TraceResult:
        return self.trace(subject_id)

    @property
    def raw_root_id(self) -> str:
        if self.subject_id is None:
            raise LineageDefect("lineage_subject_missing")
        trace = self.trace(self.subject_id)
        raw = tuple(
            node.artifact_id
            for node in trace.terminals
            if node.node_kind == "raw_evidence"
        )
        if len(raw) != 1:
            raise LineageDefect("lineage_raw_terminal_missing")
        return raw[0]

    def append_descendant(self, descendant_class: str) -> None:
        """Append a deterministic representative of a deletion-relevant class."""

        if descendant_class not in DESCENDANT_ARTIFACT_CLASSES:
            raise LineageDefect("lineage_descendant_class_unknown")
        if descendant_class in {"raw_evidence", "model"}:
            return
        raw_id = self.raw_root_id
        raw = self._read_node(raw_id)
        target_id = _digest_label(
            "skeleton.lineage.descendant.v1", self.subject_id or "", descendant_class
        )
        if self._store.connection.execute(
            "SELECT 1 FROM artifact_nodes WHERE artifact_id = ?", (target_id,)
        ).fetchone() is not None:
            return
        if descendant_class == "memory":
            self.append_descendant("derived_artifact")
            source_id = _digest_label(
                "skeleton.lineage.descendant.v1",
                self.subject_id or "",
                "derived_artifact",
            )
            edge_kind = "derived_from"
            from_id, from_kind = target_id, descendant_class
            to_id, to_kind = source_id, "derived_artifact"
        elif descendant_class == "derived_artifact":
            edge_kind = "derived_from"
            from_id, from_kind = target_id, descendant_class
            to_id, to_kind = raw_id, raw.node_kind
        else:
            edge_kind = {
                "backup": "backed_up_as",
                "manifest": "manifested_by",
                "export": "exported_as",
            }[descendant_class]
            from_id, from_kind = raw_id, raw.node_kind
            to_id, to_kind = target_id, descendant_class
        node = ArtifactNode(
            artifact_id=target_id,
            node_kind=descendant_class,
            content_sha256=_digest_label(
                "skeleton.lineage.descendant.content.v1",
                self.subject_id or "",
                descendant_class,
            ),
            rights_record_sha256=raw.rights_record_sha256,
            rights_decision_sha256=raw.rights_decision_sha256,
            authentication="verified",
            quarantine="clean",
        )
        self.add_node_and_edge(
            node,
            ArtifactEdge(
                edge_kind=edge_kind,
                from_id=from_id,
                from_kind=from_kind,
                to_id=to_id,
                to_kind=to_kind,
            ),
        )

    def descendant_closure(self, root_id: str) -> DescendantClosure:
        """Recompute the complete reverse dependency closure from stored facts."""

        _require_sha256(root_id, "lineage_artifact_id_invalid")
        all_nodes, all_edges = self._stored_graph()
        by_id = {node.artifact_id: node for node in all_nodes}
        if root_id not in by_id:
            raise LineageDefect("lineage_node_missing", root_id)
        self._validate_stored_dag(all_nodes, all_edges)
        ancestry_placeholders = ", ".join("?" for _ in ANCESTRY_EDGE_KINDS)
        output_placeholders = ", ".join("?" for _ in OUTPUT_EDGE_KINDS)
        closure_ids = {
            str(row[0])
            for row in self._store.connection.execute(
                f"""
                WITH RECURSIVE descendants(artifact_id) AS (
                    VALUES (?)
                    UNION
                    SELECT edge.parent_id
                    FROM artifact_edges AS edge
                    JOIN descendants
                      ON edge.child_id = descendants.artifact_id
                    WHERE edge.edge_kind IN ({ancestry_placeholders})
                    UNION
                    SELECT edge.child_id
                    FROM artifact_edges AS edge
                    JOIN descendants
                      ON edge.parent_id = descendants.artifact_id
                    WHERE edge.edge_kind IN ({output_placeholders})
                )
                SELECT artifact_id FROM descendants ORDER BY artifact_id
                """,
                (
                    root_id,
                    *sorted(ANCESTRY_EDGE_KINDS),
                    *sorted(OUTPUT_EDGE_KINDS),
                ),
            )
        }
        nodes = tuple(
            sorted(
                (by_id[artifact_id] for artifact_id in closure_ids),
                key=lambda node: node.artifact_id,
            )
        )
        edges = tuple(
            sorted(
                (
                    edge
                    for edge in all_edges
                    if edge.from_id in closure_ids and edge.to_id in closure_ids
                ),
                key=lambda edge: (edge.from_id, edge.edge_kind, edge.to_id),
            )
        )
        classes = tuple(
            sorted(
                {node.node_kind for node in nodes}
                & set(DESCENDANT_ARTIFACT_CLASSES)
            )
        )
        blockers = tuple(
            sorted(
                {
                    code
                    for node in nodes
                    for code in (
                        (
                            f"lineage_quarantined:{node.artifact_id}"
                            if node.quarantine != "clean"
                            else ""
                        ),
                        (
                            f"lineage_authentication_unverified:{node.artifact_id}"
                            if node.authentication != "verified"
                            else ""
                        ),
                    )
                    if code
                }
            )
        )
        graph_value = {
            "edges": [edge.canonical_value for edge in edges],
            "nodes": [node.canonical_value for node in nodes],
        }
        graph_snapshot_sha256 = sha256_hex(canonicalize(graph_value))
        closure_value = {
            "blockers": list(blockers),
            "complete": not blockers,
            "descendant_classes": list(classes),
            "edges": [edge.canonical_value for edge in edges],
            "graph_snapshot_sha256": graph_snapshot_sha256,
            "nodes": [node.canonical_value for node in nodes],
            "rights_decision_sha256s": sorted(
                {node.rights_decision_sha256 for node in nodes}
            ),
            "rights_record_sha256s": sorted(
                {node.rights_record_sha256 for node in nodes}
            ),
            "root_id": root_id,
        }
        canonical_bytes = canonicalize(closure_value)
        return DescendantClosure(
            root_id=root_id,
            nodes=nodes,
            edges=edges,
            descendant_classes=classes,
            rights_record_sha256s=tuple(closure_value["rights_record_sha256s"]),
            rights_decision_sha256s=tuple(
                closure_value["rights_decision_sha256s"]
            ),
            blockers=blockers,
            complete=not blockers,
            graph_snapshot_sha256=graph_snapshot_sha256,
            canonical_bytes=canonical_bytes,
            closure_sha256=sha256_hex(canonical_bytes),
        )

    def append_hostile(self, defect: str) -> None:
        if self.subject_id is None:
            raise LineageDefect("lineage_subject_missing")
        nodes, edges = self._stored_ancestry(self.subject_id)
        if defect == "missing_edge":
            self._validate_graph(self.subject_id, nodes, edges[:-1])
            raise AssertionError("hostile_missing_edge_accepted")
        if defect == "raw_hash_mismatch":
            changed = tuple(
                ArtifactNode(
                    artifact_id=node.artifact_id,
                    node_kind=node.node_kind,
                    content_sha256=(
                        _digest_label("hostile", "raw")
                        if node.node_kind == "raw_evidence"
                        else node.content_sha256
                    ),
                    rights_record_sha256=node.rights_record_sha256,
                    rights_decision_sha256=node.rights_decision_sha256,
                    authentication=node.authentication,
                    quarantine=node.quarantine,
                )
                for node in nodes
            )
            self._validate_graph(self.subject_id, changed, edges)
            raise AssertionError("hostile_raw_identity_accepted")
        if defect == "rights_mismatch":
            first = nodes[0]
            changed = (ArtifactNode(
                artifact_id=first.artifact_id,
                node_kind=first.node_kind,
                content_sha256=first.content_sha256,
                rights_record_sha256=_digest_label("hostile", "rights"),
                rights_decision_sha256=first.rights_decision_sha256,
                authentication=first.authentication,
                quarantine=first.quarantine,
            ),) + nodes[1:]
            self._validate_graph(self.subject_id, changed, edges)
            raise AssertionError("hostile_rights_identity_accepted")
        by_kind = {node.node_kind: node for node in nodes}
        subject = next(node for node in nodes if node.artifact_id == self.subject_id)
        raw = by_kind["raw_evidence"]
        if defect in {"cycle", "indirect_cycle"}:
            self.add_edge(
                ArtifactEdge(
                    edge_kind="derived_from",
                    from_id=raw.artifact_id,
                    from_kind="raw_evidence",
                    to_id=self.subject_id,
                    to_kind=subject.node_kind,
                )
            )
            raise AssertionError("hostile_cycle_accepted")
        if defect == "direct_cycle":
            self.add_edge(
                ArtifactEdge(
                    edge_kind="derived_from",
                    from_id=raw.artifact_id,
                    from_kind=raw.node_kind,
                    to_id=raw.artifact_id,
                    to_kind=raw.node_kind,
                )
            )
            raise AssertionError("hostile_cycle_accepted")
        if defect == "illegal_type_skip":
            self.add_edge(
                ArtifactEdge(
                    edge_kind="derived_from",
                    from_id=subject.artifact_id,
                    from_kind=subject.node_kind,
                    to_id=raw.artifact_id,
                    to_kind=raw.node_kind,
                )
            )
            raise AssertionError("hostile_type_skip_accepted")
        if defect == "missing_node":
            missing = _digest_label("hostile", "missing-from")
            self.add_edge(
                ArtifactEdge(
                    edge_kind="derived_from",
                    from_id=missing,
                    from_kind="derived_artifact",
                    to_id=raw.artifact_id,
                    to_kind=raw.node_kind,
                )
            )
        if defect == "dangling_edge":
            missing = _digest_label("hostile", "missing-to")
            self.add_edge(
                ArtifactEdge(
                    edge_kind="materialized_from",
                    from_id=by_kind["canonical_event"].artifact_id,
                    from_kind="canonical_event",
                    to_id=missing,
                    to_kind="raw_evidence",
                )
            )
        if defect == "duplicate_edge":
            self.add_edge(edges[0])
        if defect == "ambiguous_parent":
            proposal = by_kind["proposal"]
            alternative_id = _digest_label("hostile", "alternative-model")
            alternative = ArtifactNode(
                artifact_id=alternative_id,
                node_kind="model",
                content_sha256=_digest_label("hostile", "alternative-model-content"),
                rights_record_sha256=raw.rights_record_sha256,
                rights_decision_sha256=raw.rights_decision_sha256,
                authentication="verified",
                quarantine="clean",
            )
            self.add_node_and_edge(
                alternative,
                ArtifactEdge(
                    edge_kind="produced_by",
                    from_id=proposal.artifact_id,
                    from_kind=proposal.node_kind,
                    to_id=alternative_id,
                    to_kind="model",
                ),
            )
        if defect == "unknown_node":
            ArtifactNode(
                artifact_id=_digest_label("hostile", "unknown-node"),
                node_kind="unknown",
                content_sha256=_digest_label("hostile", "unknown-content"),
                rights_record_sha256=raw.rights_record_sha256,
                rights_decision_sha256=raw.rights_decision_sha256,
                authentication="verified",
                quarantine="clean",
            )
        if defect == "unknown_edge":
            ArtifactEdge(
                edge_kind="unknown",
                from_id=subject.artifact_id,
                from_kind=subject.node_kind,
                to_id=raw.artifact_id,
                to_kind=raw.node_kind,
            )
        if defect in {"quarantined_terminal", "unverified_raw_terminal"}:
            replacement = ArtifactNode(
                artifact_id=raw.artifact_id,
                node_kind=raw.node_kind,
                content_sha256=raw.content_sha256,
                rights_record_sha256=raw.rights_record_sha256,
                rights_decision_sha256=raw.rights_decision_sha256,
                authentication=(
                    "unverified"
                    if defect == "unverified_raw_terminal"
                    else raw.authentication
                ),
                quarantine=(
                    "contaminated"
                    if defect == "quarantined_terminal"
                    else raw.quarantine
                ),
            )
            changed = tuple(replacement if node == raw else node for node in nodes)
            self._validate_graph(self.subject_id, changed, edges)
        if defect == "missing_raw_terminal":
            changed_nodes = tuple(node for node in nodes if node != raw)
            changed_edges = tuple(
                edge
                for edge in edges
                if edge.from_id != raw.artifact_id and edge.to_id != raw.artifact_id
            )
            self._validate_graph(self.subject_id, changed_nodes, changed_edges)
        if defect == "non_raw_terminal":
            changed_edges = tuple(
                edge
                for edge in edges
                if not (
                    edge.from_kind == "canonical_event"
                    and edge.to_kind == "raw_evidence"
                )
            )
            self._validate_graph(self.subject_id, nodes, changed_edges)
        if defect == "disconnected_subgraph":
            orphan_id = _digest_label("hostile", "disconnected-raw")
            orphan = ArtifactNode(
                artifact_id=orphan_id,
                node_kind="raw_evidence",
                content_sha256=orphan_id,
                rights_record_sha256=raw.rights_record_sha256,
                rights_decision_sha256=raw.rights_decision_sha256,
                authentication="verified",
                quarantine="clean",
            )
            self._validate_graph(self.subject_id, nodes + (orphan,), edges)
        raise LineageDefect("lineage_hostile_case_unknown")

    def logical_snapshot(self) -> tuple[tuple[tuple[Any, ...], ...], ...]:
        return tuple(
            tuple(
                tuple(row)
                for row in self._store.connection.execute(
                    f"SELECT * FROM {table} ORDER BY {order_by}"
                )
            )
            for table, order_by in (
                ("artifact_nodes", "artifact_id"),
                ("artifact_edges", "parent_id, edge_kind, child_id"),
                (
                    "artifact_rights",
                    "artifact_id, rights_record_id, rights_decision_id",
                ),
                ("lineage_records", "lineage_id"),
            )
        )

    def _assert_schema(self) -> None:
        required = {"artifact_nodes", "artifact_edges", "artifact_rights", "lineage_records"}
        observed = {
            str(row[0])
            for row in self._store.connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        if not required <= observed:
            raise LineageDefect("lineage_store_schema_missing")

    def _register_fixture_rights(
        self, records: Sequence[Mapping[str, Any]]
    ) -> tuple[str, str]:
        by_id = {str(record.get("id")): record for record in records}
        required = (
            "legal-terms-record-valid",
            "rights-record-valid",
            "rights-use-decision-valid",
            "lineage-record-valid",
        )
        if any(identifier not in by_id for identifier in required):
            raise LineageDefect("lineage_fixture_incomplete")
        for identifier in required:
            record = by_id[identifier]
            payload = record.get("payload")
            source_sha256 = record.get("source_sha256")
            if (
                not isinstance(payload, dict)
                or not isinstance(source_sha256, str)
                or sha256_hex(canonicalize(payload)) != source_sha256
            ):
                raise LineageDefect("lineage_fixture_identity_mismatch")
        legal = by_id["legal-terms-record-valid"]["payload"]
        rights = by_id["rights-record-valid"]["payload"]
        decision = by_id["rights-use-decision-valid"]["payload"]
        with self._lock, self._store.transaction() as connection:
            connection.execute(
                "INSERT INTO legal_terms_records VALUES (?, 'venue_contract', ?, ?, ?, ?)",
                (
                    legal["legal_terms_id"],
                    legal["effective_from"],
                    legal["effective_to"],
                    legal["effective_from"],
                    canonicalize(legal),
                ),
            )
            connection.execute(
                "INSERT INTO rights_records VALUES (?, ?, ?, ?, ?, ?)",
                (
                    rights["rights_record_id"],
                    rights["legal_terms_id"],
                    rights["status"],
                    rights["effective_from"],
                    rights["effective_to"],
                    canonicalize(rights),
                ),
            )
            connection.execute(
                "INSERT INTO rights_decisions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    decision["decision_id"],
                    decision["request_id"],
                    decision["legal_terms_id"],
                    decision["rights_record_id"],
                    decision["boundary"],
                    decision["decision"],
                    decision["reason_code"],
                    decision["decided_at"],
                    canonicalize(decision),
                ),
            )
        return str(rights["rights_record_id"]), str(decision["decision_id"])

    def _read_node(self, artifact_id: str) -> ArtifactNode:
        rows = self._store.connection.execute(
            "SELECT node.artifact_id, node.node_kind, node.content_sha256, "
            "node.authentication, node.quarantine, node.canonical_node, "
            "rights.rights_record_id, rights.rights_decision_id "
            "FROM artifact_nodes AS node "
            "LEFT JOIN artifact_rights AS rights "
            "ON rights.artifact_id = node.artifact_id "
            "WHERE node.artifact_id = ? "
            "ORDER BY rights.rights_record_id, rights.rights_decision_id",
            (artifact_id,),
        ).fetchall()
        if not rows:
            raise LineageDefect("lineage_node_missing", artifact_id)
        if any(row[6] is None or row[7] is None for row in rows):
            raise LineageDefect("lineage_rights_mismatch", artifact_id)
        node = self._node_from_bytes(bytes(rows[0][5]))
        if any(
            tuple(row[index] for index in (0, 1, 2, 3, 4, 5))
            != tuple(rows[0][index] for index in (0, 1, 2, 3, 4, 5))
            for row in rows[1:]
        ):
            raise LineageDefect("lineage_node_identity_mismatch", artifact_id)
        if any(str(row[6]) != node.rights_record_sha256 for row in rows):
            raise LineageDefect("lineage_rights_mismatch", artifact_id)
        canonical_bindings = tuple(
            row for row in rows if str(row[7]) == node.rights_decision_sha256
        )
        if len(canonical_bindings) != 1:
            raise LineageDefect("lineage_rights_mismatch", artifact_id)
        row = canonical_bindings[0]
        expected = (
            node.artifact_id,
            node.node_kind,
            node.content_sha256,
            node.authentication,
            node.quarantine,
            node.rights_record_sha256,
            node.rights_decision_sha256,
        )
        observed = tuple(str(row[index]) for index in (0, 1, 2, 3, 4, 6, 7))
        if observed != expected or canonicalize(node.canonical_value) != bytes(row[5]):
            raise LineageDefect("lineage_node_identity_mismatch", artifact_id)
        decision = self._store.connection.execute(
            "SELECT decision.rights_record_id, decision.disposition, record.status "
            "FROM rights_decisions AS decision "
            "JOIN rights_records AS record "
            "ON record.rights_record_id = decision.rights_record_id "
            "WHERE decision.decision_id = ?",
            (node.rights_decision_sha256,),
        ).fetchone()
        if (
            decision is None
            or str(decision[0]) != node.rights_record_sha256
            or str(decision[1]) != "permit"
            or str(decision[2]) != "active"
        ):
            raise LineageDefect("lineage_rights_mismatch", artifact_id)
        return node

    def _stored_graph(
        self,
    ) -> tuple[tuple[ArtifactNode, ...], tuple[ArtifactEdge, ...]]:
        identifiers = tuple(
            str(row[0])
            for row in self._store.connection.execute(
                "SELECT artifact_id FROM artifact_nodes ORDER BY artifact_id"
            )
        )
        nodes = tuple(self._read_node(identifier) for identifier in identifiers)
        edges: list[ArtifactEdge] = []
        for row in self._store.connection.execute(
            "SELECT parent_id, child_id, edge_kind, canonical_edge "
            "FROM artifact_edges ORDER BY parent_id, edge_kind, child_id"
        ):
            edge = self._edge_from_bytes(bytes(row[3]))
            observed = (str(row[0]), str(row[1]), str(row[2]))
            expected = (edge.from_id, edge.to_id, edge.edge_kind)
            if observed != expected or canonicalize(edge.canonical_value) != bytes(row[3]):
                raise LineageDefect("lineage_edge_identity_mismatch", edge.from_id)
            edges.append(edge)
        return nodes, tuple(edges)

    def _validate_stored_dag(
        self,
        nodes: tuple[ArtifactNode, ...],
        edges: tuple[ArtifactEdge, ...],
    ) -> None:
        by_id = {node.artifact_id: node for node in nodes}
        adjacency: dict[str, list[str]] = {identifier: [] for identifier in by_id}
        singular: set[tuple[str, str]] = set()
        for edge in edges:
            if edge.from_id not in by_id:
                raise LineageDefect("lineage_node_missing", edge.from_id)
            if edge.to_id not in by_id:
                raise LineageDefect("lineage_edge_dangling", edge.to_id)
            if (
                by_id[edge.from_id].node_kind != edge.from_kind
                or by_id[edge.to_id].node_kind != edge.to_kind
                or (edge.from_kind, edge.to_kind)
                not in ALLOWED_TRANSITIONS[edge.edge_kind]
            ):
                raise LineageDefect("lineage_transition_forbidden", edge.from_id)
            key = (edge.from_id, edge.edge_kind)
            if edge.edge_kind in _SINGULAR_EDGE_KINDS and key in singular:
                raise LineageDefect("lineage_ambiguous", edge.from_id)
            singular.add(key)
            adjacency[edge.from_id].append(edge.to_id)
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(artifact_id: str) -> None:
            if artifact_id in visiting:
                raise LineageDefect("lineage_cycle", artifact_id)
            if artifact_id in visited:
                return
            visiting.add(artifact_id)
            for child_id in sorted(adjacency[artifact_id]):
                visit(child_id)
            visiting.remove(artifact_id)
            visited.add(artifact_id)

        for artifact_id in sorted(by_id):
            visit(artifact_id)
    def _stored_ancestry(
        self, subject_id: str
    ) -> tuple[tuple[ArtifactNode, ...], tuple[ArtifactEdge, ...]]:
        all_nodes, all_edges = self._stored_graph()
        self._validate_stored_dag(all_nodes, all_edges)
        by_id = {node.artifact_id: node for node in all_nodes}
        if subject_id not in by_id:
            raise LineageDefect("lineage_node_missing", subject_id)
        placeholders = ", ".join("?" for _ in ANCESTRY_EDGE_KINDS)
        identifiers = {
            str(row[0])
            for row in self._store.connection.execute(
                f"""
                WITH RECURSIVE ancestors(artifact_id) AS (
                    VALUES (?)
                    UNION
                    SELECT edge.child_id
                    FROM artifact_edges AS edge
                    JOIN ancestors ON edge.parent_id = ancestors.artifact_id
                    WHERE edge.edge_kind IN ({placeholders})
                )
                SELECT artifact_id FROM ancestors ORDER BY artifact_id
                """,
                (subject_id, *sorted(ANCESTRY_EDGE_KINDS)),
            )
        }
        nodes = tuple(
            sorted(
                (by_id[identifier] for identifier in identifiers),
                key=lambda node: node.artifact_id,
            )
        )
        edges = tuple(
            sorted(
                (
                    edge
                    for edge in all_edges
                    if edge.edge_kind in ANCESTRY_EDGE_KINDS
                    and edge.from_id in identifiers
                    and edge.to_id in identifiers
                ),
                key=lambda edge: (edge.from_id, edge.edge_kind, edge.to_id),
            )
        )
        return nodes, edges

    def _validate_graph(
        self,
        subject_id: str,
        nodes: tuple[ArtifactNode, ...],
        edges: tuple[ArtifactEdge, ...],
    ) -> None:
        by_id = {node.artifact_id: node for node in nodes}
        if subject_id not in by_id:
            raise LineageDefect("lineage_node_missing", subject_id)
        adjacency: dict[str, list[str]] = {artifact_id: [] for artifact_id in by_id}
        for edge in edges:
            if edge.from_id not in by_id:
                raise LineageDefect("lineage_node_missing", edge.from_id)
            if edge.to_id not in by_id:
                raise LineageDefect("lineage_edge_dangling", edge.to_id)
            if (
                by_id[edge.from_id].node_kind != edge.from_kind
                or by_id[edge.to_id].node_kind != edge.to_kind
                or (edge.from_kind, edge.to_kind)
                not in ALLOWED_TRANSITIONS[edge.edge_kind]
            ):
                raise LineageDefect("lineage_transition_forbidden", edge.from_id)
            adjacency[edge.from_id].append(edge.to_id)
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(artifact_id: str) -> None:
            if artifact_id in visiting:
                raise LineageDefect("lineage_cycle", artifact_id)
            if artifact_id in visited:
                return
            visiting.add(artifact_id)
            for child_id in sorted(adjacency[artifact_id]):
                visit(child_id)
            visiting.remove(artifact_id)
            visited.add(artifact_id)

        visit(subject_id)
        terminals = tuple(by_id[identifier] for identifier in visited if not adjacency[identifier])
        if not terminals or any(node.node_kind != "raw_evidence" for node in terminals):
            raise LineageDefect("lineage_raw_terminal_missing")
        if visited != set(by_id):
            raise LineageDefect("lineage_disconnected")
        for node in sorted(nodes, key=lambda item: item.artifact_id):
            if node.node_kind == "raw_evidence" and node.artifact_id != node.content_sha256:
                raise LineageDefect("lineage_raw_identity_mismatch", node.artifact_id)
            rights_rows = self._store.connection.execute(
                "SELECT rights_record_id, rights_decision_id FROM artifact_rights "
                "WHERE artifact_id = ? ORDER BY rights_record_id, rights_decision_id",
                (node.artifact_id,),
            ).fetchall()
            expected = (node.rights_record_sha256, node.rights_decision_sha256)
            normalized = tuple((str(row[0]), str(row[1])) for row in rights_rows)
            if (
                expected not in normalized
                or any(row[0] != node.rights_record_sha256 for row in normalized)
            ):
                raise LineageDefect("lineage_rights_mismatch", node.artifact_id)
            decision = self._store.connection.execute(
                "SELECT rights_record_id, disposition FROM rights_decisions "
                "WHERE decision_id = ?",
                (node.rights_decision_sha256,),
            ).fetchone()
            if (
                decision is None
                or str(decision[0]) != node.rights_record_sha256
                or str(decision[1]) != "permit"
            ):
                raise LineageDefect("lineage_rights_mismatch", node.artifact_id)
            if node.quarantine != "clean":
                raise LineageDefect("lineage_quarantined", node.artifact_id)
            if node.authentication != "verified":
                raise LineageDefect(
                    "lineage_authentication_unverified", node.artifact_id
                )
        component = {
            str(row[0])
            for row in self._store.connection.execute(
                """
                WITH RECURSIVE connected(artifact_id) AS (
                    VALUES (?)
                    UNION
                    SELECT edge.child_id FROM artifact_edges AS edge
                    JOIN connected ON edge.parent_id = connected.artifact_id
                    UNION
                    SELECT edge.parent_id FROM artifact_edges AS edge
                    JOIN connected ON edge.child_id = connected.artifact_id
                )
                SELECT artifact_id FROM connected
                """,
                (subject_id,),
            )
        }
        subject = by_id[subject_id]
        scoped = {
            str(row[0])
            for row in self._store.connection.execute(
                "SELECT artifact_id FROM artifact_rights "
                "WHERE rights_record_id = ? AND rights_decision_id = ?",
                (
                    subject.rights_record_sha256,
                    subject.rights_decision_sha256,
                ),
            )
        }
        if not scoped <= component:
            raise LineageDefect("lineage_disconnected")

    def _persist_lineage_record(self) -> None:
        if self.subject_id is None:
            raise LineageDefect("lineage_subject_missing")
        trace = self.trace(self.subject_id)
        lineage_id = _digest_label(
            "skeleton.lineage.record.v1", self.subject_id, trace.graph_snapshot_sha256
        )
        value = {
            "edges": [edge.canonical_value for edge in trace.edges],
            "graph_sha256": trace.graph_snapshot_sha256,
            "lineage_id": lineage_id,
            "nodes": [node.canonical_value for node in trace.nodes],
            "subject_artifact_id": self.subject_id,
        }
        with self._lock, self._store.transaction() as connection:
            connection.execute(
                "INSERT INTO lineage_records VALUES (?, ?, ?, ?)",
                (
                    lineage_id,
                    self.subject_id,
                    trace.graph_snapshot_sha256,
                    canonicalize(value),
                ),
            )

    @staticmethod
    def _node_from_bytes(raw: bytes) -> ArtifactNode:
        value = parse_raw_json(raw)
        if not isinstance(value, dict):
            raise LineageDefect("lineage_node_identity_mismatch")
        return ArtifactNode(
            artifact_id=value.get("artifact_id"),
            node_kind=value.get("node_kind"),
            content_sha256=value.get("content_sha256"),
            rights_record_sha256=value.get("rights_record_sha256"),
            rights_decision_sha256=value.get("rights_decision_sha256"),
            authentication=value.get("authentication"),
            quarantine=value.get("quarantine"),
        )

    @staticmethod
    def _edge_from_bytes(raw: bytes) -> ArtifactEdge:
        value = parse_raw_json(raw)
        if not isinstance(value, dict):
            raise LineageDefect("lineage_edge_identity_mismatch")
        return ArtifactEdge(
            edge_kind=value.get("edge_kind"),
            from_id=value.get("from"),
            from_kind=value.get("from_kind"),
            to_id=value.get("to"),
            to_kind=value.get("to_kind"),
        )
