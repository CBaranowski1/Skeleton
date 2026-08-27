"""Isolated append-only persistence for Phase 9 deterministic simulation."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import multiprocessing
from multiprocessing.connection import Connection
import os
from pathlib import Path
import sqlite3
import tempfile
from typing import Any, Mapping

from .canonical import canonicalize, parse_raw_json, sha256_hex
from .simulation_engine import SimulationTrace, SimulationTransition
from .simulation_contracts import (
    ARTIFACT_SCHEMA_ID,
    REPORT_SCHEMA_ID,
    SimulationContractPublication,
    SimulationContractValue,
)
from .simulation_migrations import (
    MIGRATION_ID,
    MIGRATION_SHA256,
    SIMULATION_TABLES,
)


_RUN_DOMAIN = "SKELETON_PHASE09_SIMULATION_RUN_V1"
_TRACE_DOMAIN = "SKELETON_SIMULATION_TRACE_V1"
_TRANSITION_DOMAIN = "SKELETON_SIMULATION_TRANSITION_V1"
_REPORT_DOMAIN = "SKELETON_PHASE09_SIMULATION_REPORT_RECORD_V1"
_ANCESTRY_DOMAIN = "SKELETON_PHASE09_SIMULATION_RUN_ANCESTRY_V1"
_CHANGED_INPUT_DOMAIN = "SKELETON_PHASE09_CHANGED_INPUT_INVENTORY_V1"
_UPSTREAM_TABLE_DOMAIN = "SKELETON_PHASE09_SEEDED_UPSTREAM_TABLES_V1"
_TERMINAL_STATES = frozenset({"completed", "unresolved", "abstained", "rolled_back"})


@dataclass(slots=True)
class SimulationStoreRejection(ValueError):
    code: str

    def __str__(self) -> str:
        return self.code


def _reject(code: str) -> None:
    raise SimulationStoreRejection(code)


def _framed_digest(domain: str, payload: bytes) -> str:
    domain_bytes = domain.encode("ascii", errors="strict")
    return sha256(
        len(domain_bytes).to_bytes(8, "big")
        + domain_bytes
        + len(payload).to_bytes(8, "big")
        + payload
    ).hexdigest()


def _is_reparse(path: Path) -> bool:
    return path.is_symlink() or bool(
        hasattr(os.path, "isjunction") and os.path.isjunction(path)
    )


def _production_contracts_root() -> Path:
    candidates = tuple(
        parent / "contracts" / "v1"
        for parent in Path(__file__).resolve().parents
        if (
            parent
            / "contracts"
            / "v1"
            / "schemas"
            / "simulation-primitives.schema.json"
        ).is_file()
    )
    if len(candidates) != 1:
        _reject("simulation_contracts_root_unavailable")
    return candidates[0]


def _require_hash(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _reject(code)
    return value


def _plain_json(raw: bytes, code: str) -> dict[str, Any]:
    try:
        value = parse_raw_json(raw)
    except Exception as error:
        raise SimulationStoreRejection(code) from error
    if not isinstance(value, dict) or canonicalize(value) != raw:
        _reject(code)
    return value


def _jsonable(value: object) -> object:
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if value is None or isinstance(value, (bool, int, str)):
        return value
    _reject("upstream_table_value_invalid")


@dataclass(frozen=True, slots=True)
class _DetachedRows:
    rows: tuple[tuple[object, ...], ...]

    def fetchone(self) -> tuple[object, ...] | None:
        return self.rows[0] if self.rows else None

    def fetchall(self) -> list[tuple[object, ...]]:
        return list(self.rows)

    def __iter__(self):
        return iter(self.rows)


def _sqlite_authorizer(
    action: int,
    arg1: str | None,
    arg2: str | None,
    database: str | None,
    trigger: str | None,
) -> int:
    del database, trigger
    if action in {
        sqlite3.SQLITE_SELECT,
        sqlite3.SQLITE_READ,
        sqlite3.SQLITE_TRANSACTION,
        getattr(sqlite3, "SQLITE_RECURSIVE", -1),
        getattr(sqlite3, "SQLITE_SAVEPOINT", -2),
    }:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_FUNCTION:
        return (
            sqlite3.SQLITE_DENY
            if str(arg2).lower() == "load_extension"
            else sqlite3.SQLITE_OK
        )
    if action == sqlite3.SQLITE_INSERT and arg1 in SIMULATION_TABLES:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_PRAGMA and str(arg1).lower() in {
        "foreign_key_check",
        "foreign_keys",
        "integrity_check",
        "quick_check",
        "query_only",
        "table_info",
    }:
        if arg2 is None or str(arg1).lower() == "table_info":
            return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def _sqlite_worker(path: str, channel: Connection) -> None:
    """Own the only SQLite connection in a process unreachable from callers."""

    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(path, timeout=0.0)
        connection.execute("PRAGMA foreign_keys = ON")
        if connection.execute("PRAGMA foreign_keys").fetchone() != (1,):
            raise RuntimeError("foreign_keys_unavailable")
        connection.execute("PRAGMA locking_mode = EXCLUSIVE")
        connection.set_authorizer(_sqlite_authorizer)
        connection.execute("BEGIN EXCLUSIVE")
        connection.commit()
        channel.send(("ready", None))
        while True:
            try:
                request = channel.recv()
            except EOFError:
                break
            if (
                not isinstance(request, tuple)
                or len(request) != 3
                or not isinstance(request[0], int)
                or not isinstance(request[1], str)
                or not isinstance(request[2], tuple)
            ):
                channel.send(("protocol_error", "sqlite_worker_request_invalid"))
                continue
            sequence, operation, arguments = request
            try:
                if operation == "execute" and len(arguments) == 2:
                    sql, parameters = arguments
                    if not isinstance(sql, str) or not isinstance(parameters, tuple):
                        raise TypeError("sqlite_worker_execute_invalid")
                    cursor = connection.execute(sql, parameters)
                    rows = (
                        tuple(tuple(row) for row in cursor.fetchall())
                        if cursor.description
                        else ()
                    )
                    result: object = rows
                elif operation == "commit" and not arguments:
                    connection.commit()
                    result = None
                elif operation == "rollback" and not arguments:
                    connection.rollback()
                    result = None
                elif operation == "in_transaction" and not arguments:
                    result = bool(connection.in_transaction)
                elif operation == "close" and not arguments:
                    if connection.in_transaction:
                        connection.rollback()
                    connection.close()
                    connection = None
                    channel.send((sequence, "ok", None))
                    return
                else:
                    raise ValueError("sqlite_worker_operation_forbidden")
                channel.send((sequence, "ok", result))
            except BaseException as error:
                channel.send(
                    (
                        sequence,
                        "error",
                        (type(error).__module__, type(error).__name__, str(error)),
                    )
                )
    except BaseException as error:
        try:
            channel.send(
                (
                    "startup_error",
                    (type(error).__module__, type(error).__name__, str(error)),
                )
            )
        except (BrokenPipeError, EOFError, OSError):
            pass
    finally:
        if connection is not None:
            try:
                if connection.in_transaction:
                    connection.rollback()
                connection.close()
            except sqlite3.Error:
                pass
        channel.close()


class _SqliteProcessMembrane:
    """Typed IPC only; this object graph never contains a sqlite3.Connection."""

    __slots__ = ("_channel", "_closed", "_process", "_sequence")

    def __init__(self, path: Path) -> None:
        context = multiprocessing.get_context("spawn")
        parent, child = context.Pipe(duplex=True)
        process = context.Process(
            target=_sqlite_worker,
            args=(str(path), child),
            daemon=True,
            name="skeleton-phase09-sqlite-owner",
        )
        process.start()
        child.close()
        self._channel = parent
        self._process = process
        self._sequence = 0
        self._closed = False
        if not parent.poll(10.0):
            process.terminate()
            process.join(5.0)
            parent.close()
            _reject("simulation_sqlite_worker_unavailable")
        response = parent.recv()
        if response != ("ready", None):
            process.join(5.0)
            parent.close()
            _reject("simulation_sqlite_worker_start_failed")

    @staticmethod
    def _raise_remote(details: object) -> None:
        if (
            not isinstance(details, tuple)
            or len(details) != 3
            or not all(isinstance(item, str) for item in details)
        ):
            _reject("simulation_sqlite_worker_protocol_invalid")
        module, name, message = details
        if module == "sqlite3" and name == "OperationalError":
            raise sqlite3.OperationalError(message)
        if module == "sqlite3" and name in {
            "DatabaseError",
            "IntegrityError",
            "ProgrammingError",
        }:
            exception = getattr(sqlite3, name, sqlite3.DatabaseError)
            raise exception(message)
        if module == "builtins" and name == "TypeError":
            raise TypeError(message)
        if module == "builtins" and name == "ValueError":
            raise ValueError(message)
        raise RuntimeError(f"sqlite_worker_error:{name}:{message}")

    def _request(self, operation: str, *arguments: object) -> object:
        if self._closed or not self._process.is_alive():
            _reject("simulation_sqlite_worker_unavailable")
        self._sequence += 1
        sequence = self._sequence
        try:
            self._channel.send((sequence, operation, tuple(arguments)))
            response = self._channel.recv()
        except (BrokenPipeError, EOFError, OSError) as error:
            raise SimulationStoreRejection("simulation_sqlite_worker_unavailable") from error
        if (
            not isinstance(response, tuple)
            or len(response) != 3
            or response[0] != sequence
            or response[1] not in {"ok", "error"}
        ):
            _reject("simulation_sqlite_worker_protocol_invalid")
        if response[1] == "error":
            self._raise_remote(response[2])
        return response[2]

    def execute(self, sql: str, parameters: tuple[object, ...] = ()) -> _DetachedRows:
        rows = self._request("execute", sql, parameters)
        if not isinstance(rows, tuple):
            _reject("simulation_sqlite_worker_protocol_invalid")
        return _DetachedRows(rows)

    def commit(self) -> None:
        self._request("commit")

    def rollback(self) -> None:
        self._request("rollback")

    def in_transaction(self) -> bool:
        result = self._request("in_transaction")
        if not isinstance(result, bool):
            _reject("simulation_sqlite_worker_protocol_invalid")
        return result

    def close(self) -> None:
        if self._closed:
            return
        try:
            if self._process.is_alive():
                self._request("close")
        finally:
            self._closed = True
            self._channel.close()
            self._process.join(5.0)
            if self._process.is_alive():
                self._process.terminate()
                self._process.join(5.0)


def _open_exclusive_sqlite_membrane(path: Path):
    membrane = _SqliteProcessMembrane(path)
    return (
        membrane.execute,
        membrane.commit,
        membrane.rollback,
        membrane.close,
        membrane.in_transaction,
    )


@dataclass(frozen=True, slots=True)
class PersistedSimulationReport:
    report_id: str
    run_id: str
    trace_root: str
    canonical_sha256: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class PersistedSimulationRun:
    run_id: str
    manifest_id: str
    trace_root: str
    terminal_status: str
    canonical_sha256: str
    canonical_bytes: bytes
    transitions: tuple[SimulationTransition, ...]
    report: PersistedSimulationReport


@dataclass(frozen=True, slots=True)
class PersistedRunAncestry:
    child_run_id: str
    parent_run_id: str
    changed_input_ids: tuple[str, ...]
    superseded_report_id: str
    canonical_sha256: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class PersistedModelProfile:
    model_profile_id: str
    family: str
    prior_model_profile_id: str | None
    model_version: str
    algorithm_id: str
    canonical_sha256: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class PersistedCalibration:
    calibration_id: str
    manifest_id: str
    prior_model_profile_id: str
    output_model_profile_id: str
    evaluation_request_id: str
    algorithm_id: str
    canonical_sha256: str
    canonical_bytes: bytes


class SimulationStore:
    """Exclusive SQLite owner permitting only append-only Phase 9 inserts."""

    __slots__ = (
        "__execute",
        "__commit",
        "__rollback",
        "__close_owner",
        "__in_transaction",
        "_database_path",
        "_temporary_root",
        "_publication",
        "_closed",
    )

    def __init__(
        self,
        *,
        database_path: Path | str,
        temporary_root: Path | str,
    ) -> None:
        root = Path(temporary_root).resolve(strict=True)
        system_temp = Path(tempfile.gettempdir()).resolve(strict=True)
        if (
            not root.is_dir()
            or _is_reparse(root)
            or (root != system_temp and system_temp not in root.parents)
        ):
            _reject("simulation_temporary_root_invalid")
        path = Path(database_path).resolve(strict=True)
        if (
            not path.is_file()
            or _is_reparse(path)
            or root not in path.parents
        ):
            _reject("simulation_database_outside_temporary_root")
        execute, commit, rollback, close_owner, in_transaction = (
            _open_exclusive_sqlite_membrane(path)
        )
        if in_transaction():
            close_owner()
            _reject("active_transaction_forbidden")
        row = execute(
            "SELECT sql_sha256 FROM schema_migrations WHERE migration_id=?",
            (MIGRATION_ID,),
        ).fetchone()
        if row is None or str(row[0]) != MIGRATION_SHA256:
            close_owner()
            _reject("simulation_schema_unauthenticated")
        self.__execute = execute
        self.__commit = commit
        self.__rollback = rollback
        self.__close_owner = close_owner
        self.__in_transaction = in_transaction
        self._database_path = path
        self._temporary_root = root
        self._publication = SimulationContractPublication.from_registry(
            _production_contracts_root()
        )
        self._closed = False

    @staticmethod
    def transition_identity(canonical_bytes: bytes) -> str:
        return _framed_digest(_TRANSITION_DOMAIN, canonical_bytes)

    @staticmethod
    def trace_identity(canonical_bytes: bytes) -> str:
        return _framed_digest(_TRACE_DOMAIN, canonical_bytes)

    @staticmethod
    def run_identity(canonical_body: bytes) -> str:
        return _framed_digest(_RUN_DOMAIN, canonical_body)

    @staticmethod
    def report_identity(canonical_body: bytes) -> str:
        return _framed_digest(_REPORT_DOMAIN, canonical_body)

    @staticmethod
    def ancestry_identity(canonical_body: bytes) -> str:
        return _framed_digest(_ANCESTRY_DOMAIN, canonical_body)

    def close(self) -> None:
        if self._closed:
            return
        self.__close_owner()
        self._closed = True

    def upstream_table_snapshot(self) -> str:
        """Hash every seeded non-Phase-9 table independently of schema metadata."""

        names = tuple(
            str(row[0])
            for row in self.__execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
            if str(row[0]) != "schema_migrations"
            and not str(row[0]).startswith("simulation_")
        )
        material: list[dict[str, object]] = []
        for name in names:
            if not name.replace("_", "a").isalnum():
                _reject("upstream_table_identity_invalid")
            columns = tuple(
                str(row[1])
                for row in self.__execute(f'PRAGMA table_info("{name}")')
            )
            if not columns:
                _reject("upstream_table_unavailable")
            order = ", ".join(f'"{column}"' for column in columns)
            rows = self.__execute(
                f'SELECT * FROM "{name}" ORDER BY {order}'
            ).fetchall()
            material.append(
                {
                    "columns": list(columns),
                    "name": name,
                    "rows": [[_jsonable(item) for item in row] for row in rows],
                }
            )
        return _framed_digest(_UPSTREAM_TABLE_DOMAIN, canonicalize(material))

    def row_counts(self) -> dict[str, int]:
        return {
            table: int(
                self.__execute(f'SELECT count(*) FROM "{table}"').fetchone()[0]
            )
            for table in SIMULATION_TABLES
        }

    def persist_model_profile(
        self,
        profile: SimulationContractValue,
        *,
        algorithm_id: str = "declared-profile-v1",
    ) -> PersistedModelProfile:
        persisted = self._model_profile_record(
            profile,
            prior_model_profile_id=None,
            algorithm_id=algorithm_id,
        )
        upstream_before = self.upstream_table_snapshot()
        if self.__in_transaction():
            _reject("nested_transaction")
        self.__execute("BEGIN IMMEDIATE")
        try:
            self._insert_model_profile(persisted)
            if self.upstream_table_snapshot() != upstream_before:
                _reject("upstream_mutation_detected")
            self.__commit()
        except BaseException as error:
            self.__rollback()
            if isinstance(error, SimulationStoreRejection):
                raise
            raise SimulationStoreRejection("model_profile_persist_failed") from error
        return persisted

    def _model_profile_record(
        self,
        profile: SimulationContractValue,
        *,
        prior_model_profile_id: str | None,
        algorithm_id: str,
    ) -> PersistedModelProfile:
        if (
            not isinstance(profile, SimulationContractValue)
            or profile.schema_id != ARTIFACT_SCHEMA_ID
            or profile.value.get("artifact_type") != "simulation_model_profile"
        ):
            _reject("model_profile_contract_required")
        if not isinstance(algorithm_id, str) or not algorithm_id:
            _reject("calibration_algorithm_invalid")
        if prior_model_profile_id is not None:
            _require_hash(prior_model_profile_id, "prior_model_profile_invalid")
            if prior_model_profile_id == profile.identity:
                _reject("calibration_model_identity_unchanged")
        return PersistedModelProfile(
            model_profile_id=profile.identity,
            family=str(profile.value["family"]),
            prior_model_profile_id=prior_model_profile_id,
            model_version=str(profile.value["model_version"]),
            algorithm_id=algorithm_id,
            canonical_sha256=profile.canonical_sha256,
            canonical_bytes=profile.canonical_bytes,
        )

    def _insert_model_profile(self, profile: PersistedModelProfile) -> None:
        self.__execute(
            "INSERT INTO simulation_model_profiles VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                profile.model_profile_id,
                profile.family,
                profile.prior_model_profile_id,
                profile.model_version,
                profile.algorithm_id,
                profile.canonical_sha256,
                profile.canonical_bytes,
            ),
        )

    def persist_calibration_descendant(
        self,
        *,
        prior_profile: SimulationContractValue,
        output_profile: SimulationContractValue,
        calibration: SimulationContractValue,
    ) -> tuple[PersistedModelProfile, PersistedCalibration]:
        if (
            not isinstance(calibration, SimulationContractValue)
            or calibration.schema_id != ARTIFACT_SCHEMA_ID
            or calibration.value.get("artifact_type") != "simulation_calibration"
        ):
            _reject("calibration_contract_required")
        value = calibration.value
        if (
            value.get("prior_model_profile_id") != prior_profile.identity
            or value.get("output_model_profile_id") != output_profile.identity
            or value.get("training_eligible") is not False
            or value.get("readiness_eligible") is not False
            or value.get("promotion_eligible") is not False
        ):
            _reject("calibration_contract_mismatch")
        if self.__execute(
            "SELECT 1 FROM simulation_model_profiles WHERE model_profile_id=?",
            (prior_profile.identity,),
        ).fetchone() is None:
            _reject("prior_model_profile_missing")
        algorithm_id = str(value["algorithm_id"])
        output = self._model_profile_record(
            output_profile,
            prior_model_profile_id=prior_profile.identity,
            algorithm_id=algorithm_id,
        )
        observations = tuple(str(item) for item in value["observation_ids"])
        exclusions = tuple(str(item) for item in value["rights_exclusion_ids"])
        persisted = PersistedCalibration(
            calibration_id=calibration.identity,
            manifest_id=str(value["manifest_id"]),
            prior_model_profile_id=prior_profile.identity,
            output_model_profile_id=output_profile.identity,
            evaluation_request_id=str(value["evaluation_request_id"]),
            algorithm_id=algorithm_id,
            canonical_sha256=calibration.canonical_sha256,
            canonical_bytes=calibration.canonical_bytes,
        )
        upstream_before = self.upstream_table_snapshot()
        prior_before = self.fetch_model_profile(prior_profile.identity)
        self.__execute("BEGIN IMMEDIATE")
        try:
            self._insert_model_profile(output)
            self.__execute(
                "INSERT INTO simulation_calibrations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    persisted.calibration_id,
                    persisted.manifest_id,
                    persisted.prior_model_profile_id,
                    persisted.output_model_profile_id,
                    persisted.evaluation_request_id,
                    _framed_digest(
                        "SKELETON_PHASE09_CALIBRATION_OBSERVATION_INVENTORY_V1",
                        canonicalize(list(observations)),
                    ),
                    _framed_digest(
                        "SKELETON_PHASE09_CALIBRATION_EXCLUSION_INVENTORY_V1",
                        canonicalize(list(exclusions)),
                    ),
                    persisted.algorithm_id,
                    str(value["code_sha256"]),
                    str(value["parameter_delta_sha256"]),
                    str(value["diagnostics_sha256"]),
                    persisted.canonical_sha256,
                    persisted.canonical_bytes,
                ),
            )
            if self.upstream_table_snapshot() != upstream_before:
                _reject("upstream_mutation_detected")
            if self.fetch_model_profile(prior_profile.identity) != prior_before:
                _reject("prior_model_profile_mutated")
            self.__commit()
        except BaseException as error:
            self.__rollback()
            if isinstance(error, SimulationStoreRejection):
                raise
            raise SimulationStoreRejection("calibration_persist_failed") from error
        return output, persisted

    def fetch_model_profile(self, model_profile_id: str) -> PersistedModelProfile:
        identity = _require_hash(model_profile_id, "model_profile_identity_invalid")
        row = self.__execute(
            "SELECT family, prior_model_profile_id, model_version, algorithm_id, canonical_sha256, canonical_profile "
            "FROM simulation_model_profiles WHERE model_profile_id=?",
            (identity,),
        ).fetchone()
        if row is None:
            _reject("model_profile_missing")
        raw = bytes(row[5])
        if sha256_hex(raw) != str(row[4]):
            _reject("stored_object_hash_mismatch")
        return PersistedModelProfile(
            model_profile_id=identity,
            family=str(row[0]),
            prior_model_profile_id=None if row[1] is None else str(row[1]),
            model_version=str(row[2]),
            algorithm_id=str(row[3]),
            canonical_sha256=str(row[4]),
            canonical_bytes=raw,
        )

    def fetch_calibration(self, calibration_id: str) -> PersistedCalibration:
        identity = _require_hash(calibration_id, "calibration_identity_invalid")
        row = self.__execute(
            "SELECT manifest_id, prior_model_profile_id, output_model_profile_id, "
            "evaluation_request_id, algorithm_id, canonical_sha256, canonical_calibration "
            "FROM simulation_calibrations WHERE calibration_id=?",
            (identity,),
        ).fetchone()
        if row is None:
            _reject("calibration_missing")
        raw = bytes(row[6])
        if sha256_hex(raw) != str(row[5]):
            _reject("stored_object_hash_mismatch")
        return PersistedCalibration(
            calibration_id=identity,
            manifest_id=str(row[0]),
            prior_model_profile_id=str(row[1]),
            output_model_profile_id=str(row[2]),
            evaluation_request_id=str(row[3]),
            algorithm_id=str(row[4]),
            canonical_sha256=str(row[5]),
            canonical_bytes=raw,
        )

    def persist_complete_run(
        self,
        trace: SimulationTrace,
        *,
        report: object,
    ) -> PersistedSimulationRun:
        persisted = self._build_complete_run(trace, report=report)
        upstream_before = self.upstream_table_snapshot()
        if self.__in_transaction():
            _reject("nested_transaction")
        self.__execute("BEGIN IMMEDIATE")
        try:
            self._insert_complete_run(persisted)
            upstream_after = self.upstream_table_snapshot()
            if upstream_before != upstream_after:
                _reject("upstream_mutation_detected")
            self.__commit()
        except BaseException as error:
            self.__rollback()
            if isinstance(error, SimulationStoreRejection):
                raise
            raise SimulationStoreRejection("simulation_run_persist_failed") from error
        return persisted

    def _build_complete_run(
        self,
        trace: SimulationTrace,
        *,
        report: object,
    ) -> PersistedSimulationRun:
        if self._closed:
            _reject("simulation_store_closed")
        self._validate_trace(trace)
        validated_report, terminal_status = self._validate_report(trace, report)
        run_body = canonicalize(
            {
                "manifest_id": trace.manifest_id,
                "report_id": validated_report.report_id,
                "terminal_status": terminal_status,
                "trace_root": trace.trace_root,
                "trace_sha256": sha256_hex(trace.canonical_bytes),
                "transition_ids": [item.transition_id for item in trace.transitions],
            }
        )
        run_id = self.run_identity(run_body)
        run_value = _plain_json(run_body, "run_identity_invalid")
        run_value["run_id"] = run_id
        run_raw = canonicalize(run_value)
        persisted_report = PersistedSimulationReport(
            report_id=validated_report.report_id,
            run_id=run_id,
            trace_root=trace.trace_root,
            canonical_sha256=sha256_hex(validated_report.canonical_bytes),
            canonical_bytes=validated_report.canonical_bytes,
        )
        return PersistedSimulationRun(
            run_id=run_id,
            manifest_id=trace.manifest_id,
            trace_root=trace.trace_root,
            terminal_status=terminal_status,
            canonical_sha256=sha256_hex(run_raw),
            canonical_bytes=run_raw,
            transitions=trace.transitions,
            report=persisted_report,
        )

    def persist_correction(
        self,
        trace: SimulationTrace,
        *,
        report: object,
        parent_run_id: str,
        changed_input_ids: tuple[str, ...],
    ) -> PersistedSimulationRun:
        """Append one complete corrected child and ancestry edge atomically."""

        parent_id = _require_hash(parent_run_id, "correction_parent_invalid")
        if (
            not isinstance(changed_input_ids, tuple)
            or not changed_input_ids
            or changed_input_ids != tuple(sorted(changed_input_ids))
            or len(set(changed_input_ids)) != len(changed_input_ids)
        ):
            _reject("correction_changed_inputs_invalid")
        for item in changed_input_ids:
            _require_hash(item, "correction_changed_inputs_invalid")
        child = self._build_complete_run(trace, report=report)
        if child.run_id == parent_id:
            _reject("correction_self_edge")
        parent_row = self.__execute(
            "SELECT r.run_id, p.report_id FROM simulation_runs r "
            "JOIN simulation_reports p ON p.run_id=r.run_id WHERE r.run_id=?",
            (parent_id,),
        ).fetchone()
        if parent_row is None:
            _reject("correction_parent_missing")
        if self._would_create_cycle(child.run_id, parent_id):
            _reject("correction_cycle")
        if self.__execute(
            "SELECT 1 FROM simulation_runs WHERE run_id=?", (child.run_id,)
        ).fetchone() is not None:
            _reject("correction_child_duplicate")
        inventory_raw = canonicalize(list(changed_input_ids))
        ancestry_value = {
            "child_run_id": child.run_id,
            "changed_input_ids": list(changed_input_ids),
            "parent_run_id": parent_id,
            "superseded_report_id": str(parent_row[1]),
        }
        ancestry_raw = canonicalize(ancestry_value)
        ancestry = PersistedRunAncestry(
            child_run_id=child.run_id,
            parent_run_id=parent_id,
            changed_input_ids=changed_input_ids,
            superseded_report_id=str(parent_row[1]),
            canonical_sha256=_framed_digest(_ANCESTRY_DOMAIN, ancestry_raw),
            canonical_bytes=ancestry_raw,
        )
        upstream_before = self.upstream_table_snapshot()
        parent_before = self.fetch_complete_run(parent_id)
        if self.__in_transaction():
            _reject("nested_transaction")
        self.__execute("BEGIN IMMEDIATE")
        try:
            self._insert_complete_run(child)
            self.__execute(
                "INSERT INTO simulation_run_ancestry VALUES (?, ?, ?, ?, ?, ?)",
                (
                    ancestry.child_run_id,
                    ancestry.parent_run_id,
                    _framed_digest(_CHANGED_INPUT_DOMAIN, inventory_raw),
                    ancestry.superseded_report_id,
                    ancestry.canonical_sha256,
                    ancestry.canonical_bytes,
                ),
            )
            if self.upstream_table_snapshot() != upstream_before:
                _reject("upstream_mutation_detected")
            if self.fetch_complete_run(parent_id) != parent_before:
                _reject("correction_predecessor_mutated")
            self.__commit()
        except BaseException as error:
            self.__rollback()
            if isinstance(error, SimulationStoreRejection):
                raise
            raise SimulationStoreRejection("correction_persist_failed") from error
        return child

    def _would_create_cycle(self, child_run_id: str, parent_run_id: str) -> bool:
        row = self.__execute(
            "WITH RECURSIVE chain(run_id) AS ("
            "SELECT ? UNION "
            "SELECT a.parent_run_id FROM simulation_run_ancestry a "
            "JOIN chain c ON a.child_run_id=c.run_id"
            ") SELECT 1 FROM chain WHERE run_id=? LIMIT 1",
            (parent_run_id, child_run_id),
        ).fetchone()
        return row is not None

    def fetch_ancestry(self, child_run_id: str) -> PersistedRunAncestry:
        child_id = _require_hash(child_run_id, "correction_child_invalid")
        row = self.__execute(
            "SELECT parent_run_id, superseded_report_id, canonical_sha256, canonical_ancestry "
            "FROM simulation_run_ancestry WHERE child_run_id=?",
            (child_id,),
        ).fetchone()
        if row is None:
            _reject("correction_ancestry_missing")
        raw = bytes(row[3])
        value = _plain_json(raw, "correction_ancestry_invalid")
        observed = PersistedRunAncestry(
            child_run_id=child_id,
            parent_run_id=str(row[0]),
            changed_input_ids=tuple(str(item) for item in value["changed_input_ids"]),
            superseded_report_id=str(row[1]),
            canonical_sha256=str(row[2]),
            canonical_bytes=raw,
        )
        if (
            value.get("child_run_id") != child_id
            or value.get("parent_run_id") != observed.parent_run_id
            or value.get("superseded_report_id") != observed.superseded_report_id
            or _framed_digest(_ANCESTRY_DOMAIN, raw) != observed.canonical_sha256
        ):
            _reject("correction_ancestry_invalid")
        return observed

    def _insert_complete_run(self, run: PersistedSimulationRun) -> None:
        self.__execute(
            "INSERT INTO simulation_runs VALUES (?, ?, ?, ?, ?, ?)",
            (
                run.run_id,
                run.manifest_id,
                run.trace_root,
                run.terminal_status,
                run.canonical_sha256,
                run.canonical_bytes,
            ),
        )
        for item in run.transitions:
            self.__execute(
                "INSERT INTO simulation_transitions VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    item.transition_id,
                    run.run_id,
                    item.ordinal,
                    item.event_id,
                    item.prior_transition_id,
                    sha256_hex(item.canonical_bytes),
                    item.canonical_bytes,
                ),
            )
        self.__execute(
            "INSERT INTO simulation_reports VALUES (?, ?, ?, ?, ?)",
            (
                run.report.report_id,
                run.run_id,
                run.trace_root,
                run.report.canonical_sha256,
                run.report.canonical_bytes,
            ),
        )

    def _validate_trace(self, trace: SimulationTrace) -> None:
        if not isinstance(trace, SimulationTrace):
            raise TypeError("SimulationTrace required")
        _require_hash(trace.manifest_id, "manifest_identity_invalid")
        if trace.upstream_pre_sha256 != trace.upstream_post_sha256:
            _reject("upstream_mutation_detected")
        trace_value = _plain_json(trace.canonical_bytes, "trace_bytes_invalid")
        if self.trace_identity(trace.canonical_bytes) != trace.trace_root:
            _reject("trace_identity_mismatch")
        if trace_value.get("manifest_id") != trace.manifest_id:
            _reject("trace_manifest_mismatch")
        if trace_value.get("transition_ids") != [
            item.transition_id for item in trace.transitions
        ]:
            _reject("trace_transition_inventory_mismatch")
        if trace.transition_count != len(trace.transitions) or not trace.transitions:
            _reject("trace_transition_inventory_invalid")
        prior: str | None = None
        for ordinal, item in enumerate(trace.transitions):
            value = _plain_json(item.canonical_bytes, "transition_bytes_invalid")
            if (
                item.ordinal != ordinal
                or item.prior_transition_id != prior
                or value.get("ordinal") != ordinal
                or value.get("prior_transition_id") != prior
                or value.get("event_id") != item.event_id
                or self.transition_identity(item.canonical_bytes) != item.transition_id
            ):
                _reject("transition_chain_invalid")
            prior = item.transition_id

    def _validate_report(
        self, trace: SimulationTrace, report: object
    ) -> tuple[object, str]:
        # Imported lazily to keep the reporting/store dependency one-way while
        # still requiring the reporter-owned sealed runtime type.
        from .simulation_reporting import SimulationReport

        if not isinstance(report, SimulationReport):
            raise TypeError("authenticated SimulationReport required")
        validated = self._publication.validate_contract(
            report.canonical_bytes, REPORT_SCHEMA_ID
        )
        if (
            validated.identity != report.report_id
            or validated.canonical_bytes != report.canonical_bytes
            or report.trace is not trace
            or report.resolved.manifest_id != trace.manifest_id
            or report.resolved.candidate_inputs != trace.candidate_inputs
            or report.resolved.admitted_inputs != trace.admitted_inputs
            or report.resolved.rights_excluded_inputs
            != trace.rights_excluded_inputs
        ):
            _reject("simulation_report_trace_mismatch")
        value = validated.value
        status = str(value.get("status", ""))
        if status not in _TERMINAL_STATES:
            _reject("terminal_status_invalid")
        if (
            value.get("manifest_id") != trace.manifest_id
            or value.get("trace_root") != trace.trace_root
            or tuple(value.get("candidate_inputs", ())) != trace.candidate_inputs
            or tuple(value.get("admitted_inputs", ())) != trace.admitted_inputs
            or tuple(value.get("rights_excluded_inputs", ()))
            != trace.rights_excluded_inputs
        ):
            _reject("simulation_report_trace_mismatch")
        results = report.family_results
        if (
            len(results) != len(trace.transitions)
            or {item.event_id for item in results}
            != {item.event_id for item in trace.transitions}
        ):
            _reject("simulation_report_family_inventory_mismatch")
        transitions = {item.event_id: item for item in trace.transitions}
        expected_events = tuple(
            sorted(item.artifact_id for item in report.resolved.events)
        )
        expected_fills = tuple(
            sorted(
                transitions[item.event_id].fill_hashes[0]
                for item in results
                if item.filled_quantity > 0
            )
        )
        expected_costs = tuple(
            sorted(
                {cost.canonical_sha256 for item in results for cost in item.costs}
            )
        )
        expected_settlements = tuple(
            sorted(
                {
                evidence_id
                for item in results
                for evidence_id in item.settlement_evidence_ids
                }
            )
        )
        expected_labels = tuple(
            sorted(
                transitions[item.event_id].label_hash
                for item in results
                if item.successful is True
            )
        )
        if (
            tuple(value.get("events", ())) != expected_events
            or tuple(value.get("fills", ())) != expected_fills
            or tuple(value.get("costs", ())) != expected_costs
            or tuple(value.get("settlements", ())) != expected_settlements
            or tuple(value.get("success_labels", ())) != expected_labels
        ):
            _reject("simulation_report_economic_inventory_mismatch")
        return report, status

    def fetch_complete_run(self, run_id: str) -> PersistedSimulationRun:
        _require_hash(run_id, "run_identity_invalid")
        row = self.__execute(
            "SELECT manifest_id, trace_root, terminal_status, canonical_sha256, canonical_run "
            "FROM simulation_runs WHERE run_id=?",
            (run_id,),
        ).fetchone()
        if row is None:
            _reject("simulation_run_missing")
        transition_rows = self.__execute(
            "SELECT transition_id, ordinal, event_id, prior_transition_id, canonical_sha256, canonical_transition "
            "FROM simulation_transitions WHERE run_id=? ORDER BY ordinal",
            (run_id,),
        ).fetchall()
        transitions = tuple(self._restore_transition(item) for item in transition_rows)
        report_row = self.__execute(
            "SELECT report_id, trace_root, canonical_sha256, canonical_report "
            "FROM simulation_reports WHERE run_id=?",
            (run_id,),
        ).fetchone()
        if report_row is None:
            _reject("simulation_report_missing")
        report = PersistedSimulationReport(
            report_id=str(report_row[0]),
            run_id=run_id,
            trace_root=str(report_row[1]),
            canonical_sha256=str(report_row[2]),
            canonical_bytes=bytes(report_row[3]),
        )
        observed = PersistedSimulationRun(
            run_id=run_id,
            manifest_id=str(row[0]),
            trace_root=str(row[1]),
            terminal_status=str(row[2]),
            canonical_sha256=str(row[3]),
            canonical_bytes=bytes(row[4]),
            transitions=transitions,
            report=report,
        )
        if (
            sha256_hex(observed.canonical_bytes) != observed.canonical_sha256
            or sha256_hex(report.canonical_bytes) != report.canonical_sha256
        ):
            _reject("stored_object_hash_mismatch")
        self._validate_stored_run_identity(observed)
        return observed

    def _validate_stored_run_identity(self, run: PersistedSimulationRun) -> None:
        run_value = _plain_json(run.canonical_bytes, "run_bytes_invalid")
        if run_value.pop("run_id", None) != run.run_id:
            _reject("run_identity_mismatch")
        if self.run_identity(canonicalize(run_value)) != run.run_id:
            _reject("run_identity_mismatch")
        report_value = _plain_json(run.report.canonical_bytes, "report_bytes_invalid")
        if (
            report_value.get("report_id") != run.report.report_id
            or report_value.get("trace_root") != run.trace_root
        ):
            _reject("report_identity_mismatch")
        validated = self._publication.validate_contract(
            run.report.canonical_bytes, REPORT_SCHEMA_ID
        )
        if validated.identity != run.report.report_id:
            _reject("report_identity_mismatch")

    def _restore_transition(self, row: tuple[object, ...]) -> SimulationTransition:
        raw = bytes(row[5])
        value = _plain_json(raw, "transition_bytes_invalid")
        transition_id = str(row[0])
        if self.transition_identity(raw) != transition_id or sha256_hex(raw) != row[4]:
            _reject("stored_object_hash_mismatch")
        return SimulationTransition(
            transition_id=transition_id,
            ordinal=int(value["ordinal"]),
            event_id=str(value["event_id"]),
            prior_transition_id=(
                None
                if value["prior_transition_id"] is None
                else str(value["prior_transition_id"])
            ),
            simulated_at=str(value["simulated_at"]),
            pre_state_hash=str(value["pre_state_hash"]),
            decision_hash=str(value["decision_hash"]),
            fill_hashes=tuple(str(item) for item in value["fill_hashes"]),
            cost_hashes=tuple(str(item) for item in value["cost_hashes"]),
            label_hash=str(value["label_hash"]),
            post_state_hash=str(value["post_state_hash"]),
            draw_ids=tuple(str(item) for item in value["draw_ids"]),
            model_profile_id=str(value["model_profile_id"]),
            engine_version=str(value["engine_version"]),
            ordering_policy_version=str(value["ordering_policy_version"]),
            canonical_bytes=raw,
        )


__all__ = [
    "PersistedCalibration",
    "PersistedModelProfile",
    "PersistedRunAncestry",
    "PersistedSimulationReport",
    "PersistedSimulationRun",
    "SimulationStore",
    "SimulationStoreRejection",
]
