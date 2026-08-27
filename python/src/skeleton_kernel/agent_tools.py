"""Closed deterministic local tools and the always-denied Phase 11 egress port."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
import errno
from hashlib import sha256
import os
from pathlib import Path
from queue import Empty, Queue
import stat
import threading
from time import monotonic_ns
from typing import Any

from .agent_budgets import BudgetAccount, BudgetReservation, BudgetVector
from .agent_safety import AgentBoundary, AgentSafetyScanner
from .agent_store import AgentStore, IncidentAppend, ToolReceiptAppend, ZERO_SHA256
from .agent_types import SAFE_INTEGER_MAX
from .canonical import canonicalize, parse_raw_json


_ALLOWLIST_DOMAIN = b"SKELETON_PHASE11_TOOL_ALLOWLIST_V1"
_ENTRY_DOMAIN = b"SKELETON_PHASE11_TOOL_ALLOWLIST_ENTRY_V1"
_RECEIPT_DOMAIN = b"SKELETON_PHASE11_AGENT_TOOL_RECEIPT_V1"
_EGRESS_RECEIPT_DOMAIN = b"SKELETON_PHASE11_RESEARCH_EGRESS_DENIAL_V1"
_INCIDENT_DOMAIN = b"SKELETON_PHASE11_EGRESS_INCIDENT_V1"
_OPERATION_DOMAIN = b"SKELETON_PHASE11_TOOL_OPERATION_V1"
_CLASSIFICATIONS = frozenset({"public", "internal", "confidential", "restricted"})
_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _relative_parts(relative: str) -> tuple[str, ...]:
    normalized = relative.replace("\\", "/")
    parts = tuple(normalized.split("/"))
    if (
        not parts
        or any(part in {"", ".", ".."} for part in parts)
        or (os.name == "nt" and any(":" in part for part in parts))
    ):
        _reject("tool_filesystem_scope_denied")
    return parts


if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    _FILE_READ_DATA = 0x0001
    _FILE_READ_ATTRIBUTES = 0x0080
    _SYNCHRONIZE = 0x00100000
    _FILE_SHARE_ALL = 0x00000007
    _FILE_OPEN = 0x00000001
    _FILE_DIRECTORY_FILE = 0x00000001
    _FILE_NON_DIRECTORY_FILE = 0x00000040
    _FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
    _FILE_OPEN_REPARSE_POINT = 0x00200000
    _OBJ_CASE_INSENSITIVE = 0x00000040
    _DUPLICATE_SAME_ACCESS = 0x00000002
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    class _UnicodeString(ctypes.Structure):
        _fields_ = (
            ("Length", wintypes.USHORT),
            ("MaximumLength", wintypes.USHORT),
            ("Buffer", wintypes.LPWSTR),
        )

    class _ObjectAttributes(ctypes.Structure):
        _fields_ = (
            ("Length", wintypes.ULONG),
            ("RootDirectory", wintypes.HANDLE),
            ("ObjectName", ctypes.POINTER(_UnicodeString)),
            ("Attributes", wintypes.ULONG),
            ("SecurityDescriptor", wintypes.LPVOID),
            ("SecurityQualityOfService", wintypes.LPVOID),
        )

    class _IoStatusBlock(ctypes.Structure):
        _fields_ = (("Status", ctypes.c_void_p), ("Information", ctypes.c_size_t))

    class _ByHandleFileInformation(ctypes.Structure):
        _fields_ = (
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        )

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _ntdll = ctypes.WinDLL("ntdll")
    _kernel32.CreateFileW.restype = wintypes.HANDLE
    _kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    _kernel32.DuplicateHandle.argtypes = (
        wintypes.HANDLE,
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    )
    _kernel32.DuplicateHandle.restype = wintypes.BOOL
    _ntdll.NtCreateFile.restype = ctypes.c_long

    def _windows_attributes(handle: int) -> int:
        information = _ByHandleFileInformation()
        if not _kernel32.GetFileInformationByHandle(
            wintypes.HANDLE(handle), ctypes.byref(information)
        ):
            raise OSError(ctypes.get_last_error(), "GetFileInformationByHandle")
        return int(information.dwFileAttributes)

    def _open_root_handle(root: Path) -> int:
        handle = _kernel32.CreateFileW(
            str(root),
            _FILE_READ_ATTRIBUTES | _SYNCHRONIZE,
            _FILE_SHARE_ALL,
            None,
            3,
            0x02000000 | _FILE_OPEN_REPARSE_POINT,
            None,
        )
        value = ctypes.cast(handle, ctypes.c_void_p).value
        if value == _INVALID_HANDLE_VALUE or value is None:
            raise OSError(ctypes.get_last_error(), "CreateFileW")
        attributes = _windows_attributes(value)
        if attributes & _REPARSE_ATTRIBUTE or not attributes & 0x10:
            _kernel32.CloseHandle(wintypes.HANDLE(value))
            _reject("tool_contained_root_invalid")
        return value

    def _nt_open_component(parent: int, name: str, *, directory: bool) -> int:
        buffer = ctypes.create_unicode_buffer(name)
        name_value = _UnicodeString(
            len(name.encode("utf-16-le")),
            len(name.encode("utf-16-le")) + 2,
            ctypes.cast(buffer, wintypes.LPWSTR),
        )
        attributes = _ObjectAttributes(
            ctypes.sizeof(_ObjectAttributes),
            wintypes.HANDLE(parent),
            ctypes.pointer(name_value),
            _OBJ_CASE_INSENSITIVE,
            None,
            None,
        )
        io_status = _IoStatusBlock()
        result = wintypes.HANDLE()
        options = (
            _FILE_OPEN_REPARSE_POINT
            | _FILE_SYNCHRONOUS_IO_NONALERT
            | (_FILE_DIRECTORY_FILE if directory else _FILE_NON_DIRECTORY_FILE)
        )
        status = _ntdll.NtCreateFile(
            ctypes.byref(result),
            _FILE_READ_DATA | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE,
            ctypes.byref(attributes),
            ctypes.byref(io_status),
            None,
            0,
            _FILE_SHARE_ALL,
            _FILE_OPEN,
            options,
            None,
            0,
        )
        if status < 0:
            raise OSError(f"NtCreateFile failed: 0x{status & 0xffffffff:08x}")
        value = ctypes.cast(result, ctypes.c_void_p).value
        if value is None:
            raise OSError("NtCreateFile returned no handle")
        return value

    def _read_from_root(root_handle: int, parts: tuple[str, ...]) -> bytes:
        current = root_handle
        owned = False
        try:
            for index, part in enumerate(parts):
                following = _nt_open_component(
                    current, part, directory=index < len(parts) - 1
                )
                if owned:
                    _kernel32.CloseHandle(wintypes.HANDLE(current))
                current = following
                owned = True
                attributes = _windows_attributes(current)
                if attributes & _REPARSE_ATTRIBUTE:
                    _reject("tool_filesystem_scope_denied")
            chunks: list[bytes] = []
            while True:
                buffer = ctypes.create_string_buffer(64 * 1024)
                read = wintypes.DWORD()
                if not _kernel32.ReadFile(
                    wintypes.HANDLE(current),
                    buffer,
                    len(buffer),
                    ctypes.byref(read),
                    None,
                ):
                    error = ctypes.get_last_error()
                    if error == 38:
                        break
                    raise OSError(error, "ReadFile")
                if read.value == 0:
                    break
                chunks.append(buffer.raw[: read.value])
            return b"".join(chunks)
        finally:
            if owned:
                _kernel32.CloseHandle(wintypes.HANDLE(current))

    def _close_root_handle(handle: int) -> None:
        _kernel32.CloseHandle(wintypes.HANDLE(handle))

    def _duplicate_root_handle(handle: int) -> int:
        process = _kernel32.GetCurrentProcess()
        duplicate = wintypes.HANDLE()
        if not _kernel32.DuplicateHandle(
            process,
            wintypes.HANDLE(handle),
            process,
            ctypes.byref(duplicate),
            0,
            False,
            _DUPLICATE_SAME_ACCESS,
        ):
            raise OSError(ctypes.get_last_error(), "DuplicateHandle")
        value = ctypes.cast(duplicate, ctypes.c_void_p).value
        if value is None:
            raise OSError("DuplicateHandle returned no handle")
        return value

else:
    def _open_root_handle(root: Path) -> int:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(root, flags)
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            _reject("tool_contained_root_invalid")
        return descriptor

    def _read_from_root(root_handle: int, parts: tuple[str, ...]) -> bytes:
        current = os.dup(root_handle)
        try:
            for index, part in enumerate(parts):
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                if index < len(parts) - 1:
                    flags |= getattr(os, "O_DIRECTORY", 0)
                else:
                    # A hostile in-root actor can plant a FIFO at the leaf; a
                    # blocking open would wedge the dispatcher under its lock.
                    # O_NONBLOCK makes the open return immediately and is a
                    # no-op for regular-file reads; fstat below rejects the
                    # FIFO before any bytes are read.
                    flags |= getattr(os, "O_NONBLOCK", 0)
                try:
                    following = os.open(part, flags, dir_fd=current)
                except OSError as error:
                    # O_NOFOLLOW surfaces a symlink component as ELOOP (or
                    # ENOTDIR for a non-directory component); both are scope
                    # violations of the contained root, not dispatcher faults.
                    if error.errno in (errno.ELOOP, errno.ENOTDIR):
                        _reject("tool_filesystem_scope_denied")
                    raise
                os.close(current)
                current = following
            if not stat.S_ISREG(os.fstat(current).st_mode):
                _reject("tool_filesystem_scope_denied")
            chunks: list[bytes] = []
            while chunk := os.read(current, 64 * 1024):
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(current)

    def _close_root_handle(handle: int) -> None:
        os.close(handle)

    def _duplicate_root_handle(handle: int) -> int:
        return os.dup(handle)


class LocalToolOperation(StrEnum):
    CANONICAL_METADATA_READ = "canonical_metadata_read"
    DETERMINISTIC_FIXTURE_LOOKUP = "deterministic_fixture_lookup"
    SEALED_ARTIFACT_READ = "sealed_artifact_read"


class ToolDisposition(StrEnum):
    ALLOWED = "allowed"
    DENIED = "denied"


class ToolDenialReason(StrEnum):
    NONE = "none"
    UNKNOWN_OPERATION = "unknown_operation"
    NOT_ALLOWLISTED = "not_allowlisted"
    ARGUMENT_SCHEMA_INVALID = "argument_schema_invalid"
    CLASSIFICATION_DENIED = "classification_denied"
    FILESYSTEM_SCOPE_DENIED = "filesystem_scope_denied"
    EGRESS_DENIED = "egress_denied"
    BUDGET_EXHAUSTED = "budget_exhausted"
    TIMEOUT = "timeout"
    DISPATCHER_ERROR = "dispatcher_error"


@dataclass(slots=True)
class AgentToolRejection(ValueError):
    code: str

    def __str__(self) -> str:
        return self.code


def _reject(code: str) -> None:
    raise AgentToolRejection(code)


def _identity(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _reject(code)
    return value


def _safe_counter(value: object, code: str, *, positive: bool = False) -> int:
    if type(value) is not int or not 0 <= value <= SAFE_INTEGER_MAX or (positive and value == 0):
        _reject(code)
    return value


def _digest(domain: bytes, value: object) -> str:
    raw = canonicalize(value)
    return sha256(
        len(domain).to_bytes(8, "big")
        + domain
        + len(raw).to_bytes(8, "big")
        + raw
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class ToolAllowlistEntry:
    allowlist_entry_id: str
    operation: LocalToolOperation
    argument_schema_root: str
    result_schema_root: str
    data_classification: str
    filesystem_scope: str
    egress_class: str
    timeout_ms: int
    maximum_calls: int

    def __post_init__(self) -> None:
        _identity(self.allowlist_entry_id, "tool_entry_identity_invalid")
        _identity(self.argument_schema_root, "tool_argument_schema_invalid")
        _identity(self.result_schema_root, "tool_result_schema_invalid")
        if (
            not isinstance(self.operation, LocalToolOperation)
            or self.data_classification not in _CLASSIFICATIONS
            or self.filesystem_scope != "contained_read"
            or self.egress_class != "none"
        ):
            _reject("tool_allowlist_entry_invalid")
        _safe_counter(self.timeout_ms, "tool_timeout_invalid", positive=True)
        _safe_counter(self.maximum_calls, "tool_maximum_calls_invalid", positive=True)

    def material(self) -> dict[str, object]:
        return {
            "allowlist_entry_id": self.allowlist_entry_id,
            "argument_schema_root": self.argument_schema_root,
            "data_classification": self.data_classification,
            "egress_class": self.egress_class,
            "filesystem_scope": self.filesystem_scope,
            "maximum_calls": self.maximum_calls,
            "operation": self.operation.value,
            "result_schema_root": self.result_schema_root,
            "timeout_ms": self.timeout_ms,
        }


def tool_allowlist_entry(
    operation: LocalToolOperation,
    *,
    argument_schema_root: str,
    result_schema_root: str,
    data_classification: str,
    timeout_ms: int,
    maximum_calls: int,
) -> ToolAllowlistEntry:
    material = {
        "argument_schema_root": _identity(argument_schema_root, "tool_argument_schema_invalid"),
        "data_classification": data_classification,
        "egress_class": "none",
        "filesystem_scope": "contained_read",
        "maximum_calls": maximum_calls,
        "operation": operation.value if isinstance(operation, LocalToolOperation) else operation,
        "result_schema_root": _identity(result_schema_root, "tool_result_schema_invalid"),
        "timeout_ms": timeout_ms,
    }
    return ToolAllowlistEntry(
        _digest(_ENTRY_DOMAIN, material),
        operation,
        argument_schema_root,
        result_schema_root,
        data_classification,
        "contained_read",
        "none",
        timeout_ms,
        maximum_calls,
    )


@dataclass(frozen=True, slots=True)
class ToolRequest:
    request_id: str
    invocation_id: str
    attempt_ordinal: int
    operation: LocalToolOperation
    allowlist_root: str
    allowlist_entry_id: str
    argument_schema_root: str
    result_schema_root: str
    data_classification: str
    filesystem_scope: str
    egress_class: str
    timeout_ms: int
    maximum_calls: int
    argument_bytes: bytes
    recorded_at: str

    def __post_init__(self) -> None:
        _identity(self.request_id, "tool_request_identity_invalid")
        _identity(self.invocation_id, "tool_invocation_identity_invalid")
        _safe_counter(self.attempt_ordinal, "tool_attempt_invalid")
        if not isinstance(self.operation, LocalToolOperation):
            _reject("tool_operation_invalid")
        for value in (
            self.allowlist_root,
            self.allowlist_entry_id,
            self.argument_schema_root,
            self.result_schema_root,
        ):
            _identity(value, "tool_request_binding_invalid")
        _safe_counter(self.timeout_ms, "tool_timeout_invalid", positive=True)
        _safe_counter(self.maximum_calls, "tool_maximum_calls_invalid", positive=True)
        if not isinstance(self.argument_bytes, bytes) or not self.recorded_at.endswith("Z"):
            _reject("tool_request_invalid")


@dataclass(frozen=True, slots=True)
class AgentToolReceipt:
    tool_receipt_id: str
    invocation_id: str
    attempt_ordinal: int
    allowlist_root: str
    allowlist_entry_id: str
    operation: LocalToolOperation
    argument_root: str
    result_root: str
    disposition: ToolDisposition
    denial_reason: ToolDenialReason
    call_ordinal: int
    call_count: int
    elapsed_milliseconds: int
    external_effect_count: int
    canonical_bytes: bytes


def tool_allowlist_root(entries: tuple[ToolAllowlistEntry, ...]) -> str:
    if len({entry.allowlist_entry_id for entry in entries}) != len(entries):
        _reject("tool_allowlist_duplicate")
    return _digest(_ALLOWLIST_DOMAIN, [entry.material() for entry in sorted(entries, key=lambda item: item.allowlist_entry_id)])


class AgentToolDispatcher:
    """Executes only code-owned contained reads; no caller receives a raw handle."""

    __slots__ = (
        "_account",
        "_allowlist_root",
        "_counts",
        "_entries",
        "_fence_id",
        "_lock",
        "_root",
        "_root_handle",
        "_scanner",
        "_store",
        "_writer_id",
    )

    def __init__(
        self,
        *,
        store: AgentStore,
        budget_account: BudgetAccount,
        contained_root: Path | str,
        writer_id: str,
        fence_id: str,
        entries: tuple[ToolAllowlistEntry, ...] = (),
    ) -> None:
        root = Path(contained_root).resolve(strict=True)
        if not root.is_dir() or root.is_symlink() or (hasattr(os.path, "isjunction") and os.path.isjunction(root)):
            _reject("tool_contained_root_invalid")
        if any(not isinstance(entry, ToolAllowlistEntry) for entry in entries):
            _reject("tool_allowlist_invalid")
        self._store = store
        self._account = budget_account
        self._root = root
        self._root_handle = _open_root_handle(root)
        self._writer_id = _identity(writer_id, "tool_writer_identity_invalid")
        self._fence_id = _identity(fence_id, "tool_fence_identity_invalid")
        self._entries = {entry.allowlist_entry_id: entry for entry in entries}
        self._allowlist_root = tool_allowlist_root(entries)
        self._counts = {entry.allowlist_entry_id: 0 for entry in entries}
        self._scanner = AgentSafetyScanner()
        self._lock = threading.Lock()

    def close(self) -> None:
        handle = self._root_handle
        if handle != -1:
            self._root_handle = -1
            _close_root_handle(handle)

    def __del__(self) -> None:
        handle = getattr(self, "_root_handle", -1)
        if handle != -1:
            try:
                _close_root_handle(handle)
            except OSError:
                pass

    @property
    def allowlist_root(self) -> str:
        return self._allowlist_root

    def dispatch(self, request: ToolRequest) -> AgentToolReceipt:
        if not isinstance(request, ToolRequest):
            _reject("tool_request_invalid")
        with self._lock:
            start = monotonic_ns()
            deadline = start + request.timeout_ms * 1_000_000
            reservation = None
            try:
                reservation = self._account.reserve(
                    BudgetVector(elapsed_milliseconds=request.timeout_ms, tool_calls=1),
                    attempt=request.attempt_ordinal,
                    reservation_key=f"tool:{request.request_id}",
                )
            except ValueError:
                return self._persist_receipt(
                    request,
                    None,
                    ToolDenialReason.BUDGET_EXHAUSTED,
                    elapsed_ms=0,
                    call_ordinal=0,
                )

            assert reservation is not None
            try:
                return self._dispatch_reserved(
                    request,
                    reservation,
                    start=start,
                    deadline=deadline,
                )
            except BaseException:
                try:
                    self._account.mark_uncertain(
                        reservation,
                        uncertainty_key=f"tool-interrupted:{request.request_id}",
                    )
                except BaseException:
                    pass
                raise

    def _dispatch_reserved(
        self,
        request: ToolRequest,
        reservation: BudgetReservation,
        *,
        start: int,
        deadline: int,
    ) -> AgentToolReceipt:
        reason = self._preflight_reason(request)
        result: bytes | None = None
        call_ordinal = 0
        deadline_expired = False
        if reason is ToolDenialReason.NONE:
            entry = self._entries[request.allowlist_entry_id]
            try:
                argument = self._scanner.scan(
                    request.argument_bytes,
                    segment_type="evidence",
                    source_id=request.request_id,
                    purpose="security_conformance",
                    classification=request.data_classification,
                    retention="ephemeral_discard",
                    boundary=AgentBoundary.TOOL_ARGUMENT,
                ).canonical_bytes
                result, execution_error, deadline_expired = self._execute_bounded(
                    entry.operation,
                    argument,
                    request.request_id,
                    deadline_ns=deadline,
                )
                if execution_error is not None:
                    raise execution_error
                if deadline_expired:
                    reason = ToolDenialReason.TIMEOUT
            except AgentToolRejection as error:
                reason = (
                    ToolDenialReason.FILESYSTEM_SCOPE_DENIED
                    if error.code == "tool_filesystem_scope_denied"
                    else ToolDenialReason.ARGUMENT_SCHEMA_INVALID
                )
            except ValueError:
                reason = ToolDenialReason.ARGUMENT_SCHEMA_INVALID
            except OSError:
                reason = ToolDenialReason.DISPATCHER_ERROR
        elapsed_ns = max(0, monotonic_ns() - start)
        elapsed_ms = (elapsed_ns + 999_999) // 1_000_000
        if elapsed_ms > request.timeout_ms:
            result = None
            reason = ToolDenialReason.TIMEOUT
            call_ordinal = 0
            deadline_expired = True
        elif reason is ToolDenialReason.NONE and result is not None:
            self._counts[request.allowlist_entry_id] += 1
            call_ordinal = self._counts[request.allowlist_entry_id]
        receipt, receipt_append = self._build_receipt(
            request,
            result,
            reason,
            elapsed_ms=elapsed_ms,
            call_ordinal=call_ordinal,
        )
        if deadline_expired:
            budget_event = self._account.prepare_uncertain(
                reservation,
                uncertainty_key=f"tool-timeout:{receipt.tool_receipt_id}",
            )
        else:
            budget_event, _reconciliation = self._account.prepare_reconciliation(
                reservation,
                BudgetVector(
                    elapsed_milliseconds=elapsed_ms,
                    tool_calls=receipt.call_count,
                ),
                reconciliation_key=f"tool-receipt:{receipt.tool_receipt_id}",
            )
        self._store.commit_tool_operation(
            tool_receipt=receipt_append,
            budget=budget_event,
            incident=None,
            writer_id=self._writer_id,
            operation_id=_digest(
                _RECEIPT_DOMAIN,
                {"operation": "terminal", "receipt_id": receipt.tool_receipt_id},
            ),
        )
        return receipt

    def _execute_bounded(
        self,
        operation: LocalToolOperation,
        raw: bytes,
        source_id: str,
        *,
        deadline_ns: int,
    ) -> tuple[bytes | None, BaseException | None, bool]:
        root_handle = _duplicate_root_handle(self._root_handle)
        outcome: Queue[tuple[bytes | None, BaseException | None]] = Queue(maxsize=1)

        def work() -> None:
            try:
                outcome.put((self._execute(operation, raw, source_id, root_handle), None))
            except BaseException as error:
                outcome.put((None, error))
            finally:
                _close_root_handle(root_handle)

        remaining_ns = deadline_ns - monotonic_ns()
        if remaining_ns <= 0:
            _close_root_handle(root_handle)
            return None, None, True
        worker = threading.Thread(
            target=work,
            name=f"phase11-tool-{source_id[:12]}",
            daemon=True,
        )
        try:
            worker.start()
        except BaseException:
            _close_root_handle(root_handle)
            raise
        try:
            result, error = outcome.get(timeout=remaining_ns / 1_000_000_000)
        except Empty:
            return None, None, True
        return result, error, False

    def _preflight_reason(self, request: ToolRequest) -> ToolDenialReason:
        operation = request.operation
        entry = self._entries.get(request.allowlist_entry_id)
        if request.allowlist_root != self._allowlist_root or entry is None:
            return ToolDenialReason.NOT_ALLOWLISTED
        if operation is not entry.operation:
            return ToolDenialReason.UNKNOWN_OPERATION
        if request.argument_schema_root != entry.argument_schema_root or request.result_schema_root != entry.result_schema_root:
            return ToolDenialReason.ARGUMENT_SCHEMA_INVALID
        if request.data_classification != entry.data_classification:
            return ToolDenialReason.CLASSIFICATION_DENIED
        if request.filesystem_scope != entry.filesystem_scope:
            return ToolDenialReason.FILESYSTEM_SCOPE_DENIED
        if request.egress_class != "none" or request.egress_class != entry.egress_class:
            return ToolDenialReason.EGRESS_DENIED
        if request.timeout_ms != entry.timeout_ms:
            return ToolDenialReason.TIMEOUT
        if request.maximum_calls != entry.maximum_calls or self._counts[entry.allowlist_entry_id] >= entry.maximum_calls:
            return ToolDenialReason.NOT_ALLOWLISTED
        return ToolDenialReason.NONE

    def _execute(
        self,
        operation: LocalToolOperation,
        raw: bytes,
        source_id: str,
        root_handle: int,
    ) -> bytes:
        value = parse_raw_json(raw)
        if not isinstance(value, Mapping) or canonicalize(value) != raw:
            _reject("tool_argument_schema_invalid")
        relative = value.get("relative_path")
        expected_sha256 = value.get("expected_sha256")
        if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
            _reject("tool_argument_schema_invalid")
        _identity(expected_sha256, "tool_argument_schema_invalid")
        raw_result = _read_from_root(root_handle, _relative_parts(relative))
        if sha256(raw_result).hexdigest() != expected_sha256:
            _reject("tool_artifact_authentication_failed")
        if operation is LocalToolOperation.DETERMINISTIC_FIXTURE_LOOKUP:
            case_id = value.get("case_id")
            if not isinstance(case_id, str) or not case_id:
                _reject("tool_argument_schema_invalid")
            matches = []
            for line in raw_result.splitlines():
                record = parse_raw_json(line)
                if isinstance(record, Mapping) and record.get("case_id") == case_id:
                    matches.append(record)
            if len(matches) != 1:
                _reject("tool_fixture_lookup_invalid")
            raw_result = canonicalize(matches[0])
        elif operation is LocalToolOperation.CANONICAL_METADATA_READ:
            if canonicalize(parse_raw_json(raw_result)) != raw_result:
                _reject("tool_result_schema_invalid")
        return self._scanner.scan(
            raw_result,
            segment_type="tool_result",
            source_id=source_id,
            purpose="local_tool_result",
            classification="internal" if operation is not LocalToolOperation.CANONICAL_METADATA_READ else "internal",
            retention="ephemeral_discard",
            boundary=AgentBoundary.TOOL_RESULT,
        ).canonical_bytes

    def _persist_receipt(
        self,
        request: ToolRequest,
        result: bytes | None,
        reason: ToolDenialReason,
        *,
        elapsed_ms: int,
        call_ordinal: int,
    ) -> AgentToolReceipt:
        receipt, receipt_append = self._build_receipt(
            request,
            result,
            reason,
            elapsed_ms=elapsed_ms,
            call_ordinal=call_ordinal,
        )
        self._store.append_tool_receipt(
            receipt_append,
            writer_id=self._writer_id,
            operation_id=_digest(
                _RECEIPT_DOMAIN,
                {"operation": "append", "receipt_id": receipt.tool_receipt_id},
            ),
        )
        return receipt

    def _build_receipt(
        self,
        request: ToolRequest,
        result: bytes | None,
        reason: ToolDenialReason,
        *,
        elapsed_ms: int,
        call_ordinal: int,
    ) -> tuple[AgentToolReceipt, ToolReceiptAppend]:
        allowed = reason is ToolDenialReason.NONE and result is not None
        disposition = ToolDisposition.ALLOWED if allowed else ToolDisposition.DENIED
        result_root = sha256(result).hexdigest() if allowed else "none"
        argument_root = sha256(request.argument_bytes).hexdigest()
        operation_value = request.operation.value
        value: dict[str, Any] = {
            "allowlist_entry_id": request.allowlist_entry_id,
            "allowlist_root": request.allowlist_root,
            "argument_root": argument_root,
            "argument_schema_root": request.argument_schema_root,
            "attempt": request.attempt_ordinal + 1,
            "call_count": 1 if allowed else 0,
            "call_ordinal": call_ordinal if allowed else 0,
            "data_classification": request.data_classification,
            "denial_reason": reason.value,
            "disposition": disposition.value,
            "egress_class": "none",
            "elapsed_milliseconds": elapsed_ms,
            "external_effect_count": 0,
            "filesystem_scope": request.filesystem_scope,
            "invocation_id": request.invocation_id,
            "maximum_calls": request.maximum_calls,
            "operation": operation_value,
            "record_type": "tool_receipt",
            "recorded_at": request.recorded_at,
            "result_root": result_root,
            "result_schema_root": request.result_schema_root,
            "schema_version": "skeleton.agent-tool-receipt.v1",
            "timeout_ms": request.timeout_ms,
        }
        receipt_id = _digest(_RECEIPT_DOMAIN, value)
        value["tool_receipt_id"] = receipt_id
        raw = canonicalize(value)
        receipt = AgentToolReceipt(
            receipt_id,
            request.invocation_id,
            request.attempt_ordinal,
            request.allowlist_root,
            request.allowlist_entry_id,
            request.operation,
            argument_root,
            result_root,
            disposition,
            reason,
            value["call_ordinal"],
            value["call_count"],
            elapsed_ms,
            0,
            raw,
        )
        receipt_append = ToolReceiptAppend(
            receipt_id,
            request.invocation_id,
            self._fence_id,
            request.attempt_ordinal,
            _digest(
                _OPERATION_DOMAIN,
                {"operation": operation_value, "request_id": request.request_id},
            ),
            argument_root,
            result_root if result_root != "none" else ZERO_SHA256,
            raw,
        )
        return receipt, receipt_append


@dataclass(frozen=True, slots=True)
class DeniedEgressReceipt:
    denial_receipt_id: str
    incident_id: str
    invocation_id: str
    attempt_ordinal: int
    purpose_root: str
    denial_reason: ToolDenialReason
    disposition: ToolDisposition
    egress_class: str
    external_effect_count: int
    network_count: int
    loopback_count: int
    dns_count: int
    hosted_model_count: int
    external_api_count: int
    credential_count: int
    authority_count: int
    external_state_count: int
    canonical_bytes: bytes


class DeniedEgressPort:
    """A destination-free port: construction cannot represent a usable egress target."""

    __slots__ = ("_account", "_fence_id", "_store", "_writer_id")

    def __init__(
        self,
        *,
        store: AgentStore,
        budget_account: BudgetAccount,
        writer_id: str,
        fence_id: str,
    ) -> None:
        self._store = store
        self._account = budget_account
        self._writer_id = _identity(writer_id, "egress_writer_identity_invalid")
        self._fence_id = _identity(fence_id, "egress_fence_identity_invalid")

    def deny(
        self,
        *,
        invocation_id: str,
        attempt_ordinal: int,
        purpose_root: str,
        attempt_key: str,
        recorded_at: str,
    ) -> DeniedEgressReceipt:
        invocation_id = _identity(invocation_id, "egress_invocation_identity_invalid")
        purpose_root = _identity(purpose_root, "egress_purpose_identity_invalid")
        attempt_ordinal = _safe_counter(attempt_ordinal, "egress_attempt_invalid")
        if not isinstance(attempt_key, str) or not attempt_key or not recorded_at.endswith("Z"):
            _reject("egress_attempt_invalid")
        snapshot = self._store.snapshot(invocation_id)
        if snapshot.current_fence_id != self._fence_id:
            _reject("egress_fence_identity_invalid")
        reservation = self._account.reserve(
            BudgetVector(elapsed_milliseconds=1, tool_calls=1),
            attempt=attempt_ordinal,
            reservation_key=f"egress-denied:{attempt_key}",
        )
        body = {
            "attempt": attempt_ordinal + 1,
            "authority_count": 0,
            "credential_count": 0,
            "denial_reason": ToolDenialReason.EGRESS_DENIED.value,
            "disposition": ToolDisposition.DENIED.value,
            "dns_count": 0,
            "egress_class": "none",
            "external_api_count": 0,
            "external_effect_count": 0,
            "external_state_count": 0,
            "hosted_model_count": 0,
            "invocation_id": invocation_id,
            "loopback_count": 0,
            "network_count": 0,
            "purpose_root": purpose_root,
            "record_type": "research_egress_denial",
            "recorded_at": recorded_at,
            "schema_version": "skeleton.agent-egress-denial.v1",
        }
        receipt_id = _digest(_EGRESS_RECEIPT_DOMAIN, body)
        incident_body = {
            "attempt": attempt_ordinal,
            "boundary": "research_egress",
            "detector_category": "exfiltration",
            "disposition": "denied_before_connection",
            "fence_id": self._fence_id,
            "generation": snapshot.current_generation,
            "invocation_id": invocation_id,
            "lineage_root": purpose_root,
            "retention_disposition": "retain_audit_metadata",
            "rule_id": "phase11_egress_always_denied_v1",
            "recorded_at": recorded_at,
        }
        incident_id = _digest(_INCIDENT_DOMAIN, incident_body)
        body["denial_receipt_id"] = receipt_id
        body["incident_id"] = incident_id
        raw = canonicalize(body)
        tool_append = ToolReceiptAppend(
            receipt_id,
            invocation_id,
            self._fence_id,
            attempt_ordinal,
            _digest(
                _OPERATION_DOMAIN,
                {"operation": "research_egress_denial", "purpose_root": purpose_root},
            ),
            purpose_root,
            ZERO_SHA256,
            raw,
        )
        incident_raw = canonicalize({"incident_id": incident_id, **incident_body})
        incident_append = IncidentAppend(
            incident_id,
            invocation_id,
            self._fence_id,
            snapshot.current_generation,
            attempt_ordinal,
            recorded_at,
            "exfiltration",
            "skeleton.agent-safety.v1",
            "phase11_egress_always_denied_v1",
            "research_egress",
            "denied_before_connection",
            purpose_root,
            _digest(_INCIDENT_DOMAIN, {"attempt_key": attempt_key}),
            "retain_audit_metadata",
            incident_raw,
        )
        budget_event, _reconciliation = self._account.prepare_reconciliation(
            reservation,
            BudgetVector(elapsed_milliseconds=0, tool_calls=0),
            reconciliation_key=f"egress-denial:{receipt_id}",
        )
        try:
            self._store.commit_tool_operation(
                tool_receipt=tool_append,
                budget=budget_event,
                incident=incident_append,
                writer_id=self._writer_id,
                operation_id=_digest(
                    _EGRESS_RECEIPT_DOMAIN,
                    {"operation": "terminal", "receipt_id": receipt_id},
                ),
            )
        except BaseException:
            try:
                self._account.mark_uncertain(
                    reservation,
                    uncertainty_key=f"egress-interrupted:{attempt_key}",
                )
            except BaseException:
                pass
            raise
        return DeniedEgressReceipt(
            receipt_id,
            incident_id,
            invocation_id,
            attempt_ordinal,
            purpose_root,
            ToolDenialReason.EGRESS_DENIED,
            ToolDisposition.DENIED,
            "none",
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            raw,
        )
