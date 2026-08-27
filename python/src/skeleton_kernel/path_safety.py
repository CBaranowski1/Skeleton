"""Fail-closed path and inventory primitives for contained Phase 7 evidence."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
import tempfile
from typing import Final


REPARSE_ATTRIBUTE: Final[int] = getattr(
    stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
)


class PathSafetyRejection(ValueError):
    """Stable path rejection that never includes a submitted or resolved path."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class PathIdentity:
    device: int
    inode: int
    mode: int
    attributes: int


@dataclass(frozen=True, slots=True)
class FileIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int
    links: int
    mode: int
    attributes: int


@dataclass(frozen=True, slots=True)
class InventoryRow:
    relative_path: str
    byte_length: int
    content_sha256: str


@dataclass(frozen=True, slots=True)
class InventorySnapshot:
    file_count: int
    sha256: str
    rows: tuple[InventoryRow, ...]


def _attributes(metadata: os.stat_result) -> int:
    return int(getattr(metadata, "st_file_attributes", 0))


def _is_junction(path: Path) -> bool:
    return bool(getattr(os.path, "isjunction", lambda _path: False)(path))


def _path_identity(metadata: os.stat_result) -> PathIdentity:
    return PathIdentity(
        int(metadata.st_dev),
        int(metadata.st_ino),
        stat.S_IFMT(metadata.st_mode),
        _attributes(metadata),
    )


def file_identity(metadata: os.stat_result) -> FileIdentity:
    return FileIdentity(
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(metadata.st_nlink),
        stat.S_IFMT(metadata.st_mode),
        _attributes(metadata),
    )


def _absolute_lexical(path: Path) -> Path:
    try:
        return Path(os.path.abspath(path))
    except (OSError, RuntimeError, ValueError) as error:
        raise PathSafetyRejection("path_unavailable") from error


def _assert_chain(path: Path, *, terminal_directory: bool) -> tuple[Path, os.stat_result]:
    absolute = _absolute_lexical(path)
    anchor = Path(absolute.anchor)
    current = anchor
    try:
        parts = absolute.parts[1:]
        for index, part in enumerate(parts):
            current = current / part
            metadata = current.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or _is_junction(current)
                or _attributes(metadata) & REPARSE_ATTRIBUTE
            ):
                raise PathSafetyRejection("path_reparse_forbidden")
            terminal = index == len(parts) - 1
            if not terminal and not stat.S_ISDIR(metadata.st_mode):
                raise PathSafetyRejection("path_component_not_directory")
        metadata = absolute.lstat()
    except PathSafetyRejection:
        raise
    except OSError as error:
        raise PathSafetyRejection("path_unavailable") from error
    expected = stat.S_ISDIR(metadata.st_mode) if terminal_directory else stat.S_ISREG(
        metadata.st_mode
    )
    if not expected:
        raise PathSafetyRejection(
            "root_not_directory" if terminal_directory else "file_not_regular"
        )
    return absolute, metadata


def canonical_relative_path(value: str) -> str:
    """Accept only portable relative paths with no alternate path interpretation."""

    if not isinstance(value, str) or not value:
        raise PathSafetyRejection("path_empty")
    if value.startswith(("//", "\\\\")):
        raise PathSafetyRejection("path_unc_forbidden")
    if Path(value).is_absolute() or value.startswith("/"):
        raise PathSafetyRejection("path_absolute_forbidden")
    if "\\" in value:
        raise PathSafetyRejection("path_noncanonical_separator")
    if ":" in value:
        raise PathSafetyRejection("path_alternate_stream_forbidden")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise PathSafetyRejection("path_traversal_forbidden")
    if any(part.endswith((" ", ".")) for part in parts):
        raise PathSafetyRejection("path_noncanonical_component")
    return "/".join(parts)


def is_strict_descendant(root: Path, candidate: Path) -> bool:
    """Compare path components, never lexical prefixes."""

    root_absolute = _absolute_lexical(root)
    candidate_absolute = _absolute_lexical(candidate)
    try:
        common = Path(os.path.commonpath((root_absolute, candidate_absolute)))
    except ValueError:
        return False
    return (
        os.path.normcase(str(common)) == os.path.normcase(str(root_absolute))
        and os.path.normcase(str(candidate_absolute))
        != os.path.normcase(str(root_absolute))
    )


class ContainedRoot:
    """An OS-temporary directory pinned to one filesystem identity."""

    __slots__ = ("root", "_identity")

    def __init__(self, root: Path | str) -> None:
        temporary, _ = _assert_chain(
            Path(tempfile.gettempdir()), terminal_directory=True
        )
        candidate, metadata = _assert_chain(Path(root), terminal_directory=True)
        if not is_strict_descendant(temporary, candidate):
            raise PathSafetyRejection("root_not_os_temporary_child")
        self.root = candidate
        self._identity = _path_identity(metadata)

    def assert_root_identity(self) -> None:
        _candidate, metadata = _assert_chain(self.root, terminal_directory=True)
        if _path_identity(metadata) != self._identity:
            raise PathSafetyRejection("root_identity_changed")

    def derive(self, relative: str, *, must_exist: bool = False) -> Path:
        self.assert_root_identity()
        canonical = canonical_relative_path(relative)
        candidate = self.root.joinpath(*canonical.split("/"))
        if not is_strict_descendant(self.root, candidate):
            raise PathSafetyRejection("path_traversal_forbidden")
        if must_exist:
            _assert_chain(candidate, terminal_directory=False)
        return candidate

    def assert_directory(self, path: Path) -> PathIdentity:
        self.assert_root_identity()
        if path != self.root and not is_strict_descendant(self.root, path):
            raise PathSafetyRejection("path_traversal_forbidden")
        _absolute, metadata = _assert_chain(path, terminal_directory=True)
        return _path_identity(metadata)

    def assert_regular_file(self, path: Path) -> FileIdentity:
        self.assert_root_identity()
        if not is_strict_descendant(self.root, path):
            raise PathSafetyRejection("path_traversal_forbidden")
        _absolute, metadata = _assert_chain(path, terminal_directory=False)
        if int(metadata.st_nlink) != 1:
            raise PathSafetyRejection("path_hard_link_forbidden")
        return file_identity(metadata)


def inventory_directory(root: Path | str) -> InventorySnapshot:
    """Hash a complete nonempty directory inventory in canonical tuple order."""

    absolute, _metadata = _assert_chain(Path(root), terminal_directory=True)
    rows: list[InventoryRow] = []
    try:
        for current, directory_names, file_names in os.walk(
            absolute, followlinks=False
        ):
            current_path = Path(current)
            for name in directory_names:
                _assert_chain(current_path / name, terminal_directory=True)
            for name in file_names:
                path = current_path / name
                _file, metadata = _assert_chain(path, terminal_directory=False)
                if int(metadata.st_nlink) != 1:
                    raise PathSafetyRejection("path_hard_link_forbidden")
                before = file_identity(metadata)
                raw = path.read_bytes()
                _after_path, after_metadata = _assert_chain(
                    path, terminal_directory=False
                )
                if file_identity(after_metadata) != before or len(raw) != before.size:
                    raise PathSafetyRejection("object_identity_changed")
                rows.append(
                    InventoryRow(
                        path.relative_to(absolute).as_posix(),
                        len(raw),
                        hashlib.sha256(raw).hexdigest(),
                    )
                )
    except PathSafetyRejection:
        raise
    except OSError as error:
        raise PathSafetyRejection("inventory_unavailable") from error
    if not rows:
        raise PathSafetyRejection("inventory_empty")
    rows.sort(
        key=lambda row: (
            row.relative_path.encode("utf-8"),
            row.byte_length,
            row.content_sha256,
        )
    )
    frame = bytearray(b"SKELETON_PHASE07_COMPLETE_INVENTORY_V1\0")
    for row in rows:
        relative = row.relative_path.encode("utf-8")
        frame.extend(len(relative).to_bytes(4, "big"))
        frame.extend(relative)
        frame.extend(row.byte_length.to_bytes(8, "big"))
        frame.extend(bytes.fromhex(row.content_sha256))
    return InventorySnapshot(
        len(rows), hashlib.sha256(frame).hexdigest(), tuple(rows)
    )
