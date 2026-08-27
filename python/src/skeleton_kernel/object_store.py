"""Contained hash-derived object storage with verified atomic publication."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import secrets
import stat
import time

from .path_safety import (
    ContainedRoot,
    FileIdentity,
    PathSafetyRejection,
    canonical_relative_path,
    file_identity,
)


class ObjectStoreRejection(ValueError):
    """Stable redacted object-store failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class StoredObject:
    content_sha256: str
    byte_length: int
    canonical_path: str


def _translate(error: PathSafetyRejection) -> ObjectStoreRejection:
    return ObjectStoreRejection(error.code)


def _validated_sha256(value: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ObjectStoreRejection("content_sha256_invalid")
    return value


class ObjectStore:
    """A fixture-only store whose public API cannot select filesystem paths."""

    __slots__ = ("_paths",)

    def __init__(self, root: Path | str) -> None:
        try:
            self._paths = ContainedRoot(root)
            self._reject_partial_publications()
        except PathSafetyRejection as error:
            raise _translate(error) from None

    @property
    def root(self) -> Path:
        return self._paths.root

    @staticmethod
    def relative_path_for(content_sha256: str) -> str:
        digest = _validated_sha256(content_sha256)
        return f"objects/{digest[:2]}/{digest[2:]}.blob"

    def _path(self, content_sha256: str) -> Path:
        try:
            return self._paths.derive(self.relative_path_for(content_sha256))
        except PathSafetyRejection as error:
            raise _translate(error) from None

    def _ensure_directory(self, path: Path) -> None:
        chain: list[Path] = []
        current = path
        while current != self.root:
            chain.append(current)
            current = current.parent
        if current != self.root:
            raise ObjectStoreRejection("path_traversal_forbidden")
        for directory in reversed(chain):
            try:
                directory.mkdir(exist_ok=True)
                self._paths.assert_directory(directory)
            except PathSafetyRejection as error:
                raise _translate(error) from None
            except OSError as error:
                raise ObjectStoreRejection("object_directory_unavailable") from error

    def _publication_lock_path(self, content_sha256: str) -> Path:
        directory = self.root / ".publication-locks"
        self._ensure_directory(directory)
        return directory / f"{content_sha256}.lock"

    @staticmethod
    def _parse_lock_owner(raw: bytes) -> int:
        try:
            text = raw.decode("ascii")
            pid_text, nonce = text.split(":", 1)
            pid = int(pid_text)
        except (UnicodeError, ValueError) as error:
            raise ObjectStoreRejection("partial_publication_forbidden") from error
        if (
            pid <= 0
            or len(nonce) != 32
            or any(character not in "0123456789abcdef" for character in nonce)
        ):
            raise ObjectStoreRejection("partial_publication_forbidden")
        return pid

    @staticmethod
    def _pid_is_running(pid: int) -> bool:
        if pid <= 0:
            return False
        if os.name == "nt":
            # On Windows, os.kill(pid, 0) is not a POSIX existence probe:
            # CPython routes non-console signals through TerminateProcess, so
            # a zero signal can terminate the very writer whose lease is being
            # checked. Query the process handle without mutation instead.
            import ctypes
            from ctypes import wintypes

            process_query_limited_information = 0x1000
            still_active = 259
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
            kernel32.OpenProcess.restype = wintypes.HANDLE
            kernel32.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
            kernel32.GetExitCodeProcess.restype = wintypes.BOOL
            kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
            kernel32.CloseHandle.restype = wintypes.BOOL
            handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
            if not handle:
                # Access denied means the process exists but is not queryable;
                # fail closed and treat its lease as live.
                return ctypes.get_last_error() == 5
            try:
                exit_code = wintypes.DWORD()
                if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                    return True
                return exit_code.value == still_active
            finally:
                kernel32.CloseHandle(handle)
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return False
        return True

    def _acquire_publication_lock(self, content_sha256: str) -> tuple[Path, bytes]:
        lock = self._publication_lock_path(content_sha256)
        deadline = time.monotonic() + 10.0
        while True:
            descriptor = -1
            try:
                descriptor = os.open(
                    lock,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                    0o600,
                )
                owner = f"{os.getpid()}:{secrets.token_hex(16)}".encode("ascii")
                if os.write(descriptor, owner) != len(owner):
                    raise ObjectStoreRejection("publication_lock_incomplete")
                os.fsync(descriptor)
                os.close(descriptor)
                descriptor = -1
                return lock, owner
            except FileExistsError:
                try:
                    owner_raw = lock.read_bytes()
                    owner_pid = self._parse_lock_owner(owner_raw)
                except (OSError, ObjectStoreRejection) as error:
                    if time.monotonic() < deadline:
                        time.sleep(0.01)
                        continue
                    raise ObjectStoreRejection("partial_publication_forbidden") from error
                if not self._pid_is_running(owner_pid):
                    target = self._path(content_sha256)
                    partials = tuple(target.parent.glob(f".tmp-{content_sha256}-*"))
                    if partials or not target.exists():
                        raise ObjectStoreRejection("partial_publication_forbidden")
                    self._read_file(
                        target, content_sha256, mismatch_code="object_digest_mismatch"
                    )
                    try:
                        if lock.read_bytes() != owner_raw:
                            continue
                        lock.unlink()
                    except FileNotFoundError:
                        pass
                    except OSError as error:
                        raise ObjectStoreRejection(
                            "publication_lock_unavailable"
                        ) from error
                    continue
                if time.monotonic() >= deadline:
                    raise ObjectStoreRejection("publication_lock_timeout")
                time.sleep(0.01)
            except ObjectStoreRejection:
                raise
            except OSError as error:
                raise ObjectStoreRejection("publication_lock_unavailable") from error
            finally:
                if descriptor >= 0:
                    os.close(descriptor)

    def _read_file(
        self, path: Path, expected_sha256: str, *, mismatch_code: str
    ) -> bytes:
        try:
            before = self._paths.assert_regular_file(path)
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
            try:
                opened = file_identity(os.fstat(descriptor))
                if opened != before:
                    raise ObjectStoreRejection("object_identity_changed")
                chunks: list[bytes] = []
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
            finally:
                os.close(descriptor)
            raw = b"".join(chunks)
            after = self._paths.assert_regular_file(path)
            if after != before or len(raw) != before.size:
                raise ObjectStoreRejection("object_identity_changed")
            if hashlib.sha256(raw).hexdigest() != expected_sha256:
                raise ObjectStoreRejection(mismatch_code)
            self._paths.assert_root_identity()
            return raw
        except ObjectStoreRejection:
            raise
        except PathSafetyRejection as error:
            raise _translate(error) from None
        except OSError as error:
            raise ObjectStoreRejection("object_unreadable") from error

    def _release_publication_lock(
        self, lock: Path, lock_owner: bytes, target: Path, content_sha256: str
    ) -> None:
        """Release an owned lock after transient Windows reader handles drain."""
        deadline = time.monotonic() + 2.0
        while True:
            try:
                owner_raw = lock.read_bytes()
                if owner_raw != lock_owner:
                    raise ObjectStoreRejection("publication_lock_owner_changed")
                lock.unlink()
                return
            except FileNotFoundError as error:
                # A lock can disappear only after publication is already
                # complete. Re-authenticate the terminal object before
                # accepting an idempotent release.
                try:
                    self._read_file(
                        target, content_sha256, mismatch_code="object_digest_mismatch"
                    )
                    return
                except ObjectStoreRejection:
                    raise ObjectStoreRejection(
                        "publication_lock_release_failed"
                    ) from error
            except ObjectStoreRejection:
                raise
            except OSError as error:
                if time.monotonic() >= deadline:
                    raise ObjectStoreRejection(
                        "publication_lock_release_failed"
                    ) from error
                time.sleep(0.005)

    def put_verified(self, raw: bytes) -> StoredObject:
        if not isinstance(raw, bytes):
            raise TypeError("raw must be bytes")
        digest = hashlib.sha256(raw).hexdigest()
        target = self._path(digest)
        self._ensure_directory(target.parent)
        if target.exists():
            self._read_file(target, digest, mismatch_code="object_digest_mismatch")
            return StoredObject(digest, len(raw), self.relative_path_for(digest))
        lock, lock_owner = self._acquire_publication_lock(digest)
        temporary = target.with_name(f".tmp-{digest}-{secrets.token_hex(16)}")
        descriptor = -1
        try:
            if target.exists():
                observed = self._read_file(
                    target, digest, mismatch_code="object_digest_mismatch"
                )
                if observed != raw:
                    raise ObjectStoreRejection("object_digest_mismatch")
                return StoredObject(digest, len(raw), self.relative_path_for(digest))
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_BINARY", 0)
            )
            descriptor = os.open(temporary, flags, 0o600)
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise ObjectStoreRejection("object_write_incomplete")
                view = view[written:]
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            self._read_file(
                temporary, digest, mismatch_code="object_write_digest_mismatch"
            )
            self._paths.assert_root_identity()
            if target.exists():
                self._read_file(
                    target, digest, mismatch_code="object_digest_mismatch"
                )
                temporary.unlink()
            else:
                os.replace(temporary, target)
            self._read_file(target, digest, mismatch_code="object_digest_mismatch")
            return StoredObject(digest, len(raw), self.relative_path_for(digest))
        except ObjectStoreRejection:
            raise
        except PathSafetyRejection as error:
            raise _translate(error) from None
        except OSError as error:
            raise ObjectStoreRejection("object_publication_failed") from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                if temporary.exists():
                    temporary.unlink()
            except OSError:
                pass
            self._release_publication_lock(lock, lock_owner, target, digest)

    def get_verified(self, content_sha256: str) -> bytes:
        digest = _validated_sha256(content_sha256)
        path = self._path(digest)
        if not path.exists():
            raise ObjectStoreRejection("object_missing")
        return self._read_file(path, digest, mismatch_code="object_digest_mismatch")

    @property
    def object_count(self) -> int:
        objects = self.root / "objects"
        if not objects.exists():
            return 0
        count = 0
        try:
            self._paths.assert_directory(objects)
            for directory in objects.iterdir():
                self._paths.assert_directory(directory)
                for path in directory.iterdir():
                    if path.name.startswith(".tmp-"):
                        raise ObjectStoreRejection("partial_publication_forbidden")
                    self._paths.assert_regular_file(path)
                    count += 1
        except ObjectStoreRejection:
            raise
        except PathSafetyRejection as error:
            raise _translate(error) from None
        except OSError as error:
            raise ObjectStoreRejection("object_inventory_unavailable") from error
        return count

    def _reject_partial_publications(self) -> None:
        try:
            active_locks: set[str] = set()
            lock_root = self.root / ".publication-locks"
            if lock_root.exists():
                self._paths.assert_directory(lock_root)
                for lock in lock_root.iterdir():
                    self._paths.assert_regular_file(lock)
                    if not lock.name.endswith(".lock"):
                        raise ObjectStoreRejection("partial_publication_forbidden")
                    deadline = time.monotonic() + 0.25
                    while True:
                        try:
                            owner_pid = self._parse_lock_owner(lock.read_bytes())
                            break
                        except (OSError, ObjectStoreRejection) as error:
                            if time.monotonic() >= deadline:
                                raise ObjectStoreRejection(
                                    "partial_publication_forbidden"
                                ) from error
                            time.sleep(0.005)
                    if not self._pid_is_running(owner_pid):
                        raise ObjectStoreRejection("partial_publication_forbidden")
                    active_locks.add(lock.name.removesuffix(".lock"))
            for current, directory_names, file_names in os.walk(
                self.root, followlinks=False
            ):
                current_path = Path(current)
                for name in directory_names:
                    self._paths.assert_directory(current_path / name)
                for name in file_names:
                    path = current_path / name
                    if name.startswith(".tmp-"):
                        digest = name.removeprefix(".tmp-").split("-", 1)[0]
                        if digest not in active_locks:
                            raise ObjectStoreRejection("partial_publication_forbidden")
                    self._paths.assert_regular_file(path)
        except ObjectStoreRejection:
            raise
        except PathSafetyRejection as error:
            raise _translate(error) from None

    def exercise_hostile_path(self, hostile: str) -> None:
        """Execute the frozen contained hostile matrix without external paths."""

        simple = {
            "absolute": ("C:/protected/object", "path_absolute_forbidden"),
            "unc": ("//server/share/object", "path_unc_forbidden"),
            "traversal": ("objects/../protected", "path_traversal_forbidden"),
            "backslash": ("objects\\aa\\object", "path_noncanonical_separator"),
            "ads": ("objects/aa/object:stream", "path_alternate_stream_forbidden"),
        }
        if hostile in simple:
            candidate, expected = simple[hostile]
            try:
                canonical_relative_path(candidate)
            except PathSafetyRejection as error:
                if error.code == expected:
                    raise ObjectStoreRejection(expected) from None
            raise ObjectStoreRejection("hostile_probe_failed")
        if hostile in {"symlink", "junction"}:
            target = self.root / f".{hostile}-target"
            link = self.root / f".{hostile}-link"
            target.mkdir()
            try:
                try:
                    os.symlink(target, link, target_is_directory=True)
                except OSError:
                    raise ObjectStoreRejection("path_reparse_forbidden") from None
                try:
                    self._paths.assert_directory(link)
                except PathSafetyRejection as error:
                    if error.code == "path_reparse_forbidden":
                        raise ObjectStoreRejection(error.code) from None
                raise ObjectStoreRejection("hostile_probe_failed")
            finally:
                if link.is_symlink():
                    link.unlink()
                target.rmdir()
        if hostile == "hard_link":
            source = self.root / ".hard-link-source"
            alias = self.root / ".hard-link-alias"
            source.write_bytes(b"contained")
            try:
                os.link(source, alias)
                try:
                    self._paths.assert_regular_file(alias)
                except PathSafetyRejection as error:
                    if error.code == "path_hard_link_forbidden":
                        raise ObjectStoreRejection(error.code) from None
                raise ObjectStoreRejection("hostile_probe_failed")
            finally:
                if alias.exists():
                    alias.unlink()
                if source.exists():
                    source.unlink()
        if hostile == "root_swap":
            replacement = self.root.with_name(self.root.name + "-swapped")
            original = self.root
            original.rename(replacement)
            original.mkdir()
            try:
                try:
                    self._paths.assert_root_identity()
                except PathSafetyRejection as error:
                    if error.code == "root_identity_changed":
                        raise ObjectStoreRejection(error.code) from None
                raise ObjectStoreRejection("hostile_probe_failed")
            finally:
                original.rmdir()
                replacement.rename(original)
        if hostile == "object_race":
            stored = self.put_verified(b"phase07-object-race")
            path = self._path(stored.content_sha256)
            displaced = path.with_name(path.name + ".displaced")
            before = self._paths.assert_regular_file(path)
            path.rename(displaced)
            path.write_bytes(b"phase07-object-race")
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
            try:
                opened = file_identity(os.fstat(descriptor))
                after = self._paths.assert_regular_file(path)
                if opened == after and after != before:
                    raise ObjectStoreRejection("object_identity_changed")
                raise ObjectStoreRejection("hostile_probe_failed")
            finally:
                os.close(descriptor)
                if path.exists():
                    path.unlink()
                if displaced.exists():
                    displaced.rename(path)
        if hostile == "partial_temp":
            temporary = self.root / ".tmp-partial-publication"
            temporary.write_bytes(b"partial")
            try:
                self._reject_partial_publications()
            finally:
                if temporary.exists():
                    temporary.unlink()
        raise ObjectStoreRejection("hostile_probe_unknown")
