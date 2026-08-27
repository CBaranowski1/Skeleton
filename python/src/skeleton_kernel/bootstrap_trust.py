"""Authenticate the independently pinned Phase 6 release root before state exists."""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
import tempfile
from typing import Any

from .canonical import canonicalize, parse_raw_json


EXPECTED_RELEASE_ROOT_ANCHOR_SHA256 = (
    "56dbeb400d868d747728101f7356259f4802b7165c129180adf902934d2e02ed"
)
EXPECTED_RELEASE_ROOT_FINGERPRINT_SHA256 = (
    "21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9"
)
PROVISIONER_PIN = "skeleton.phase06.fixed-root-provisioner.v1"
ANCHOR_SCHEMA = "skeleton.phase06.release-root-anchor.v1"
BINDING_SCHEMA = "skeleton.phase06.root-anchor-binding.v1"
ANCHOR_LENGTH = 297
MAX_BINDING_LENGTH = 4096
FILE_ATTRIBUTE_READONLY = 0x1
FILE_ATTRIBUTE_REPARSE_POINT = 0x400


@dataclass(slots=True)
class RootTrustRejection(ValueError):
    code: str

    def __str__(self) -> str:
        return self.code


@dataclass(frozen=True, slots=True)
class ReleaseRootAnchor:
    anchor_epoch: str
    anchor_id: str
    root_fingerprint_sha256: str
    root_public_key: bytes
    artifact_sha256: str
    installed_path: Path
    source_commit: str
    binding_sha256: str


def load_release_root_anchor(
    path: Path | None = None,
    binding_path: Path | None = None,
    *,
    test_mode: bool = False,
) -> ReleaseRootAnchor:
    """Load only the fixed installed root pair, with overrides confined to tests."""

    if test_mode:
        if path is None or binding_path is None:
            raise RootTrustRejection("test_mode_paths_required")
        anchor_path = Path(path)
        sidecar_path = Path(binding_path)
        _assert_test_containment(anchor_path, sidecar_path)
    else:
        if path is not None or binding_path is not None:
            raise RootTrustRejection("normal_mode_override")
        anchor_path = _production_anchor_path()
        sidecar_path = anchor_path.with_name("release-root-anchor.binding.json")

    if sidecar_path.parent != anchor_path.parent or sidecar_path.name != (
        "release-root-anchor.binding.json"
    ):
        raise RootTrustRejection("binding_path_mismatch")

    anchor_raw, anchor_stat = _read_sealed_file(
        anchor_path, exact_length=ANCHOR_LENGTH, code_prefix="anchor"
    )
    observed_anchor_sha256 = hashlib.sha256(anchor_raw).hexdigest()
    if observed_anchor_sha256 != EXPECTED_RELEASE_ROOT_ANCHOR_SHA256:
        raise RootTrustRejection("anchor_digest_mismatch")
    anchor_value = _strict_canonical_object(anchor_raw, "anchor")
    expected_anchor_keys = {
        "anchor_epoch",
        "anchor_id",
        "root_fingerprint_sha256",
        "root_public_key",
        "schema_version",
    }
    if set(anchor_value) != expected_anchor_keys:
        raise RootTrustRejection("anchor_fields_mismatch")
    if anchor_value["schema_version"] != ANCHOR_SCHEMA:
        raise RootTrustRejection("anchor_schema_mismatch")
    if anchor_value["anchor_epoch"] != "0":
        raise RootTrustRejection("anchor_epoch_mismatch")
    if anchor_value["anchor_id"] != "phase06-rfc8032-test-root":
        raise RootTrustRejection("anchor_id_mismatch")
    public_key_text = _lower_hex(anchor_value["root_public_key"], 64, "root_public_key")
    public_key = bytes.fromhex(public_key_text)
    observed_fingerprint = hashlib.sha256(public_key).hexdigest()
    if (
        anchor_value["root_fingerprint_sha256"] != observed_fingerprint
        or observed_fingerprint != EXPECTED_RELEASE_ROOT_FINGERPRINT_SHA256
    ):
        raise RootTrustRejection("root_fingerprint_mismatch")

    binding_raw, binding_stat = _read_sealed_file(
        sidecar_path, maximum_length=MAX_BINDING_LENGTH, code_prefix="binding"
    )
    binding = _strict_canonical_object(binding_raw, "binding")
    expected_binding = {
        "anchor_epoch": "0",
        "expected_root_fingerprint_sha256": (
            EXPECTED_RELEASE_ROOT_FINGERPRINT_SHA256
        ),
        "installed_anchor_sha256": EXPECTED_RELEASE_ROOT_ANCHOR_SHA256,
        "installed_path": str(anchor_path.resolve(strict=True)),
        "provisioner_pin": PROVISIONER_PIN,
        "schema_version": BINDING_SCHEMA,
        "source_anchor_sha256": EXPECTED_RELEASE_ROOT_ANCHOR_SHA256,
    }
    if set(binding) != expected_binding.keys() | {"source_commit"}:
        raise RootTrustRejection("binding_fields_mismatch")
    for key, expected in expected_binding.items():
        if key == "installed_path":
            if os.path.normcase(str(binding.get(key))) != os.path.normcase(expected):
                raise RootTrustRejection("binding_installed_path_mismatch")
        elif binding.get(key) != expected:
            raise RootTrustRejection(f"binding_{key}_mismatch")
    source_commit = binding.get("source_commit")
    if (
        not isinstance(source_commit, str)
        or len(source_commit) != 40
        or any(character not in "0123456789abcdef" for character in source_commit)
    ):
        raise RootTrustRejection("binding_source_commit_mismatch")

    _assert_unchanged(anchor_path, anchor_stat, anchor_raw, "anchor")
    _assert_unchanged(sidecar_path, binding_stat, binding_raw, "binding")
    return ReleaseRootAnchor(
        anchor_epoch="0",
        anchor_id="phase06-rfc8032-test-root",
        root_fingerprint_sha256=EXPECTED_RELEASE_ROOT_FINGERPRINT_SHA256,
        root_public_key=public_key,
        artifact_sha256=EXPECTED_RELEASE_ROOT_ANCHOR_SHA256,
        installed_path=anchor_path.resolve(strict=True),
        source_commit=source_commit,
        binding_sha256=hashlib.sha256(binding_raw).hexdigest(),
    )


def _production_anchor_path() -> Path:
    if os.name != "nt":
        raise RootTrustRejection("production_path_unsupported")
    buffer = ctypes.create_unicode_buffer(32768)
    # CSIDL_COMMON_APPDATA resolves through the Windows shell API rather than
    # a caller-controlled environment variable.
    result = ctypes.windll.shell32.SHGetFolderPathW(None, 35, None, 0, buffer)
    if result != 0 or not buffer.value:
        raise RootTrustRejection("programdata_resolution_failed")
    return (
        Path(buffer.value)
        / "Skeleton"
        / "trust"
        / "phase06"
        / "release-root-anchor.json"
    )


def _assert_test_containment(anchor_path: Path, binding_path: Path) -> None:
    temporary_root = Path(tempfile.gettempdir()).resolve(strict=True)
    for candidate in (anchor_path, binding_path):
        absolute = Path(os.path.abspath(candidate))
        try:
            if absolute != temporary_root and temporary_root not in absolute.parents:
                raise RootTrustRejection("test_mode_not_contained")
        except (OSError, RuntimeError) as error:
            raise RootTrustRejection("test_mode_not_contained") from error
    expected_suffix = ("Skeleton", "trust", "phase06")
    if (
        tuple(anchor_path.parent.parts[-3:]) != expected_suffix
        or tuple(binding_path.parent.parts[-3:]) != expected_suffix
        or anchor_path.name != "release-root-anchor.json"
        or binding_path.name != "release-root-anchor.binding.json"
    ):
        _assert_no_reparse_chain(anchor_path, "anchor")
        _assert_no_reparse_chain(binding_path, "binding")
        raise RootTrustRejection("test_mode_not_contained")


def _read_sealed_file(
    path: Path,
    *,
    code_prefix: str,
    exact_length: int | None = None,
    maximum_length: int | None = None,
) -> tuple[bytes, os.stat_result]:
    _assert_no_reparse_chain(path, code_prefix)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise RootTrustRejection(f"{code_prefix}_unreadable") from error
    attributes = getattr(metadata, "st_file_attributes", 0)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or attributes & FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise RootTrustRejection(f"{code_prefix}_not_regular")
    if not attributes & FILE_ATTRIBUTE_READONLY:
        raise RootTrustRejection(f"{code_prefix}_not_readonly")
    if os.access(path, os.W_OK):
        raise RootTrustRejection(f"{code_prefix}_effectively_writable")
    if exact_length is not None and metadata.st_size != exact_length:
        raise RootTrustRejection(f"{code_prefix}_length_mismatch")
    if maximum_length is not None and not 0 < metadata.st_size <= maximum_length:
        raise RootTrustRejection(f"{code_prefix}_length_mismatch")
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise RootTrustRejection(f"{code_prefix}_unreadable") from error
    if len(raw) != metadata.st_size:
        raise RootTrustRejection(f"{code_prefix}_changed_during_read")
    return raw, metadata


def _assert_no_reparse_chain(path: Path, code_prefix: str) -> None:
    absolute = Path(os.path.abspath(path))
    for candidate in (absolute, *absolute.parents):
        if not candidate.exists():
            continue
        try:
            attributes = getattr(candidate.lstat(), "st_file_attributes", 0)
        except OSError as error:
            raise RootTrustRejection(f"{code_prefix}_unreadable") from error
        if candidate.is_symlink() or attributes & FILE_ATTRIBUTE_REPARSE_POINT:
            raise RootTrustRejection(f"{code_prefix}_reparse")


def _assert_unchanged(
    path: Path,
    before: os.stat_result,
    raw: bytes,
    code_prefix: str,
) -> None:
    after = path.lstat()
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_after != identity_before or path.read_bytes() != raw:
        raise RootTrustRejection(f"{code_prefix}_changed_during_read")


def _strict_canonical_object(raw: bytes, code_prefix: str) -> dict[str, Any]:
    if raw.startswith(b"\xef\xbb\xbf") or raw.endswith((b"\n", b"\r")):
        raise RootTrustRejection(f"{code_prefix}_not_canonical")
    try:
        value = parse_raw_json(raw)
        if not isinstance(value, dict) or canonicalize(value) != raw:
            raise RootTrustRejection(f"{code_prefix}_not_canonical")
    except RootTrustRejection:
        raise
    except (TypeError, ValueError) as error:
        raise RootTrustRejection(f"{code_prefix}_malformed") from error
    return value


def _lower_hex(value: Any, length: int, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != length
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise RootTrustRejection(f"{field}_malformed")
    return value
