from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


MANIFEST_SCHEMA = "skeleton.public-export-manifest.v1"
PROVENANCE_SCHEMA = "skeleton.public-export-provenance.v1"
PROVENANCE_PATH = "PUBLIC-PROVENANCE.json"
MAX_PUBLIC_FILE_BYTES = 10 * 1024 * 1024

DENIED_PREFIXES = (
    ".git/",
    ".planning/",
    "owner-private/",
    "private/",
    "public-export/",
    "public-mirror/",
    "secrets/",
    "validation/",
)

DENIED_BASENAMES = {
    ".netrc",
    ".npmrc",
    ".pypirc",
    "auth.json",
    "credentials.json",
    "credentials.toml",
    "credentials.yaml",
    "credentials.yml",
    "kubeconfig",
    "service-account.json",
    "secrets.json",
    "secrets.toml",
    "secrets.yaml",
    "secrets.yml",
    "tokens.json",
    "tokens.toml",
    "tokens.yaml",
    "tokens.yml",
    "wallet.dat",
}

SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
ALLOWED_MODES = {"100644", "100755"}


class ExportError(RuntimeError):
    pass


@dataclass(frozen=True)
class ExportFile:
    path: str
    sha256: str
    size: int
    mode: str
    data: bytes


def _git(repo: Path, *args: str) -> bytes:
    try:
        return subprocess.check_output(
            ("git", "-C", str(repo), *args),
            stderr=subprocess.STDOUT,
        )
    except subprocess.CalledProcessError as exc:
        detail = exc.output.decode("utf-8", errors="replace").strip()
        raise ExportError(f"git command failed: {' '.join(args)}: {detail}") from exc


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ExportError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _validate_relative_path(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ExportError("manifest path must be a non-empty string")
    if "\\" in value or ":" in value or any(ord(char) < 32 for char in value):
        raise ExportError(f"unsafe manifest path: {value!r}")

    pure = PurePosixPath(value)
    if pure.is_absolute() or value.startswith("./") or value.endswith("/"):
        raise ExportError(f"manifest path is not canonical: {value!r}")
    if any(part in {"", ".", ".."} for part in pure.parts):
        raise ExportError(f"manifest path escapes or aliases the export root: {value!r}")

    lowered = value.lower()
    if lowered == ".git" or any(lowered.startswith(prefix) for prefix in DENIED_PREFIXES):
        raise ExportError(f"manifest path is denied: {value}")
    if pure.name.lower() in DENIED_BASENAMES:
        raise ExportError(f"credential filename is denied: {value}")
    if value == PROVENANCE_PATH:
        raise ExportError(f"{PROVENANCE_PATH} is generated and cannot be allowlisted")
    return value


def _resolve_commit(repo: Path, source: str) -> str:
    resolved = _git(repo, "rev-parse", "--verify", f"{source}^{{commit}}")
    commit = resolved.decode("ascii", errors="strict").strip()
    if not COMMIT_RE.fullmatch(commit):
        raise ExportError(f"source did not resolve to a full commit: {source}")
    return commit


def _manifest_bytes(repo: Path, commit: str, manifest_path: str) -> bytes:
    _validate_relative_path(manifest_path)
    return _git(repo, "show", f"{commit}:{manifest_path}")


def _load_manifest(data: bytes) -> list[dict[str, str]]:
    try:
        text = data.decode("utf-8", errors="strict")
        document = json.loads(text, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExportError(f"manifest is not strict UTF-8 JSON: {exc}") from exc

    if not isinstance(document, dict):
        raise ExportError("manifest root must be an object")
    if set(document) != {"schema_version", "files"}:
        raise ExportError("manifest must contain exactly schema_version and files")
    if document["schema_version"] != MANIFEST_SCHEMA:
        raise ExportError(f"unsupported manifest schema: {document['schema_version']!r}")

    raw_files = document["files"]
    if not isinstance(raw_files, list) or not raw_files:
        raise ExportError("manifest files must be a non-empty array")

    entries: list[dict[str, str]] = []
    for index, raw_entry in enumerate(raw_files):
        if not isinstance(raw_entry, dict) or set(raw_entry) != {"path", "sha256"}:
            raise ExportError(f"manifest files[{index}] must contain exactly path and sha256")
        path = _validate_relative_path(raw_entry["path"])
        digest = raw_entry["sha256"]
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise ExportError(f"manifest files[{index}] has an invalid SHA-256 digest")
        entries.append({"path": path, "sha256": digest})

    paths = [entry["path"] for entry in entries]
    if paths != sorted(paths):
        raise ExportError("manifest files must be sorted by path")
    if len(paths) != len(set(paths)):
        raise ExportError("manifest contains duplicate paths")
    return entries


def _tree_entry(repo: Path, commit: str, path: str) -> tuple[str, bytes]:
    raw = _git(repo, "ls-tree", "-z", commit, "--", path)
    records = [record for record in raw.split(b"\0") if record]
    if len(records) != 1:
        raise ExportError(f"allowlisted path is missing or ambiguous at {commit}: {path}")
    metadata, separator, returned_path = records[0].partition(b"\t")
    fields = metadata.split()
    if not separator or len(fields) != 3:
        raise ExportError(f"unexpected Git tree entry for: {path}")
    mode = fields[0].decode("ascii", errors="strict")
    kind = fields[1].decode("ascii", errors="strict")
    decoded_path = returned_path.decode("utf-8", errors="strict")
    if decoded_path != path or kind != "blob" or mode not in ALLOWED_MODES:
        raise ExportError(f"allowlisted path is not a regular public file: {path}")
    data = _git(repo, "show", f"{commit}:{path}")
    return mode, data


def _prepare_export(
    repo: Path,
    commit: str,
    manifest_path: str,
) -> tuple[str, list[ExportFile]]:
    manifest_data = _manifest_bytes(repo, commit, manifest_path)
    manifest_digest = hashlib.sha256(manifest_data).hexdigest()
    entries = _load_manifest(manifest_data)
    prepared: list[ExportFile] = []

    for entry in entries:
        path = entry["path"]
        mode, data = _tree_entry(repo, commit, path)
        if len(data) > MAX_PUBLIC_FILE_BYTES:
            raise ExportError(f"allowlisted file exceeds {MAX_PUBLIC_FILE_BYTES} bytes: {path}")
        actual_digest = hashlib.sha256(data).hexdigest()
        if actual_digest != entry["sha256"]:
            raise ExportError(
                f"allowlisted file digest changed: {path}; review it and update the manifest"
            )
        prepared.append(
            ExportFile(
                path=path,
                sha256=actual_digest,
                size=len(data),
                mode=mode,
                data=data,
            )
        )
    return manifest_digest, prepared


def _validate_output(repo: Path, output: Path) -> None:
    repo = repo.resolve()
    output = output.resolve()
    if output == repo or repo in output.parents:
        raise ExportError("output must be outside the private canonical repository")
    if output.exists():
        if not output.is_dir():
            raise ExportError("output exists and is not a directory")
        if any(output.iterdir()):
            raise ExportError("output directory must be empty")


def export_public_tree(
    repo: Path,
    source: str,
    manifest_path: str,
    output: Path,
) -> dict[str, Any]:
    repo = repo.resolve()
    if not (repo / ".git").exists():
        raise ExportError(f"repository does not have local Git metadata: {repo}")
    _validate_output(repo, output)

    commit = _resolve_commit(repo, source)
    manifest_digest, prepared = _prepare_export(repo, commit, manifest_path)
    output.mkdir(parents=True, exist_ok=True)

    for item in prepared:
        destination = output.joinpath(*PurePosixPath(item.path).parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(item.data)
        if os.name != "nt" and item.mode == "100755":
            destination.chmod(destination.stat().st_mode | 0o111)

    provenance: dict[str, Any] = {
        "schema_version": PROVENANCE_SCHEMA,
        "source_commit": commit,
        "manifest_path": manifest_path,
        "manifest_sha256": manifest_digest,
        "files": [
            {
                "path": item.path,
                "sha256": item.sha256,
                "size": item.size,
                "mode": item.mode,
            }
            for item in prepared
        ],
    }
    provenance_text = json.dumps(provenance, indent=2, sort_keys=True) + "\n"
    (output / PROVENANCE_PATH).write_text(provenance_text, encoding="utf-8", newline="\n")
    return provenance


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Export a hash-allowlisted public tree from a committed private source revision."
    )
    parser.add_argument("--repo", type=Path, required=True, help="private canonical Git repository")
    parser.add_argument("--source", required=True, help="commit or ref to export")
    parser.add_argument(
        "--manifest",
        default="release/public-export-manifest.json",
        help="manifest path inside the selected source commit",
    )
    parser.add_argument("--output", type=Path, required=True, help="new or empty output directory")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        provenance = export_public_tree(args.repo, args.source, args.manifest, args.output)
    except ExportError as exc:
        print(f"public export blocked: {exc}", file=sys.stderr)
        return 1
    print(
        "public export generated "
        f"{len(provenance['files'])} reviewed file(s) from {provenance['source_commit']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
