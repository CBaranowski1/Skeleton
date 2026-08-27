from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType


SCRIPT_PATH = Path(__file__).with_name("export_public.py")


def load_exporter() -> ModuleType:
    spec = importlib.util.spec_from_file_location("skeleton_public_export", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("public_export_import_failed")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


EXPORTER = load_exporter()


class PublicExportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "private"
        self.output = self.root / "public"
        self.repo.mkdir()
        self.git("init", "--initial-branch=main")
        self.git("config", "user.name", "Skeleton Test")
        self.git("config", "user.email", "skeleton@example.invalid")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def git(self, *args: str) -> str:
        return subprocess.check_output(
            ("git", "-C", str(self.repo), *args),
            stderr=subprocess.STDOUT,
            text=True,
        ).strip()

    def write_manifest(self, entries: list[dict[str, str]]) -> None:
        path = self.repo / "release" / "public-export-manifest.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        document = {
            "schema_version": EXPORTER.MANIFEST_SCHEMA,
            "files": entries,
        }
        path.write_text(
            json.dumps(document, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )

    def commit_fixture(self, content: bytes = b"reviewed\n") -> tuple[str, str]:
        source = self.repo / "src" / "example.txt"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_bytes(content)
        digest = hashlib.sha256(content).hexdigest()
        self.write_manifest([{"path": "src/example.txt", "sha256": digest}])
        self.git("add", ".")
        self.git("commit", "-m", "test fixture")
        return self.git("rev-parse", "HEAD"), digest

    def test_exports_committed_bytes_and_deterministic_provenance(self) -> None:
        commit, digest = self.commit_fixture()
        (self.repo / "src" / "example.txt").write_bytes(b"dirty private change\n")

        provenance = EXPORTER.export_public_tree(
            self.repo,
            "HEAD",
            "release/public-export-manifest.json",
            self.output,
        )

        self.assertEqual((self.output / "src" / "example.txt").read_bytes(), b"reviewed\n")
        self.assertEqual(provenance["source_commit"], commit)
        self.assertEqual(provenance["files"][0]["sha256"], digest)
        recorded = json.loads((self.output / EXPORTER.PROVENANCE_PATH).read_text("utf-8"))
        self.assertEqual(recorded, provenance)

    def test_blocks_changed_allowlisted_content(self) -> None:
        source = self.repo / "src" / "example.txt"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("changed\n", encoding="utf-8", newline="\n")
        self.write_manifest([{"path": "src/example.txt", "sha256": "0" * 64}])
        self.git("add", ".")
        self.git("commit", "-m", "mismatch fixture")

        with self.assertRaisesRegex(EXPORTER.ExportError, "digest changed"):
            EXPORTER.export_public_tree(
                self.repo,
                "HEAD",
                "release/public-export-manifest.json",
                self.output,
            )
        self.assertFalse(self.output.exists())

    def test_blocks_unsorted_and_denied_paths(self) -> None:
        digest = hashlib.sha256(b"x").hexdigest()
        with self.assertRaisesRegex(EXPORTER.ExportError, "sorted by path"):
            EXPORTER._load_manifest(
                json.dumps(
                    {
                        "schema_version": EXPORTER.MANIFEST_SCHEMA,
                        "files": [
                            {"path": "z.txt", "sha256": digest},
                            {"path": "a.txt", "sha256": digest},
                        ],
                    }
                ).encode()
            )

        for path in ("../escape", ".planning/private.md", "validation/evidence.json"):
            with self.subTest(path=path):
                with self.assertRaises(EXPORTER.ExportError):
                    EXPORTER._validate_relative_path(path)

    def test_refuses_nonempty_or_in_repository_output(self) -> None:
        self.commit_fixture()
        self.output.mkdir()
        (self.output / "existing.txt").write_text("keep", encoding="utf-8")

        with self.assertRaisesRegex(EXPORTER.ExportError, "must be empty"):
            EXPORTER.export_public_tree(
                self.repo,
                "HEAD",
                "release/public-export-manifest.json",
                self.output,
            )
        with self.assertRaisesRegex(EXPORTER.ExportError, "outside"):
            EXPORTER.export_public_tree(
                self.repo,
                "HEAD",
                "release/public-export-manifest.json",
                self.repo / "generated",
            )


if __name__ == "__main__":
    unittest.main()
