"""Immutable one-way filesystem outbox for validated advisory proposals."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import stat

from .proposal import ValidatedProposal


@dataclass(slots=True)
class ProposalOutboxRejection(ValueError):
    code: str

    def __str__(self) -> str:
        return self.code


@dataclass(frozen=True, slots=True)
class PublishedProposal:
    proposal_id: str
    artifact_sha256: str
    byte_length: int
    path: Path
    digest_path: Path


class ProposalOutbox:
    """Write-only publication surface with no response or command method."""

    __slots__ = ("_directory",)

    def __init__(self, directory: Path | str) -> None:
        self._directory = Path(directory)
        self._directory.mkdir(parents=True, exist_ok=True)
        if not self._directory.is_dir():
            raise ProposalOutboxRejection("outbox_not_directory")

    def publish(self, proposal: ValidatedProposal) -> PublishedProposal:
        if not isinstance(proposal, ValidatedProposal):
            raise TypeError("ValidatedProposal required")
        artifact_path = self._directory / f"{proposal.proposal_id}.proposal.json"
        digest_path = self._directory / f"{proposal.proposal_id}.proposal.sha256"
        try:
            _write_exclusive(artifact_path, proposal.wire_bytes)
        except FileExistsError as error:
            raise ProposalOutboxRejection("duplicate_proposal_id") from error
        try:
            _write_exclusive(
                digest_path,
                f"{proposal.wire_sha256}\n".encode("ascii"),
            )
            if artifact_path.read_bytes() != proposal.wire_bytes:
                raise ProposalOutboxRejection("outbox_readback_mismatch")
            if digest_path.read_bytes() != (
                f"{proposal.wire_sha256}\n".encode("ascii")
            ):
                raise ProposalOutboxRejection("outbox_digest_readback_mismatch")
            os.chmod(artifact_path, stat.S_IREAD)
            os.chmod(digest_path, stat.S_IREAD)
        except BaseException:
            _remove_partial(digest_path)
            _remove_partial(artifact_path)
            raise
        return PublishedProposal(
            proposal_id=proposal.proposal_id,
            artifact_sha256=proposal.wire_sha256,
            byte_length=len(proposal.wire_bytes),
            path=artifact_path,
            digest_path=digest_path,
        )


def _write_exclusive(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    descriptor = os.open(path, flags, stat.S_IREAD | stat.S_IWRITE)
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short outbox write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _remove_partial(path: Path) -> None:
    try:
        os.chmod(path, stat.S_IWRITE)
        path.unlink(missing_ok=True)
    except OSError:
        pass
