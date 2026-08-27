"""Bounded versioned semantic safety gate for Phase 10 memory admission."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from math import log2
import re
from typing import Any

from .canonical import canonicalize


DETECTOR_VERSION = "skeleton.memory-safety-detector.v1"
MAX_SCAN_NODES = 4096
MAX_SCAN_DEPTH = 32
MAX_SCALAR_UTF8_BYTES = 4096


class SafetyCategory(StrEnum):
    CREDENTIAL = "credential"
    AUTHENTICATION_MATERIAL = "authentication_material"
    PRIVATE_KEY = "private_key"
    RECOVERY_SECRET = "recovery_secret"
    TOKEN = "token"
    RAW_PROMPT = "raw_prompt"
    TRANSCRIPT = "transcript"
    SCRATCHPAD = "scratchpad"
    HIDDEN_REASONING = "hidden_reasoning"


class SafetyDisposition(StrEnum):
    REJECTED_BEFORE_PERSISTENCE = "rejected_before_persistence"
    SOURCE_QUARANTINED = "source_quarantined"


@dataclass(frozen=True, slots=True)
class SafetyRejectionMetadata:
    category: SafetyCategory
    detector_version: str
    rule_id: str
    source_event_id: str
    disposition: SafetyDisposition


class MemorySafetyRejection(ValueError):
    """Stable rejection containing metadata only, never submitted material."""

    def __init__(self, code: str, metadata: SafetyRejectionMetadata) -> None:
        self.code = code
        self.metadata = metadata
        super().__init__(code)


_STRUCTURAL_RULES: tuple[tuple[re.Pattern[str], SafetyCategory, str], ...] = (
    (re.compile(r"^(?:credential|credentials)(?:_|$)"), SafetyCategory.CREDENTIAL, "credential_name_v1"),
    (re.compile(r"^(?:authentication_material|authentication|authorization|auth)(?:_|$)"), SafetyCategory.AUTHENTICATION_MATERIAL, "authentication_name_v1"),
    (re.compile(r"^(?:private_key|privatekey)(?:_|$)"), SafetyCategory.PRIVATE_KEY, "private_key_name_v1"),
    (re.compile(r"^(?:recovery_secret|recovery_code|recovery)(?:_|$)"), SafetyCategory.RECOVERY_SECRET, "recovery_name_v1"),
    (re.compile(r"^(?:api_key|access_token|refresh_token|token|password|passphrase|client_secret)(?:_|$)"), SafetyCategory.TOKEN, "token_name_v1"),
    (re.compile(r"^(?:raw_prompt|system_prompt|user_prompt|prompt)(?:_|$)"), SafetyCategory.RAW_PROMPT, "raw_prompt_name_v1"),
    (re.compile(r"^(?:transcript|tool_transcript)(?:_|$)"), SafetyCategory.TRANSCRIPT, "transcript_name_v1"),
    (re.compile(r"^(?:scratchpad|working_notes)(?:_|$)"), SafetyCategory.SCRATCHPAD, "scratchpad_name_v1"),
    (re.compile(r"^(?:hidden_reasoning|reasoning_trace|chain_of_thought|thought_process)(?:_|$)"), SafetyCategory.HIDDEN_REASONING, "hidden_reasoning_name_v1"),
)

_PREFIX_RULES: tuple[tuple[re.Pattern[str], SafetyCategory, str], ...] = (
    (re.compile(r"^(?:bearer|basic|session)(?:[\s_:=.-]|$)"), SafetyCategory.AUTHENTICATION_MATERIAL, "authentication_prefix_v1"),
    (re.compile(r"^(?:credential|credentials)(?:[\s_:=.-]|$)"), SafetyCategory.CREDENTIAL, "credential_prefix_v1"),
    (re.compile(r"^(?:authentication_material|authentication|authorization|auth)(?:[\s_:=.-]|$)"), SafetyCategory.AUTHENTICATION_MATERIAL, "authentication_prefix_v1"),
    (re.compile(r"^(?:private_key|private-key|privatekey)(?:[\s_:=.-]|$)"), SafetyCategory.PRIVATE_KEY, "private_key_prefix_v1"),
    (re.compile(r"^(?:recovery_secret|recovery-code|recovery)(?:[\s_:=.-]|$)"), SafetyCategory.RECOVERY_SECRET, "recovery_prefix_v1"),
    (re.compile(r"^(?:token|access_token|refresh_token|api_key|password|passphrase|client_secret)(?:[\s_:=.-]|$)"), SafetyCategory.TOKEN, "token_prefix_v1"),
)

# These expressions intentionally find assignments anywhere in a bounded scalar.
# They require both a credential label and a value-shaped suffix so ordinary prose
# about passwords or tokens is not rejected merely for naming the concept.
_EMBEDDED_CREDENTIAL_RULES: tuple[
    tuple[re.Pattern[str], SafetyCategory, str], ...
] = (
    (
        re.compile(
            r"\b(?:password|passphrase|api[ _-]?key|access[ _-]?token|"
            r"refresh[ _-]?token|client[ _-]?secret|credential)s?\b"
            r"\s*(?:is|=|:|=>)\s*[^\s,;]{4,256}"
        ),
        SafetyCategory.TOKEN,
        "embedded_credential_assignment_v1",
    ),
    (
        re.compile(r"\b(?:bearer|basic|session)\s+[a-z0-9._~+/-]{8,512}\b"),
        SafetyCategory.AUTHENTICATION_MATERIAL,
        "embedded_authentication_material_v1",
    ),
    (
        re.compile(
            r"\b(?:akia[0-9a-z]{16}|gh[pousr]_[0-9a-z]{20,255}|"
            r"sk-(?:proj-)?[0-9a-z_-]{10,255})\b"
        ),
        SafetyCategory.TOKEN,
        "known_token_format_v1",
    ),
)

_ENVIRONMENT_SECRET_NAMES = frozenset(
    {
        "aws_secret_access_key",
        "aws_session_token",
        "azure_client_secret",
        "client_secret",
        "database_url",
        "github_token",
        "google_application_credentials",
        "openai_api_key",
        "private_key_path",
        "secret_access_key",
    }
)

_HIDDEN_TEXT_RULES: tuple[tuple[re.Pattern[str], SafetyCategory, str], ...] = (
    (re.compile(r"\braw[ _-]+prompt\b|\bsystem[ _-]+prompt\b|\buser[ _-]+prompt\b"), SafetyCategory.RAW_PROMPT, "raw_prompt_text_v1"),
    (re.compile(r"\b(?:tool[ _-]+)?transcript\b"), SafetyCategory.TRANSCRIPT, "transcript_text_v1"),
    (re.compile(r"\bscratchpad\b"), SafetyCategory.SCRATCHPAD, "scratchpad_text_v1"),
    (re.compile(r"\b(?:hidden[ _-]+)?chain[ _-]+of[ _-]+thought\b|\breasoning[ _-]+trace\b|\bthought[ _-]+process\b|\bhidden[ _-]+reasoning\b"), SafetyCategory.HIDDEN_REASONING, "hidden_reasoning_text_v1"),
)

_PRIVATE_KEY_MARKER = re.compile(
    r"-----begin (?:rsa |ec |openssh )?private key-----|private[ _-]+key"
)


def _metadata(
    category: SafetyCategory, rule_id: str, source_event_id: str
) -> SafetyRejectionMetadata:
    return SafetyRejectionMetadata(
        category=category,
        detector_version=DETECTOR_VERSION,
        rule_id=rule_id,
        source_event_id=source_event_id,
        disposition=SafetyDisposition.REJECTED_BEFORE_PERSISTENCE,
    )


def _reject(category: SafetyCategory, rule_id: str, source_event_id: str) -> None:
    raise MemorySafetyRejection(
        "memory_safety_rejected", _metadata(category, rule_id, source_event_id)
    )


def _bounded(source_event_id: str) -> None:
    raise MemorySafetyRejection(
        "memory_safety_scan_bounded",
        _metadata(SafetyCategory.CREDENTIAL, "scan_bound_v1", source_event_id),
    )


def _classify_name(name: str) -> tuple[SafetyCategory, str] | None:
    normalized = name.casefold().replace("-", "_")
    if normalized in _ENVIRONMENT_SECRET_NAMES:
        return SafetyCategory.CREDENTIAL, "environment_secret_name_v1"
    for pattern, category, rule_id in _STRUCTURAL_RULES:
        if pattern.search(normalized):
            return category, rule_id
    return None


def _classify_text(text: str) -> tuple[SafetyCategory, str] | None:
    normalized = text.casefold().strip()
    if normalized in _ENVIRONMENT_SECRET_NAMES:
        return SafetyCategory.CREDENTIAL, "environment_secret_path_v1"
    if _PRIVATE_KEY_MARKER.search(normalized):
        return SafetyCategory.PRIVATE_KEY, "private_key_material_v1"
    for pattern, category, rule_id in _PREFIX_RULES:
        if pattern.search(normalized):
            return category, rule_id
    for pattern, category, rule_id in _EMBEDDED_CREDENTIAL_RULES:
        if pattern.search(normalized):
            return category, rule_id
    for pattern, category, rule_id in _HIDDEN_TEXT_RULES:
        if pattern.search(normalized):
            return category, rule_id
    return None


def _identity_path(path: tuple[str, ...]) -> bool:
    names = tuple(part for part in path if not part.startswith("["))
    if not names:
        return False
    name = names[-1]
    return (
        name.endswith("_id")
        or name.endswith("_ids")
        or name.endswith("_sha256")
        or name in {
            "content_hashes",
            "evidence_root_ids",
            "lineage_root_ids",
            "semantic_identity_id",
        }
    )


def _looks_high_entropy(text: str) -> bool:
    if not 40 <= len(text) <= MAX_SCALAR_UTF8_BYTES:
        return False
    alphabet = set(text)
    if len(alphabet) < 16 or any(character.isspace() for character in text):
        return False
    counts = Counter(text)
    entropy = -sum(
        (count / len(text)) * log2(count / len(text)) for count in counts.values()
    )
    return entropy >= 4.5


def scan_memory_document(
    value: Mapping[str, Any], *, schema_id: str, source_event_id: str
) -> None:
    """Scan a schema-valid data graph with explicit deterministic work bounds."""

    if (
        not isinstance(schema_id, str)
        or not schema_id.startswith("https://schemas.skeleton.local/v1/")
        or not isinstance(source_event_id, str)
        or len(source_event_id) != 64
        or any(character not in "0123456789abcdef" for character in source_event_id)
    ):
        raise MemorySafetyRejection(
            "memory_safety_context_invalid",
            _metadata(SafetyCategory.CREDENTIAL, "context_invalid_v1", "0" * 64),
        )
    if not isinstance(value, Mapping):
        _bounded(source_event_id)
    stack: list[tuple[tuple[str, ...], Any, int]] = [((), value, 0)]
    visited = 0
    while stack:
        path, current, depth = stack.pop()
        visited += 1
        if visited > MAX_SCAN_NODES or depth > MAX_SCAN_DEPTH:
            _bounded(source_event_id)
        if isinstance(current, Mapping):
            for key, nested in reversed(tuple(current.items())):
                if not isinstance(key, str):
                    _bounded(source_event_id)
                classified = _classify_name(key)
                if classified is not None:
                    _reject(*classified, source_event_id)
                stack.append((path + (key,), nested, depth + 1))
            continue
        if isinstance(current, (list, tuple)):
            for index in range(len(current) - 1, -1, -1):
                stack.append((path + (f"[{index}]",), current[index], depth + 1))
            continue
        if current is None or isinstance(current, (bool, int, float)):
            continue
        if not isinstance(current, str):
            _bounded(source_event_id)
        if len(current.encode("utf-8", errors="strict")) > MAX_SCALAR_UTF8_BYTES:
            _bounded(source_event_id)
        classified = _classify_text(current)
        if classified is not None:
            _reject(*classified, source_event_id)
        if not _identity_path(path) and _looks_high_entropy(current):
            _reject(SafetyCategory.CREDENTIAL, "high_entropy_nonidentity_v1", source_event_id)


def derive_rejection_identity(
    metadata: SafetyRejectionMetadata, *, writer_sequence: int, writer_nonce: str
) -> str:
    """Derive a later writer identity from non-sensitive metadata only."""

    if not isinstance(metadata, SafetyRejectionMetadata):
        raise TypeError("SafetyRejectionMetadata required")
    if type(writer_sequence) is not int or writer_sequence < 0:
        raise ValueError("writer_sequence_invalid")
    if (
        not isinstance(writer_nonce, str)
        or len(writer_nonce) != 64
        or any(character not in "0123456789abcdef" for character in writer_nonce)
    ):
        raise ValueError("writer_nonce_invalid")
    body = canonicalize(
        {
            "category": metadata.category.value,
            "detector_version": metadata.detector_version,
            "disposition": metadata.disposition.value,
            "rule_id": metadata.rule_id,
            "source_event_id": metadata.source_event_id,
            "writer_nonce": writer_nonce,
            "writer_sequence": writer_sequence,
        }
    )
    domain = b"SKELETON_PHASE10_MEMORY_REJECTION_ID_V1"
    framed = len(domain).to_bytes(8, "big") + domain + len(body).to_bytes(8, "big") + body
    return sha256(framed).hexdigest()


__all__ = [
    "DETECTOR_VERSION",
    "MAX_SCAN_DEPTH",
    "MAX_SCAN_NODES",
    "MAX_SCALAR_UTF8_BYTES",
    "MemorySafetyRejection",
    "SafetyCategory",
    "SafetyDisposition",
    "SafetyRejectionMetadata",
    "derive_rejection_identity",
    "scan_memory_document",
]
