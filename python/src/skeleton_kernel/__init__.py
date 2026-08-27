"""Skeleton's strict, domain-neutral Python contract oracle."""

from .canonical import (
    CanonicalizationError,
    canonical_sha256,
    canonicalize,
    canonicalize_raw,
    parse_raw_json,
    sha256_hex,
)
from .schema_registry import SchemaRegistry, ValidatedDocument
from .models import (
    FrozenObject,
    ProtocolModel,
    SchemaId,
    validate_then_model,
)

__all__ = [
    "CanonicalizationError",
    "FrozenObject",
    "ProtocolModel",
    "SchemaRegistry",
    "SchemaId",
    "ValidatedDocument",
    "canonical_sha256",
    "canonicalize",
    "canonicalize_raw",
    "parse_raw_json",
    "sha256_hex",
    "validate_then_model",
]
