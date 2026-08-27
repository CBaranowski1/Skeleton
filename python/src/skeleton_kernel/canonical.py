"""RFC 8785/JCS canonicalization guarded by strict bytes-first I-JSON parsing."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, TypeAlias

import jcs


JSONScalar: TypeAlias = None | bool | int | float | str
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]

MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 64
MAX_STRING_CODEPOINTS = 1_000_000
MAX_COLLECTION_ITEMS = 100_000
MAX_SAFE_INTEGER = 9_007_199_254_740_991


@dataclass(frozen=True, slots=True)
class CanonicalizationError(ValueError):
    """Stable fail-closed error for raw parsing and canonicalization."""

    code: str
    message: str
    path: tuple[str | int, ...] = ()

    def __str__(self) -> str:
        location = "".join(
            f"[{part}]" if isinstance(part, int) else f".{part}" for part in self.path
        )
        return f"{self.code}{location}: {self.message}"


class _ObjectPairs(list[tuple[str, Any]]):
    """Distinguish JSON objects from arrays until duplicate checks finish."""


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _reject_constant(token: str) -> Any:
    raise CanonicalizationError(
        "non_finite_number",
        f"non-I-JSON numeric token {token!r}",
    )


def _decode_raw(raw: bytes) -> str:
    if not isinstance(raw, bytes):
        raise TypeError("raw JSON input must be bytes")
    if len(raw) > MAX_INPUT_BYTES:
        raise CanonicalizationError(
            "input_too_large",
            f"raw input exceeds {MAX_INPUT_BYTES} bytes",
        )
    if raw.startswith(b"\xef\xbb\xbf"):
        raise CanonicalizationError("bom_not_allowed", "UTF-8 BOM is not permitted")
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise CanonicalizationError(
            "invalid_utf8",
            f"invalid UTF-8 at byte {error.start}",
        ) from error


def _validate_string(value: str, path: tuple[str | int, ...]) -> None:
    if len(value) > MAX_STRING_CODEPOINTS:
        raise CanonicalizationError(
            "string_too_large",
            f"string exceeds {MAX_STRING_CODEPOINTS} code points",
            path,
        )
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise CanonicalizationError(
            "lone_surrogate",
            "UTF-16 surrogate code points are outside I-JSON",
            path,
        )


def _from_pairs(
    value: Any,
    *,
    path: tuple[str | int, ...] = (),
    depth: int = 0,
) -> JSONValue:
    if depth > MAX_DEPTH:
        raise CanonicalizationError(
            "maximum_depth_exceeded",
            f"JSON nesting exceeds {MAX_DEPTH}",
            path,
        )
    if isinstance(value, _ObjectPairs):
        if len(value) > MAX_COLLECTION_ITEMS:
            raise CanonicalizationError(
                "collection_too_large",
                f"object exceeds {MAX_COLLECTION_ITEMS} members",
                path,
            )
        result: dict[str, JSONValue] = {}
        for key, item in value:
            _validate_string(key, path + (key,))
            if key in result:
                raise CanonicalizationError(
                    "duplicate_member",
                    f"duplicate JSON member {key!r}",
                    path + (key,),
                )
            result[key] = _from_pairs(
                item,
                path=path + (key,),
                depth=depth + 1,
            )
        return result
    if isinstance(value, list):
        if len(value) > MAX_COLLECTION_ITEMS:
            raise CanonicalizationError(
                "collection_too_large",
                f"array exceeds {MAX_COLLECTION_ITEMS} items",
                path,
            )
        return [
            _from_pairs(item, path=path + (index,), depth=depth + 1)
            for index, item in enumerate(value)
        ]
    _validate_value(value, path=path, depth=depth)
    return value


def _validate_value(
    value: Any,
    *,
    path: tuple[str | int, ...] = (),
    depth: int = 0,
) -> None:
    if depth > MAX_DEPTH:
        raise CanonicalizationError(
            "maximum_depth_exceeded",
            f"JSON nesting exceeds {MAX_DEPTH}",
            path,
        )
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise CanonicalizationError(
                "unsafe_integer",
                "integer exceeds the exact binary64 safe range",
                path,
            )
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalizationError(
                "non_finite_number",
                "only finite binary64 values are permitted",
                path,
            )
        return
    if isinstance(value, str):
        _validate_string(value, path)
        return
    if isinstance(value, list):
        if len(value) > MAX_COLLECTION_ITEMS:
            raise CanonicalizationError(
                "collection_too_large",
                f"array exceeds {MAX_COLLECTION_ITEMS} items",
                path,
            )
        for index, item in enumerate(value):
            _validate_value(item, path=path + (index,), depth=depth + 1)
        return
    if isinstance(value, Mapping):
        if len(value) > MAX_COLLECTION_ITEMS:
            raise CanonicalizationError(
                "collection_too_large",
                f"object exceeds {MAX_COLLECTION_ITEMS} members",
                path,
            )
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(
                    "invalid_object_key",
                    "JSON object member names must be strings",
                    path,
                )
            _validate_string(key, path + (key,))
            _validate_value(item, path=path + (key,), depth=depth + 1)
        return
    raise CanonicalizationError(
        "invalid_json_type",
        f"{type(value).__name__} is not an I-JSON value",
        path,
    )


def parse_raw_json(raw: bytes) -> JSONValue:
    """Parse untrusted bytes while retaining object pairs until duplicate rejection."""

    text = _decode_raw(raw)
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_ObjectPairs,
            parse_constant=_reject_constant,
        )
    except CanonicalizationError:
        raise
    except json.JSONDecodeError as error:
        raise CanonicalizationError(
            "invalid_json",
            f"invalid JSON at character {error.pos}",
        ) from error
    return _from_pairs(parsed)


def canonicalize(value: JSONValue) -> bytes:
    """Return exact RFC 8785 UTF-8 bytes after enforcing the I-JSON profile."""

    _validate_value(value)
    try:
        result = _canonicalize_value(value)
    except (OverflowError, TypeError, ValueError, UnicodeError) as error:
        raise CanonicalizationError(
            "canonicalization_failed",
            str(error),
        ) from error
    if not isinstance(result, bytes):
        raise CanonicalizationError(
            "canonicalization_failed",
            "pinned JCS implementation did not return bytes",
        )
    if result.startswith(b"\xef\xbb\xbf") or result.endswith(b"\n"):
        raise CanonicalizationError(
            "canonicalization_failed",
            "canonical bytes contain a BOM or final newline",
        )
    return result


def _utf16_sort_key(value: str) -> bytes:
    """Return the unsigned UTF-16 code-unit ordering key required by RFC 8785."""

    return value.encode("utf-16-be", errors="strict")


def _canonicalize_value(value: JSONValue) -> bytes:
    """Compose JCS primitives while applying the RFC's UTF-16 member ordering."""

    if isinstance(value, dict):
        members = []
        for key in sorted(value, key=_utf16_sort_key):
            members.append(
                jcs.canonicalize(key) + b":" + _canonicalize_value(value[key])
            )
        return b"{" + b",".join(members) + b"}"
    if isinstance(value, list):
        return b"[" + b",".join(_canonicalize_value(item) for item in value) + b"]"
    return jcs.canonicalize(value)


def canonicalize_raw(raw: bytes) -> bytes:
    return canonicalize(parse_raw_json(raw))


def canonical_sha256(value: JSONValue) -> str:
    return sha256_hex(canonicalize(value))
