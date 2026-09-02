"""Runtime field-authority queries over the canonical 0.4 register.

The JSON register is the only store of per-field authority values.  Public
queries read it afresh, authenticate the runtime bytes, validate that operation
selectors are unambiguous, and return copies of the selected register row.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
from typing import Any


HERE = pathlib.Path(__file__).resolve().parent
AUTHORITY_REGISTER_PATH = HERE / "authority_register_0_4.json"
AUTHORITY_REGISTER_FORMAT = "B1-AUTHORITY-REGISTER-0.4"
AUTHORITY_REGISTER_BYTES = 38577
AUTHORITY_REGISTER_SHA256 = (
    "5700FC25BD7875DE66A44648983092182ADC2168529DD4C9ADF5334A625A3B74"
)
# `semantic` and `presence_only` name authority held by the FROZEN decision
# table; `semantic_closure` and `presence_only_closure` name authority held by
# a 0.4 closure predicate, which is tighten-only and therefore a strictly
# weaker claim. They are distinct status strings rather than a widening of
# `semantic` so that a consumer pinned to the published meaning of `semantic`
# sees an unknown status and looks, instead of silently inheriting a different
# guarantee. An older pinned copy of this module rejects the newer register
# outright, which is the intended failure direction.
AUTHORITY_STATUSES = frozenset(
    {
        "semantic",
        "semantic_closure",
        "presence_only",
        "presence_only_closure",
        "inert_disclosed",
        "inert_registered_debt",
    }
)
_MAX_REGISTER_BYTES = 1024 * 1024
_MAX_REGISTER_NESTING = 64


class AuthorityRegisterError(ValueError):
    """The canonical authority register cannot define an unambiguous surface."""


def _nonempty_string(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value:
        raise AuthorityRegisterError(f"{location} must be a nonempty string")
    return value


def _check_json_nesting(raw: bytes) -> None:
    """Reject excessive JSON nesting before ``json.loads`` allocates a tree."""
    depth = 0
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in (0x5B, 0x7B):
            depth += 1
            if depth > _MAX_REGISTER_NESTING:
                raise AuthorityRegisterError(
                    "authority register exceeds the JSON nesting limit"
                )
        elif byte in (0x5D, 0x7D):
            depth -= 1


def _validate_register(register: Any) -> dict[str, Any]:
    if not isinstance(register, dict):
        raise AuthorityRegisterError("authority register must be a JSON object")
    format_version = _nonempty_string(register.get("format_version"), "format_version")
    if format_version != AUTHORITY_REGISTER_FORMAT:
        raise AuthorityRegisterError(
            f"unsupported authority register format_version: {format_version}"
        )
    operations = register.get("operations")
    if not isinstance(operations, list):
        raise AuthorityRegisterError("operations must be an array")

    obligation_ids: set[str] = set()
    operation_handles: set[str] = set()
    for operation_index, operation in enumerate(operations):
        location = f"operations[{operation_index}]"
        if not isinstance(operation, dict):
            raise AuthorityRegisterError(f"{location} must be an object")
        obligation_id = _nonempty_string(
            operation.get("obligation_id"), f"{location}.obligation_id"
        )
        operation_handle = _nonempty_string(
            operation.get("operation_handle"), f"{location}.operation_handle"
        )
        if obligation_id in obligation_ids:
            raise AuthorityRegisterError(f"duplicate obligation_id: {obligation_id}")
        if operation_handle in operation_handles:
            raise AuthorityRegisterError(f"duplicate operation_handle: {operation_handle}")
        if obligation_id in operation_handles or operation_handle in obligation_ids:
            collision = (
                obligation_id if obligation_id in operation_handles else operation_handle
            )
            raise AuthorityRegisterError(
                "cross-namespace operation selector collision: " + collision
            )
        if obligation_id == operation_handle:
            raise AuthorityRegisterError(
                "cross-namespace operation selector collision: " + obligation_id
            )
        obligation_ids.add(obligation_id)
        operation_handles.add(operation_handle)

        fields = operation.get("fields")
        if not isinstance(fields, list):
            raise AuthorityRegisterError(f"{location}.fields must be an array")
        field_names: set[str] = set()
        for field_index, field in enumerate(fields):
            field_location = f"{location}.fields[{field_index}]"
            if not isinstance(field, dict):
                raise AuthorityRegisterError(f"{field_location} must be an object")
            field_name = _nonempty_string(
                field.get("field"), f"{field_location}.field"
            )
            status = _nonempty_string(field.get("status"), f"{field_location}.status")
            if status not in AUTHORITY_STATUSES:
                raise AuthorityRegisterError(
                    f"unsupported {field_location}.status: {status}"
                )
            _nonempty_string(field.get("rationale"), f"{field_location}.rationale")
            if field_name in field_names:
                raise AuthorityRegisterError(
                    f"duplicate field in {obligation_id}: {field_name}"
                )
            field_names.add(field_name)
    return register


def read_authority_register(
    path: pathlib.Path | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Read and validate a register, returning its exact bytes and JSON value.

    ``path`` exists for deterministic generation and isolated tests.  Runtime
    authority queries omit it and therefore always use the adjacent canonical
    register.
    """
    authenticate = path is None
    source = AUTHORITY_REGISTER_PATH if authenticate else pathlib.Path(path)
    try:
        with source.open("rb") as stream:
            raw = stream.read(_MAX_REGISTER_BYTES + 1)
        if len(raw) > _MAX_REGISTER_BYTES:
            raise AuthorityRegisterError(
                f"authority register exceeds {_MAX_REGISTER_BYTES} bytes"
            )
        if authenticate and (
            len(raw) != AUTHORITY_REGISTER_BYTES
            or hashlib.sha256(raw).hexdigest().upper() != AUTHORITY_REGISTER_SHA256
        ):
            raise AuthorityRegisterError(
                "canonical authority register failed byte authentication"
            )
        _check_json_nesting(raw)
        register = json.loads(raw)
    except AuthorityRegisterError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise AuthorityRegisterError(
            f"cannot read authority register {source}: {error}"
        ) from error
    return raw, _validate_register(register)


def _surface(operation: dict[str, Any], format_version: str) -> dict[str, Any]:
    return {
        "authority_register_format_version": format_version,
        "obligation_id": operation["obligation_id"],
        "operation_handle": operation["operation_handle"],
        "fields": [
            {
                "field": field["field"],
                "status": field["status"],
                "rationale": field["rationale"],
            }
            for field in operation["fields"]
        ],
    }


def all_operation_authorities(
    register: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Return every operation's field-authority surface from one register read."""
    if register is None:
        _raw, register = read_authority_register()
    else:
        register = _validate_register(register)
    format_version = register["format_version"]
    return [_surface(operation, format_version) for operation in register["operations"]]


def authority_for_operation(operation: str) -> dict[str, Any]:
    """Return every required fact field's classification authority.

    ``operation`` may be an exact obligation ID (for example ``OBL-08``) or
    operation handle.  The canonical JSON register is read on every call, so
    this API cannot drift behind the artifact it reports.  Unknown selectors
    raise ``KeyError``; non-string selectors raise ``TypeError``.
    """
    if not isinstance(operation, str):
        raise TypeError("operation must be an obligation ID or operation handle string")
    surfaces = all_operation_authorities()
    matches = [
        surface
        for surface in surfaces
        if operation in (surface["obligation_id"], surface["operation_handle"])
    ]
    if not matches:
        raise KeyError(f"unknown authority operation: {operation}")
    if len(matches) != 1:  # protected by register validation; defense in depth
        raise AuthorityRegisterError(f"ambiguous authority operation: {operation}")
    return matches[0]
