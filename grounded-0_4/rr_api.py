"""Grounded 0.4 layer: library API + audited decisions over the frozen engine.

Fixes, additively (zero sealed 0.2/0.3 bytes change), the external review's
confirmed defect classes:

  F3  Ordinary decision receipts do not bind the decision input.
      -> decide_audited() emits an audit extension sealing
         request_raw_sha256 + decision_input_sha256 + the sealed response's
         receipt into one self-zero-sealed object. Materially different
         fact profiles can no longer share an audit seal.
  F5  Semantic failures are poorly auditable (trace computed then dropped).
      -> the audit extension carries the per-class fired map, the matched
         predicate's minimal witness trace (operators + resolved pointers),
         and derived record references.
  F2  (sharpest instances) OBL-30 accepts caller bookkeeping that
      contradicts the caller's own supplied facts.
      -> closures_0_4.json adds tighten-only closure predicates evaluated
         AFTER the frozen table: a closure can turn VALID into a defect
         class, never the reverse. The frozen sealed response is preserved
         verbatim; the 0.4 surface's verdict is `audited_behavior_class`.

The frozen engine remains the single classification authority for the 0.2/0.3
surface: the sealed response embedded in every audited result is byte-identical
to what the frozen runner emits.

The 0.4.2 audit format additionally binds the governing law bytes: every
audited decision carries ``governing_authorities`` (closure-policy, authority-
register, engine-source, and decision-table contract digests) inside the
sealed audit, so decisions produced under different policies or decision
tables are distinguishable by seal (ERRATA E8, E18).
A closure evaluator error on a VALID decision yields ``AUDIT_INCOMPLETE``
instead of silently certifying VALID (ERRATA E9); sealed defect classes
stand, because closures only tighten. 0.4 audit objects remain verifiable
by self-zero recomputation under their own recorded format string.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import sys
import types
from typing import Any

_HERE = pathlib.Path(__file__).resolve().parent
_IMPL3 = _HERE.parent / "baseline-run" / "implementation-output-0.3"
_SUPPLEMENTAL_CONTRACT = (
    _HERE.parent
    / "supplemental-0_3"
    / "control"
    / "B1_SUPPLEMENTAL_COMPARATOR_CONTRACT_0_3.json"
)
_CLOSURE_POLICY = _HERE / "closures_0_4.json"
_AUTHORITY_REGISTER = _HERE / "authority_register_0_4.json"


class RuntimeIntegrityError(RuntimeError):
    """A grounded runtime authority or implementation failed authentication."""


def _read_pinned_bytes(
    path: pathlib.Path,
    expected_length: int,
    expected_sha256: str,
    label: str,
) -> bytes:
    """Read exactly one authenticated file without an unbounded allocation."""
    try:
        with path.open("rb") as stream:
            raw = stream.read(expected_length + 1)
    except OSError as error:
        raise RuntimeIntegrityError(f"cannot read {label}: {error}") from error
    if (
        len(raw) != expected_length
        or hashlib.sha256(raw).hexdigest().upper() != expected_sha256
    ):
        raise RuntimeIntegrityError(f"{label} failed byte authentication")
    return raw


def _load_verified_module(
    name: str,
    path: pathlib.Path,
    expected_length: int,
    expected_sha256: str,
    *,
    aliases: tuple[tuple[str, types.ModuleType], ...] = (),
) -> types.ModuleType:
    """Execute only the verified source bytes, insulated from ambient names."""
    raw = _read_pinned_bytes(path, expected_length, expected_sha256, name)
    module = types.ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = name.rpartition(".")[0]
    module.__spec__ = importlib.util.spec_from_loader(
        name, loader=None, origin=str(path)
    )
    code = compile(raw, str(path), "exec", dont_inherit=True)
    absent = object()
    previous_modules = {
        alias: sys.modules.get(alias, absent) for alias, _target in aliases
    }
    previous_path = list(sys.path)
    sys.modules[name] = module
    for alias, target in aliases:
        sys.modules[alias] = target
    try:
        exec(code, module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    finally:
        sys.path[:] = previous_path
        for alias, previous in previous_modules.items():
            if previous is absent:
                sys.modules.pop(alias, None)
            else:
                sys.modules[alias] = previous
    return module


_CLOSURE_POLICY_RAW = _read_pinned_bytes(
    _CLOSURE_POLICY,
    11733,
    "8FDDCD695989A628C5075A34F45F71F4D286037F924D35F36EE7741636287704",
    "grounded closure policy",
)
_AUTHORITY_REGISTER_RAW = _read_pinned_bytes(
    _AUTHORITY_REGISTER,
    38577,
    "5700FC25BD7875DE66A44648983092182ADC2168529DD4C9ADF5334A625A3B74",
    "grounded authority register",
)
_PRIMARY_CONTRACT_RAW = _read_pinned_bytes(
    _HERE.parent / "baseline-run" / "control" / "B1_PRIMARY_IMPLEMENTER_CONTRACT_0_1.json",
    321451,
    "DCFCB0714E1A7E677548057987F604D227F791F3FC3E0EA89BE5ED932447F48E",
    "accepted 0.2 decision-table contract",
)
_SUPPLEMENTAL_CONTRACT_RAW = _read_pinned_bytes(
    _SUPPLEMENTAL_CONTRACT,
    159277,
    "6B2CAD02DDE7388D63D66E4863E5233CFBD1DC413575D9D260DB9799C7023A12",
    "composed 0.3 authority contract",
)

authority_surface = _load_verified_module(
    "_receiver_reliance_authority_surface",
    _HERE / "authority_surface.py",
    9324,
    "F40348C7DC11B8072BD7202A31359DA38D820DA8F8D7E5C26298100BD810B945",
)
authority_for_operation = authority_surface.authority_for_operation
b1 = _load_verified_module(
    "_receiver_reliance_b1_capabilities",
    _IMPL3 / "b1_capabilities.py",
    50314,
    "4D9FA1C9CCB60B980BCE1739FE8FDC10E84AEFC03D4C20E2AA1A8B0BBE2D18FC",
)
pcb_runner = _load_verified_module(
    "_receiver_reliance_pcb_runner",
    _IMPL3 / "pcb_runner.py",
    19327,
    "83319385C8B6D28965F4683B8C0689FB70158E86ED35D54E7467E8E3DF076E09",
    aliases=(("b1_capabilities", b1),),
)

_authenticated_contract = json.loads(_SUPPLEMENTAL_CONTRACT_RAW)
if b1.jcs_bytes(b1.authority_documents()["contract"]) != b1.jcs_bytes(
    _authenticated_contract
):
    raise RuntimeIntegrityError("composed authority contract changed during loading")

AUDIT_FORMAT = "B1-AUDITED-DECISION-0.4.2"

_CLOSURES: dict[str, list[dict]] = json.loads(_CLOSURE_POLICY_RAW)[
    "closures_by_obligation"
]

# The exact bytes that govern every audited decision this process produces.
# Sealing these digests into each audit makes decisions produced under
# different closure policies, authority registers, engine sources, OR DECISION
# TABLES distinguishable by seal; the repository commit remains the trust root
# that authenticates the digests themselves (TRUST_MODEL.md).
#
# The last of those was missing until 0.4.2, and its absence was the point of
# the field. E8 introduced `governing_authorities` so that decisions produced
# under different governing bytes would be distinguishable by seal -- and then
# sealed the closure policy, the authority register and the two engine SOURCE
# files, but not the contract holding the thirty rows and every predicate atom
# the engine executes. Two parties running different decision tables therefore
# produced byte-identical `governing_authorities`, so a recipient holding an
# envelope could not tell which law decided it. That is provable by
# construction rather than by attack: the digests were computed from four files,
# none of which was a contract, so changing the table could not change the seal.
# A local tamper was still caught, because both contracts are engine-manifest
# rows and `import receiver_reliance` verifies them -- the gap was never local
# forgery, it was cross-party identification, which is exactly what an audit
# envelope is for.
GOVERNING_AUTHORITIES: dict[str, str] = {
    "closure_policy_sha256": hashlib.sha256(_CLOSURE_POLICY_RAW).hexdigest().upper(),
    "authority_register_sha256": hashlib.sha256(_AUTHORITY_REGISTER_RAW).hexdigest().upper(),
    "engine_capabilities_sha256": "4D9FA1C9CCB60B980BCE1739FE8FDC10E84AEFC03D4C20E2AA1A8B0BBE2D18FC",
    "engine_runner_sha256": "83319385C8B6D28965F4683B8C0689FB70158E86ED35D54E7467E8E3DF076E09",
    "decision_table_contract_sha256": hashlib.sha256(_PRIMARY_CONTRACT_RAW).hexdigest().upper(),
    "composed_contract_sha256": hashlib.sha256(_SUPPLEMENTAL_CONTRACT_RAW).hexdigest().upper(),
}

_CLASS_ORDER = ("MALFORMED_OR_BOUNDARY", "BINDING_OR_CONFLICT", "OMISSION_OR_INCOMPLETE")


class _ObjectRequestError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _json_string_length(value: str) -> int:
    """Return exact UTF-8 JSON-string length without allocating the encoding."""
    length = 2
    for character in value:
        codepoint = ord(character)
        if character in ('"', "\\") or character in "\b\f\n\r\t":
            length += 2
        elif codepoint < 0x20:
            length += 6
        elif codepoint < 0x80:
            length += 1
        elif codepoint < 0x800:
            length += 2
        elif 0xD800 <= codepoint <= 0xDFFF:
            raise _ObjectRequestError("ERR_JSON")
        elif codepoint < 0x10000:
            length += 3
        else:
            length += 4
        if length > b1.MAX_INPUT_BYTES:
            raise _ObjectRequestError("ERR_LIMIT")
    return length


def _bounded_object_wire(request: Any) -> bytes:
    """Canonicalize an object iteratively under the frozen wire limits."""
    output = bytearray()
    active_containers: set[int] = set()
    member_count = 0
    stack: list[tuple[str, Any, int]] = [("value", request, 1)]

    def emit(raw: bytes) -> None:
        if len(output) + len(raw) > b1.MAX_INPUT_BYTES:
            raise _ObjectRequestError("ERR_LIMIT")
        output.extend(raw)

    while stack:
        action, value, depth = stack.pop()
        if action == "emit":
            emit(value)
            continue
        if action == "leave":
            active_containers.remove(value)
            continue
        if action == "string":
            encoded_length = _json_string_length(value)
            if len(output) + encoded_length > b1.MAX_INPUT_BYTES:
                raise _ObjectRequestError("ERR_LIMIT")
            try:
                encoded = json.dumps(value, ensure_ascii=False).encode("utf-8")
            except (TypeError, UnicodeError, ValueError):
                raise _ObjectRequestError("ERR_JSON") from None
            emit(encoded)
            continue

        value_type = type(value)
        if value is None:
            emit(b"null")
        elif value_type is bool:
            emit(b"true" if value else b"false")
        elif value_type is int:
            if not b1.SAFE_INTEGER_MIN <= value <= b1.SAFE_INTEGER_MAX:
                raise _ObjectRequestError("ERR_NUMBER")
            emit(str(value).encode("ascii"))
        elif value_type is float:
            raise _ObjectRequestError("ERR_NUMBER")
        elif value_type is str:
            stack.append(("string", value, 0))
        elif value_type is list or value_type is dict:
            if depth > b1.MAX_NESTING:
                raise _ObjectRequestError("ERR_LIMIT")
            identity = id(value)
            if identity in active_containers:
                raise _ObjectRequestError("ERR_JSON")
            container_length = len(value)
            member_count += container_length
            if member_count > b1.MAX_MEMBERS_OR_ITEMS:
                raise _ObjectRequestError("ERR_LIMIT")
            active_containers.add(identity)

            actions: list[tuple[str, Any, int]] = []
            if value_type is list:
                children = tuple(value)
                if len(children) != container_length:
                    raise _ObjectRequestError("ERR_JSON")
                emit(b"[")
                for index, child in enumerate(children):
                    if index:
                        actions.append(("emit", b",", 0))
                    actions.append(("value", child, depth + 1))
                actions.append(("emit", b"]", 0))
            else:
                items = tuple(value.items())
                if len(items) != container_length:
                    raise _ObjectRequestError("ERR_JSON")
                key_wire_bytes = 2 + max(0, container_length - 1) + container_length
                for key, _child in items:
                    if type(key) is not str:
                        raise _ObjectRequestError("ERR_JSON")
                    key_wire_bytes += _json_string_length(key)
                    if len(output) + key_wire_bytes > b1.MAX_INPUT_BYTES:
                        raise _ObjectRequestError("ERR_LIMIT")
                try:
                    items = sorted(
                        items, key=lambda item: item[0].encode("utf-16-be")
                    )
                except UnicodeError:
                    raise _ObjectRequestError("ERR_JSON") from None
                emit(b"{")
                for index, (key, child) in enumerate(items):
                    if index:
                        actions.append(("emit", b",", 0))
                    actions.extend(
                        (
                            ("string", key, 0),
                            ("emit", b":", 0),
                            ("value", child, depth + 1),
                        )
                    )
                actions.append(("emit", b"}", 0))
            actions.append(("leave", identity, 0))
            stack.extend(reversed(actions))
        else:
            raise _ObjectRequestError("ERR_JSON")

    emit(b"\n")
    return bytes(output)


def _prepare_request(request: dict[str, Any] | bytes) -> tuple[bytes | None, str | None]:
    if isinstance(request, bytes):
        return request, None
    try:
        return _bounded_object_wire(request), None
    except _ObjectRequestError as error:
        return None, error.code
    except (KeyError, RuntimeError):
        return None, "ERR_JSON"


def conformance_execute(request: dict[str, Any] | bytes) -> tuple[dict[str, Any], int]:
    """CONFORMANCE-ONLY frozen-engine execution. Not an evidentiary surface.

    Accepts a request object or exact wire bytes; returns (response, exit_code)
    with the response byte-identical (via JCS) to the frozen stdio runner's.
    The sealed response binds no decision facts (ERRATA E2) and applies no
    0.4 closure (E5): use it to reproduce the frozen suites, never to decide.
    Every supported evidentiary decision goes through ``decide_audited``.
    Formerly exported as ``decide``; that supported route is withdrawn
    (deep-scan findings csf_abbd6848 / csf_0479d1a9, 2026-08-16).
    """
    raw, object_error = _prepare_request(request)
    if object_error is not None:
        return pcb_runner._protocol_error(object_error, "")
    assert raw is not None
    return pcb_runner._execute(raw)


# --- closure-predicate evaluation (0.4 additions to the frozen DSL) --------


def _jcs_set(items: list[Any]) -> set[bytes]:
    return {b1.jcs_bytes(item) for item in items}


def _eval_closure_atomic(node: dict[str, Any], doc: Any) -> bool:
    op = node["op"]
    get = lambda path: b1.resolve_input_pointer(doc, path)
    if op == "PROJECTION_NE":
        # {rows_path, key, flag, flag_value, set_path}: true when the set of
        # row[key] for rows whose row[flag] == flag_value differs from the
        # set at set_path — i.e. a supplied projection contradicts the rows
        # it claims to project.
        rows = get(node["rows_path"])
        projected = {
            b1.jcs_bytes(row[node["key"]])
            for row in rows
            if b1._strict_equal(row[node["flag"]], node["flag_value"])
        }
        return projected != _jcs_set(get(node["set_path"]))
    if op == "DERIVED_DIFF_NE":
        # {base_path, subtract_paths, equals_path}: true when
        # set(base) - union(subtractions) differs from the supplied set at
        # equals_path — i.e. supplied bookkeeping contradicts its derivation.
        derived = _jcs_set(get(node["base_path"]))
        for path in node["subtract_paths"]:
            derived -= _jcs_set(get(path))
        return derived != _jcs_set(get(node["equals_path"]))
    if op == "ROW_FIELD_NE_ON_FLAG":
        # {rows_path, key, row_field, flag_rows_path, flag, flag_value,
        # value_path}: true when a row selected by the caller's own flag
        # carries row[row_field] different from the value at value_path —
        # i.e. a row the caller vouched for contradicts the declared fact it
        # was vouched against. Only the flagged rows are compared, so this
        # tightens a caller's positive claim and never converts an unflagged
        # row into one.
        flagged = {
            b1.jcs_bytes(row[node["key"]])
            for row in get(node["flag_rows_path"])
            if b1._strict_equal(row[node["flag"]], node["flag_value"])
        }
        target = get(node["value_path"])
        return any(
            not b1._strict_equal(row[node["row_field"]], target)
            for row in get(node["rows_path"])
            if b1.jcs_bytes(row[node["key"]]) in flagged
        )
    if op == "EDGE_ENDPOINTS_NOT_SUBSET":
        # {edge_paths, from, to, nodes_path}: true when any edge endpoint is
        # absent from the declared node set — the graph the caller submitted
        # is larger than the graph it declared, so every structural predicate
        # over those edges ran on undeclared vertices.
        nodes = _jcs_set(get(node["nodes_path"]))
        for path in node["edge_paths"]:
            for edge in get(path):
                if b1.jcs_bytes(edge[node["from"]]) not in nodes:
                    return True
                if b1.jcs_bytes(edge[node["to"]]) not in nodes:
                    return True
        return False
    # Fall through to the frozen evaluator for every accepted operator, so
    # closures may reuse the frozen vocabulary.
    return b1._eval_atomic(node, doc)


def _eval_closure(node: dict[str, Any], doc: Any) -> bool:
    if "all" in node:
        return all(_eval_closure(child, doc) for child in node["all"])
    if "any" in node:
        return any(_eval_closure(child, doc) for child in node["any"])
    if "not" in node:
        return not _eval_closure(node["not"], doc)
    return _eval_closure_atomic(node, doc)


_OBL30_RUNTIME_BINDINGS = (
    (
        "OBL-30-R1-candidate-pool-record-id-projection",
        "candidate_pool",
        "pool_record_ids",
        "candidate_pool record IDs must equal pool_record_ids",
    ),
    (
        "OBL-30-R2-verdict-record-id-projection",
        "compatibility_verdicts",
        "pool_record_ids",
        "compatibility_verdict record IDs must equal pool_record_ids",
    ),
    (
        "OBL-30-R3-exclusion-record-id-projection",
        "excluded_records",
        "excluded_record_ids",
        "excluded_records record IDs must equal excluded_record_ids",
    ),
)


def _obl30_runtime_binding_findings(
    decision_input: dict[str, Any],
) -> list[dict[str, Any]]:
    """Additive unsealed mitigation for projections absent from frozen policy."""
    facts = decision_input.get("facts")
    if not isinstance(facts, dict):
        return []
    required = {
        field
        for _closure_id, rows_field, ids_field, _statement in _OBL30_RUNTIME_BINDINGS
        for field in (rows_field, ids_field)
    }
    if not required.issubset(facts):
        return []

    findings: list[dict[str, Any]] = []
    for closure_id, rows_field, ids_field, statement in _OBL30_RUNTIME_BINDINGS:
        try:
            row_ids = [row["record_id"] for row in facts[rows_field]]
            fired = _jcs_set(row_ids) != _jcs_set(facts[ids_field])
        except (KeyError, TypeError, b1.EvaluatorError) as error:
            findings.append(
                {
                    "closure_id": closure_id,
                    "fired": False,
                    "evaluator_error": str(error)[:200],
                }
            )
            continue
        if fired:
            findings.append(
                {
                    "closure_id": closure_id,
                    "fired": True,
                    "tightens_to": "MALFORMED_OR_BOUNDARY",
                    "statement": statement,
                }
            )
    return findings


def closure_findings(obligation_id: str, decision_input: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []
    for row in _CLOSURES.get(obligation_id, []):
        try:
            fired = _eval_closure(row["predicate"], decision_input)
        except (b1.EvaluatorError, KeyError, TypeError) as err:
            fired = False
            findings.append(
                {"closure_id": row["closure_id"], "fired": False, "evaluator_error": str(err)[:200]}
            )
            continue
        if fired:
            findings.append(
                {
                    "closure_id": row["closure_id"],
                    "fired": True,
                    "tightens_to": row["tightens_to"],
                    "statement": row["statement"],
                }
            )
    if obligation_id == "OBL-30":
        findings.extend(_obl30_runtime_binding_findings(decision_input))
    return findings


# --- witness tracing over the frozen predicate table -----------------------


def _trace(node: dict[str, Any], doc: Any, out: list[dict[str, Any]]) -> bool:
    """Evaluate exactly like the frozen eval_predicate while recording the
    minimal witness: for `any`, the first true child's atoms; for `all`, every
    child's; for `not`, the child's. Truth values match b1.eval_predicate by
    construction (same operators, same order, same short-circuiting)."""
    if "all" in node:
        collected: list[dict[str, Any]] = []
        for child in node["all"]:
            if not _trace(child, doc, collected):
                return False
        out.extend(collected)
        return True
    if "any" in node:
        for child in node["any"]:
            branch: list[dict[str, Any]] = []
            if _trace(child, doc, branch):
                out.extend(branch)
                return True
        return False
    if "not" in node:
        branch: list[dict[str, Any]] = []
        result = not _trace(node["not"], doc, branch)
        if result:
            out.append({"op": "not", "of": node["not"].get("op", "compound")})
        return result
    fired = b1._eval_atomic(node, doc)
    if fired:
        pointers = sorted(
            {
                value
                for key, value in node.items()
                if isinstance(value, str) and value.startswith("/")
            }
            | {
                item
                for key, value in node.items()
                if isinstance(value, list)
                for item in value
                if isinstance(item, str) and item.startswith("/")
            }
        )
        out.append({"op": node["op"], "pointers": pointers})
    return fired


def _classify_traced(
    operation_handle: str,
    decision_input: dict[str, Any],
    sealed_class: str,
) -> tuple[str, dict[str, bool], list[dict[str, Any]]]:
    """Classify once while retaining the selected predicate's witness.

    This mirrors ``b1.classify`` precedence and short-circuiting.  The frozen
    response's class identifies the one predicate that needs witness
    instrumentation; preceding predicates still run through the frozen
    evaluator, so an earlier match or a false sealed predicate is detected by
    the existing sealed-class cross-check.  The selected predicate is traced
    instead of first being classified and then evaluated a second time.
    """
    predicates = b1.decision_table()[operation_handle]
    first_match: dict[str, bool] = {}
    matched: str | None = None
    witness: list[dict[str, Any]] = []
    for class_name in _CLASS_ORDER:
        if matched is None:
            if class_name == sealed_class:
                branch: list[dict[str, Any]] = []
                fired = _trace(predicates[class_name], decision_input, branch)
            else:
                branch = []
                fired = b1.eval_predicate(predicates[class_name], decision_input)
            first_match[class_name] = fired
            if fired:
                matched = class_name
                if class_name == sealed_class:
                    witness = branch
        else:
            first_match[class_name] = False
    return matched or "VALID", first_match, witness


def _derive_record_references_full(facts: Any) -> tuple[list[str], bool]:
    """Return (capped references, truncated?) — GEN_0_5 §4.5 semantics.

    ``truncated`` is True exactly when the derived candidate set exceeded the
    64-item output cap, so the cap is disclosed instead of silent (Intake 10
    finding; the 0.5 continuation spec already pins this flag)."""
    refs = derive_record_references(facts)
    return refs, len(refs) == 64 and len(_collect_record_references(facts)) > 64


def _collect_record_references(facts: Any) -> set[str]:
    found: set[str] = set()

    def walk(node: Any, key: str) -> None:
        if isinstance(node, dict):
            for child_key, child in node.items():
                walk(child, child_key)
        elif isinstance(node, list):
            if key.endswith("_record_ids") or key == "pool_record_ids":
                found.update(x for x in node if isinstance(x, str))
            else:
                for item in node:
                    walk(item, key)
        elif isinstance(node, str):
            if "record_id" in key or key == "exact_reference":
                found.add(node)

    walk(facts, "")
    return found


def derive_record_references(facts: Any, prefix: str = "") -> list[str]:
    """Deterministic extraction of record identifiers actually present in the
    fact profile: string leaves whose key names a record id (contains
    'record_id' or is 'exact_reference'), and string items of arrays whose
    key ends with '_record_ids'. Sorted, deduplicated, capped at 64."""
    found: set[str] = set()

    def walk(node: Any, key: str) -> None:
        if isinstance(node, dict):
            for child_key, child in node.items():
                walk(child, child_key)
        elif isinstance(node, list):
            if key.endswith("_record_ids") or key == "pool_record_ids":
                found.update(x for x in node if isinstance(x, str))
            else:
                for item in node:
                    walk(item, key)
        elif isinstance(node, str):
            if "record_id" in key or key == "exact_reference":
                found.add(node)

    walk(facts, "")
    return sorted(found)[:64]


def decide_audited(request: dict[str, Any] | bytes) -> dict[str, Any]:
    """Frozen decision + input-bound, trace-carrying audit extension."""
    raw, object_error = _prepare_request(request)
    if object_error is None:
        assert raw is not None
        response, exit_code = pcb_runner._execute(raw)
    else:
        response, exit_code = pcb_runner._protocol_error(object_error, "")
    audited: dict[str, Any] = {
        "format_version": AUDIT_FORMAT,
        "sealed_response": response,
        "exit_code": exit_code,
        "audit": None,
        "audited_behavior_class": None,
        "audit_sha256": b1.ZERO64,
    }
    audit: dict[str, Any] = {
        "request_raw_sha256": b1.sha256_upper(raw) if raw is not None else None,
        "engine_generation": "composed-0.3-frozen",
        "governing_authorities": dict(GOVERNING_AUTHORITIES),
    }
    if object_error is not None:
        audit["object_request_error"] = object_error
    if response.get("ok"):
        assert raw is not None
        parsed = json.loads(raw.decode("utf-8"))
        semantic = parsed["semantic_request"] if "semantic_request" in parsed else parsed
        decision_input = semantic["decision_input"]
        obligation_id = semantic["obligation_id"]
        operation_handle = semantic["operation_handle"]
        audit["decision_input_sha256"] = b1.sha256_upper(b1.jcs_bytes(decision_input))
        output = response.get("output") or {}
        sealed_class = (
            (output.get("result_object") or {}).get("behavior_class")
            or (output.get("payload") or {}).get("behavior_class")
        )
        behavior, fired_map, witness = _classify_traced(
            operation_handle, decision_input, sealed_class
        )
        if behavior != sealed_class:  # defense in depth; must never happen
            raise RuntimeError("trace classification diverged from sealed response")
        audit["first_match_predicates"] = fired_map
        audit["matched_class_witness"] = witness
        refs, refs_truncated = _derive_record_references_full(decision_input.get("facts"))
        audit["record_references"] = refs
        audit["record_references_truncated"] = refs_truncated
        findings = closure_findings(obligation_id, decision_input)
        audit["closure_findings"] = findings
        tightened = [f["tightens_to"] for f in findings if f.get("fired")]
        if behavior == "VALID" and any("evaluator_error" in f for f in findings):
            # A VALID class cannot be certified by an incomplete closure
            # pass: an errored closure might have tightened it (ERRATA E9).
            # Sealed defect classes stand — closures only tighten.
            final = "AUDIT_INCOMPLETE"
        elif behavior == "VALID" and tightened:
            final = min(tightened, key=_CLASS_ORDER.index)
        else:
            final = behavior
        audited["audited_behavior_class"] = final
    else:
        audit["decision_input_sha256"] = None
        audit["errors"] = response.get("errors")
        audited["audited_behavior_class"] = "PROTOCOL_ERROR"
    audited["audit"] = audit
    audited["audit_sha256"] = b1.self_zero_sha256(audited, "audit_sha256")
    return audited
