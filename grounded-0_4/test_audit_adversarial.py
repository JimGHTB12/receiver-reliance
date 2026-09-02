"""Adversarial checks for the grounded 0.4 audited decision surface.

The operator matrices are exhaustive bounded products, not randomized tests;
therefore no random seed is used or required.  The suite intentionally treats
the public ``derive_record_references`` docstring as the extraction contract.

Exit 0 with ``failures=0`` on success.  Failure output is capped so a large
truth-table regression remains concise.
"""
from __future__ import annotations

import base64
import copy
import itertools
import json
import pathlib
import sys
from collections.abc import Callable, Iterable, Iterator, Sequence
from typing import Any

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))

import rr_api  # noqa: E402
from rr_api import b1  # noqa: E402


PACKS = (
    REPO / "baseline-run/fixtures/PRIMARY_BASELINE_SEMANTIC_FIXTURE_PACK_0_2.json",
    REPO / "supplemental-0_3/fixtures/B1_SUPPLEMENTAL_SEMANTIC_FIXTURE_PACK_0_3.json",
)
MAX_FAILURE_DETAILS = 20

checks = 0
failure_count = 0
failures: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    global checks, failure_count
    checks += 1
    if not condition:
        failure_count += 1
        suffix = f" -- {detail}" if detail else ""
        if len(failures) < MAX_FAILURE_DETAILS:
            failures.append(f"FAIL {name}{suffix}")


def load_entry(token: str) -> tuple[dict[str, Any], bytes, bytes]:
    for path in PACKS:
        with path.open(encoding="utf-8") as fh:
            pack = json.load(fh)
        for entry in pack["entries"]:
            if token in entry["entry_id"]:
                raw = base64.b64decode(entry["semantic_request_jcs_lf_base64"])
                expected = base64.b64decode(entry["expected_response_jcs_lf_base64"])
                return entry, raw, expected
    raise AssertionError(f"fixture token not found: {token}")


def verify_audit(value: dict[str, Any]) -> bool:
    stored = value.get("audit_sha256")
    return (
        isinstance(stored, str)
        and len(stored) == 64
        and stored == b1.self_zero_sha256(value, "audit_sha256")
    )


def bounded_sequences(values: Sequence[Any], max_length: int) -> Iterator[tuple[Any, ...]]:
    for length in range(max_length + 1):
        yield from itertools.product(values, repeat=length)


def fired_ids(findings: Iterable[dict[str, Any]]) -> set[str]:
    return {row["closure_id"] for row in findings if row.get("fired")}


INTENT_TUPLE = {
    "episode_id": "EPISODE_001",
    "purpose_id": "PURPOSE_A",
    "scope_ref": "SCOPE_A",
    "action_class": "ACTION_CLASS_A",
    "version_sha256": "C" * 63 + "1",
}


def closure_facts(
    verdicts: list[dict[str, Any]],
    compatible: list[str],
    incompatible: list[str],
    selected: list[str],
    excluded: list[str],
    undispositioned: list[str],
) -> dict[str, Any]:
    """Build a synthetic OBL-30 fact profile the whole closure set can read.

    The candidate pool is derived from the verdict rows and every row carries
    the declared intent tuple, so the intent-agreement closures are quiet by
    construction and these cases keep testing exactly what they were written
    to test: the projection and derivation closures over the id sets. A pool
    row is emitted per verdict row rather than per distinct id, so the
    duplicate case still presents duplicates to both.
    """
    return {
        "facts": {
            "candidate_pool": [
                {
                    "record_id": verdict["record_id"],
                    "similarity_rank": index + 1,
                    **INTENT_TUPLE,
                }
                for index, verdict in enumerate(verdicts)
            ],
            "pool_record_ids": [verdict["record_id"] for verdict in verdicts],
            "intent_episode_id": INTENT_TUPLE["episode_id"],
            "intent_purpose_id": INTENT_TUPLE["purpose_id"],
            "intent_scope_ref": INTENT_TUPLE["scope_ref"],
            "intent_action_class": INTENT_TUPLE["action_class"],
            "intent_version_sha256": INTENT_TUPLE["version_sha256"],
            "compatibility_verdicts": verdicts,
            "compatible_record_ids": compatible,
            "incompatible_record_ids": incompatible,
            "selected_record_ids": selected,
            "excluded_record_ids": excluded,
            "undispositioned_compatible_record_ids": undispositioned,
        }
    }


# 1. Representative frozen VALID requests remain sealed and auditable.
valid_results: dict[str, dict[str, Any]] = {}
for token in ("OBL-01-IO", "OBL-22-IO", "OBL-30-IO"):
    entry, raw, expected = load_entry(token)
    audited = rr_api.decide_audited(raw)
    valid_results[token] = audited
    sealed_raw = b1.jcs_bytes(audited["sealed_response"]) + b"\n"
    check(f"fixture:{token}:sealed-parity", sealed_raw == expected, entry["entry_id"])
    check(f"fixture:{token}:audit-verifies", verify_audit(audited), entry["entry_id"])
    check(
        f"fixture:{token}:valid",
        audited["audited_behavior_class"] == "VALID",
        str(audited["audited_behavior_class"]),
    )


# 2. Recomputing the self-zero seal detects mutations across every bound layer.
seal_base = valid_results["OBL-30-IO"]


def set_audit_raw_digest(value: dict[str, Any]) -> None:
    value["audit"]["request_raw_sha256"] = "0" * 64


def set_input_digest(value: dict[str, Any]) -> None:
    value["audit"]["decision_input_sha256"] = "1" * 64


def change_witness(value: dict[str, Any]) -> None:
    value["audit"]["matched_class_witness"].append({"op": "TAMPER", "pointers": []})


def change_references(value: dict[str, Any]) -> None:
    value["audit"]["record_references"].append("REC_TAMPER")


def change_findings(value: dict[str, Any]) -> None:
    value["audit"]["closure_findings"].append(
        {"closure_id": "TAMPER", "fired": True, "tightens_to": "BINDING_OR_CONFLICT"}
    )


def change_sealed_receipt(value: dict[str, Any]) -> None:
    value["sealed_response"]["receipt_sha256"] = "2" * 64


def change_audited_class(value: dict[str, Any]) -> None:
    value["audited_behavior_class"] = "OMISSION_OR_INCOMPLETE"


def change_exit_code(value: dict[str, Any]) -> None:
    value["exit_code"] = 99


def change_stored_seal(value: dict[str, Any]) -> None:
    value["audit_sha256"] = "3" * 64


tamper_cases: tuple[tuple[str, Callable[[dict[str, Any]], None]], ...] = (
    ("request-raw-digest", set_audit_raw_digest),
    ("decision-input-digest", set_input_digest),
    ("witness", change_witness),
    ("record-references", change_references),
    ("closure-findings", change_findings),
    ("sealed-receipt", change_sealed_receipt),
    ("audited-class", change_audited_class),
    ("exit-code", change_exit_code),
    ("stored-seal", change_stored_seal),
)

for name, mutate in tamper_cases:
    candidate = copy.deepcopy(seal_base)
    mutate(candidate)
    recomputed = b1.self_zero_sha256(candidate, "audit_sha256")
    check(f"seal-tamper:{name}:rejected", not verify_audit(candidate), recomputed)
    if name != "stored-seal":
        check(
            f"seal-tamper:{name}:changes-preimage",
            recomputed != seal_base["audit_sha256"],
            recomputed,
        )


# 3. Witnesses and their containing audit object are byte-deterministic.
for token in ("OBL-22-INV", "OBL-22-CTRL", "OBL-22-FAIL", "OBL-30-IO"):
    entry, raw, _expected = load_entry(token)
    first = rr_api.decide_audited(raw)
    first_witness = b1.jcs_bytes(first["audit"]["matched_class_witness"])
    first_fired = b1.jcs_bytes(first["audit"]["first_match_predicates"])
    first_all = b1.jcs_bytes(first)
    for repeat in range(8):
        again = rr_api.decide_audited(raw)
        check(
            f"witness:{token}:repeat-{repeat}:bytes",
            b1.jcs_bytes(again["audit"]["matched_class_witness"]) == first_witness,
            entry["entry_id"],
        )
        check(
            f"witness:{token}:repeat-{repeat}:fired-map",
            b1.jcs_bytes(again["audit"]["first_match_predicates"]) == first_fired,
            entry["entry_id"],
        )
        check(
            f"witness:{token}:repeat-{repeat}:whole-audit",
            b1.jcs_bytes(again) == first_all,
            entry["entry_id"],
        )
    if token.endswith("IO"):
        check(f"witness:{token}:valid-empty", first_witness == b"[]", first_witness.decode())
    else:
        check(f"witness:{token}:defect-nonempty", first_witness != b"[]", first_witness.decode())
    for atom in first["audit"]["matched_class_witness"]:
        pointers = atom.get("pointers")
        if pointers is not None:
            check(
                f"witness:{token}:sorted-pointers:{atom['op']}",
                pointers == sorted(set(pointers)),
                str(pointers),
            )


# 4. Closure integration: empty, exact-256, duplicate, and Unicode cases.
empty_input = closure_facts([], [], [], [], [], [])
check(
    "closure:empty-pools:quiet",
    rr_api.closure_findings("OBL-30", empty_input) == [],
    str(rr_api.closure_findings("OBL-30", empty_input)),
)

ids_256 = [f"记录_{index:03d}_🧪" for index in range(256)]
verdicts_256 = [
    {"record_id": record_id, "compatible": index % 2 == 0}
    for index, record_id in enumerate(ids_256)
]
compatible_256 = ids_256[::2]
incompatible_256 = ids_256[1::2]
cap_input = closure_facts(
    verdicts_256,
    compatible_256,
    incompatible_256,
    compatible_256.copy(),
    [],
    [],
)
check(
    "closure:256-items:consistent",
    rr_api.closure_findings("OBL-30", cap_input) == [],
    str(rr_api.closure_findings("OBL-30", cap_input)),
)

cap_mismatch = copy.deepcopy(cap_input)
cap_mismatch["facts"]["compatibility_verdicts"][-1]["compatible"] = True
cap_fired = fired_ids(rr_api.closure_findings("OBL-30", cap_mismatch))
check(
    "closure:256-items:last-row-bound",
    cap_fired
    == {
        "OBL-30-C1-verdict-projection-agreement-compatible",
        "OBL-30-C2-verdict-projection-agreement-incompatible",
    },
    str(sorted(cap_fired)),
)

duplicate_input = closure_facts(
    [
        {"record_id": "REC_A", "compatible": True},
        {"record_id": "REC_A", "compatible": True},
        {"record_id": "REC_B", "compatible": False},
        {"record_id": "REC_B", "compatible": False},
    ],
    ["REC_A", "REC_A"],
    ["REC_B", "REC_B"],
    ["REC_A", "REC_A"],
    ["REC_B", "REC_B"],
    [],
)
check(
    "closure:duplicates:set-semantics",
    rr_api.closure_findings("OBL-30", duplicate_input) == [],
    str(rr_api.closure_findings("OBL-30", duplicate_input)),
)

unicode_ids = ["é", "e\u0301", "Ω", "记录", "🧪"]
unicode_input = closure_facts(
    [{"record_id": value, "compatible": True} for value in unicode_ids],
    unicode_ids.copy(),
    [],
    unicode_ids.copy(),
    [],
    [],
)
check(
    "closure:unicode:exact-codepoints-consistent",
    rr_api.closure_findings("OBL-30", unicode_input) == [],
    str(rr_api.closure_findings("OBL-30", unicode_input)),
)
unicode_mismatch = copy.deepcopy(unicode_input)
unicode_mismatch["facts"]["compatible_record_ids"].remove("e\u0301")
unicode_fired = fired_ids(rr_api.closure_findings("OBL-30", unicode_mismatch))
check(
    "closure:unicode:no-implicit-normalization",
    "OBL-30-C1-verdict-projection-agreement-compatible" in unicode_fired,
    str(sorted(unicode_fired)),
)


# 5. Complete bounded truth tables for PROJECTION_NE and DERIVED_DIFF_NE.
projection_node = {
    "op": "PROJECTION_NE",
    "rows_path": "/rows",
    "key": "id",
    "flag": "flag",
    "flag_value": True,
    "set_path": "/supplied",
}
row_options = tuple(itertools.product(("A", "B"), (True, False, 1, None)))
row_sequences = tuple(bounded_sequences(row_options, 2))
supplied_sequences = tuple(bounded_sequences(("A", "B", "C"), 2))

for flag_value in (True, False):
    projection_node["flag_value"] = flag_value
    for row_sequence in row_sequences:
        rows = [{"id": record_id, "flag": flag} for record_id, flag in row_sequence]
        oracle_projection = {
            record_id
            for record_id, flag in row_sequence
            if type(flag) is bool and flag is flag_value
        }
        for supplied in supplied_sequences:
            expected = oracle_projection != set(supplied)
            actual = rr_api._eval_closure_atomic(
                projection_node, {"rows": rows, "supplied": list(supplied)}
            )
            check(
                "truth-table:PROJECTION_NE",
                actual is expected,
                f"flag={flag_value!r} rows={row_sequence!r} supplied={supplied!r}",
            )

derived_node = {
    "op": "DERIVED_DIFF_NE",
    "base_path": "/base",
    "subtract_paths": ["/subtract_a", "/subtract_b"],
    "equals_path": "/equals",
}
ab_sequences = tuple(bounded_sequences(("A", "B"), 2))
equals_sequences = tuple(bounded_sequences(("A", "B", "C"), 2))
for base in ab_sequences:
    for subtract_a in ab_sequences:
        for subtract_b in ab_sequences:
            oracle = set(base) - set(subtract_a) - set(subtract_b)
            for equals in equals_sequences:
                expected = oracle != set(equals)
                actual = rr_api._eval_closure_atomic(
                    derived_node,
                    {
                        "base": list(base),
                        "subtract_a": list(subtract_a),
                        "subtract_b": list(subtract_b),
                        "equals": list(equals),
                    },
                )
                check(
                    "truth-table:DERIVED_DIFF_NE",
                    actual is expected,
                    (
                        f"base={base!r} subtract_a={subtract_a!r} "
                        f"subtract_b={subtract_b!r} equals={equals!r}"
                    ),
                )

row_flag_node = {
    "op": "ROW_FIELD_NE_ON_FLAG",
    "rows_path": "/rows",
    "key": "id",
    "row_field": "component",
    "flag_rows_path": "/verdicts",
    "flag": "flag",
    "flag_value": True,
    "value_path": "/declared",
}
# The oracle is written from the operator's statement, not from its code: only
# rows whose id the caller flagged are compared, and a flag that is not the
# boolean True never selects a row (matching the frozen strict-equality law,
# under which 1 is not True).
component_options = tuple(itertools.product(("R1", "R2"), ("X", "Y")))
verdict_options = tuple(itertools.product(("R1", "R2"), (True, False, 1, None)))
for row_sequence in bounded_sequences(component_options, 2):
    rows = [{"id": id_value, "component": value} for id_value, value in row_sequence]
    for verdict_sequence in bounded_sequences(verdict_options, 2):
        verdicts = [{"id": id_value, "flag": flag} for id_value, flag in verdict_sequence]
        flagged = {
            id_value
            for id_value, flag in verdict_sequence
            if type(flag) is bool and flag is True
        }
        for declared in ("X", "Y", "Z"):
            expected = any(
                value != declared
                for id_value, value in row_sequence
                if id_value in flagged
            )
            actual = rr_api._eval_closure_atomic(
                row_flag_node,
                {"rows": rows, "verdicts": verdicts, "declared": declared},
            )
            check(
                "truth-table:ROW_FIELD_NE_ON_FLAG",
                actual is expected,
                f"rows={row_sequence!r} verdicts={verdict_sequence!r} declared={declared!r}",
            )

edge_node = {
    "op": "EDGE_ENDPOINTS_NOT_SUBSET",
    "edge_paths": ["/edges_a", "/edges_b"],
    "from": "from",
    "to": "to",
    "nodes_path": "/nodes",
}
edge_options = tuple(itertools.product(("N1", "N2", "N3"), ("N1", "N2", "N3")))
node_sequences = tuple(bounded_sequences(("N1", "N2"), 2))
for edges_a in bounded_sequences(edge_options, 1):
    for edges_b in bounded_sequences(edge_options, 1):
        endpoints = {value for edge in edges_a + edges_b for value in edge}
        for nodes in node_sequences:
            expected = not endpoints <= set(nodes)
            actual = rr_api._eval_closure_atomic(
                edge_node,
                {
                    "edges_a": [{"from": f, "to": t} for f, t in edges_a],
                    "edges_b": [{"from": f, "to": t} for f, t in edges_b],
                    "nodes": list(nodes),
                },
            )
            check(
                "truth-table:EDGE_ENDPOINTS_NOT_SUBSET",
                actual is expected,
                f"edges_a={edges_a!r} edges_b={edges_b!r} nodes={nodes!r}",
            )


# 6. Record references: nesting, exact markers, Unicode, sort/dedup, cap=64.
nested_facts = {
    "record_id": "REC_ROOT",
    "outer": {
        "linked_record_id": "REC_NESTED",
        "exact_reference": "REC_EXACT",
        "plain": "IGNORE_PLAIN",
        "record_id_container": {"plain": "IGNORE_CONTAINER_VALUE"},
        "related_record_ids": ["REC_ARRAY_B", "REC_ARRAY_A", "REC_ARRAY_A", 7],
    },
    "plain_values": ["IGNORE_ARRAY"],
}
nested_expected = sorted(
    {"REC_ROOT", "REC_NESTED", "REC_EXACT", "REC_ARRAY_A", "REC_ARRAY_B"}
)
check(
    "references:nested-marker-scope",
    rr_api.derive_record_references(nested_facts) == nested_expected,
    str(rr_api.derive_record_references(nested_facts)),
)

reference_values = [f"记录_{index:03d}_🧪" for index in reversed(range(256))]
reference_facts_a = {
    "pool_record_ids": reference_values + reference_values[:8],
    "nested": {"exact_reference": reference_values[0]},
}
reference_facts_b = {
    "nested": {"exact_reference": reference_values[0]},
    "pool_record_ids": list(reversed(reference_values)) + reference_values[-8:],
}
expected_capped = sorted(set(reference_values))[:64]
refs_a = rr_api.derive_record_references(reference_facts_a)
refs_b = rr_api.derive_record_references(reference_facts_b)
check("references:cap-is-64", len(refs_a) == 64, str(len(refs_a)))
check("references:sorted-dedup-capped", refs_a == expected_capped, str(refs_a))
check("references:input-order-determinism", refs_b == refs_a, str(refs_b))

# Documented contract: `record_id` is a substring marker, while
# `exact_reference` is an exact key.  Decoy keys must not become references.
check(
    "references:exact-reference-requires-exact-key",
    rr_api.derive_record_references(
        {
            "not_exact_reference_backup": "DECOY_TOP",
            "nested": {"untrusted_exact_reference_note": "DECOY_NESTED"},
        }
    )
    == [],
    "substring decoy keys were treated as record references",
)


for failure in failures:
    print(failure)
if failure_count > MAX_FAILURE_DETAILS:
    print("FAIL additional details omitted")
print(f"grounded-0.4 audit adversarial: checks={checks} failures={failure_count}")
sys.exit(1 if failure_count else 0)
