"""Regression suite for the grounded 0.4 layer.

Checks, in order:
  1. PARITY  - conformance_execute() reproduces every frozen semantic fixture response
              byte-for-byte across both packs (the layer changes nothing
              about the sealed surface).
  2. TRACE   - decide_audited() never diverges from the sealed class, and
              every non-VALID audited fixture decision carries a nonempty
              witness trace.
  3. BINDING - two requests with different fact profiles can no longer share
              an audit seal (the external review's OBL-08 probe, re-run
              against the audited surface).
  4. CLOSURE - the review's OBL-30 probes (inverted verdicts; stale selected
              set) classify as defects on the audited surface, while the
              clean fixture stays VALID with zero closure findings.
  5. GOVERNANCE - audited decisions identify the governing policy bytes, and
              an errored closure evaluator fails closed rather than certifying.
  6. MATURATION - every closure that carries a formerly inert field's
              classification authority fires on the defect it names and
              tightens to the class it declares, with the frozen table still
              sealing VALID underneath; a record the caller declared
              incompatible may drift from the intent tuple without a hold;
              and a closure shipped without a positive control fails here.

Exit 0 with 'failures=0' on success.
"""
from __future__ import annotations

import base64
import copy
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))
import rr_api  # noqa: E402
from rr_api import b1  # noqa: E402

failures = 0
checks = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global failures, checks
    checks += 1
    if not ok:
        failures += 1
        print(f"FAIL {name} {detail}")


def load_pack(rel: str) -> dict:
    return json.load(open(REPO / rel, encoding="utf-8"))


PACKS = [
    "baseline-run/fixtures/PRIMARY_BASELINE_SEMANTIC_FIXTURE_PACK_0_2.json",
    "supplemental-0_3/fixtures/B1_SUPPLEMENTAL_SEMANTIC_FIXTURE_PACK_0_3.json",
]

# 1. PARITY + 2. TRACE over every semantic fixture entry
for rel in PACKS:
    pack = load_pack(rel)
    for entry in pack["entries"]:
        raw = base64.b64decode(entry["semantic_request_jcs_lf_base64"])
        expected = base64.b64decode(entry["expected_response_jcs_lf_base64"])
        response, _exit = rr_api.conformance_execute(raw)
        got = b1.jcs_bytes(response) + b"\n"
        check(f"parity:{entry['entry_id']}", got == expected)
        audited = rr_api.decide_audited(raw)
        sealed = b1.jcs_bytes(audited["sealed_response"]) + b"\n"
        check(f"audit-parity:{entry['entry_id']}", sealed == expected)
        seal_ok = audited["audit_sha256"] == b1.self_zero_sha256(audited, "audit_sha256")
        check(f"audit-seal:{entry['entry_id']}", seal_ok)
        if audited["sealed_response"].get("ok"):
            sealed_class = audited["sealed_response"]["output"]["result_object"]["behavior_class"]
            if sealed_class != "VALID":
                check(
                    f"witness-nonempty:{entry['entry_id']}",
                    bool(audited["audit"]["matched_class_witness"]),
                )
            frozen_closures = [
                f for f in audited["audit"]["closure_findings"] if f.get("fired")
            ]
            if sealed_class == "VALID" and entry["entry_id"].startswith("SEMFX") and "OBL-30" not in entry["entry_id"]:
                check(
                    f"closure-quiet:{entry['entry_id']}",
                    audited["audited_behavior_class"] == "VALID",
                    str(frozen_closures),
                )

# 3. BINDING: the OBL-08 substitution probe against the audited surface
pack02 = load_pack(PACKS[0])
e08 = next(e for e in pack02["entries"] if "OBL-08-IO" in e["entry_id"])
r08 = json.loads(base64.b64decode(e08["semantic_request_jcs_lf_base64"]).decode())
mut08 = copy.deepcopy(r08)
mut08["decision_input"]["facts"]["actor_id"] = "ACTOR_TOTALLY_DIFFERENT"
mut08["decision_input"]["facts"]["capability_id"] = "CAPABILITY_NUKE_PROD"
a_base = rr_api.decide_audited(r08)
a_mut = rr_api.decide_audited(mut08)
check(
    "binding:different-facts-different-audit-seal",
    a_base["audit_sha256"] != a_mut["audit_sha256"],
)
check(
    "binding:different-facts-different-input-digest",
    a_base["audit"]["decision_input_sha256"] != a_mut["audit"]["decision_input_sha256"],
)
check(
    "binding:sealed-receipts-still-identical-documenting-frozen-gap",
    a_base["sealed_response"]["receipt_sha256"] == a_mut["sealed_response"]["receipt_sha256"],
)

# 4. CLOSURE: the review's OBL-30 probes
pack03 = load_pack(PACKS[1])
e30 = next(e for e in pack03["entries"] if "OBL-30-IO" in e["entry_id"])
r30 = json.loads(base64.b64decode(e30["semantic_request_jcs_lf_base64"]).decode())

clean = rr_api.decide_audited(r30)
check("closure:clean-io-stays-valid", clean["audited_behavior_class"] == "VALID")
check(
    "closure:clean-io-zero-findings",
    not [f for f in clean["audit"]["closure_findings"] if f.get("fired")],
)

inverted = copy.deepcopy(r30)
for row in inverted["decision_input"]["facts"]["compatibility_verdicts"]:
    row["compatible"] = not row["compatible"]
a_inv = rr_api.decide_audited(inverted)
check(
    "closure:inverted-verdicts-now-conflict",
    a_inv["audited_behavior_class"] == "BINDING_OR_CONFLICT",
    a_inv["audited_behavior_class"],
)

stale = copy.deepcopy(r30)
stale["decision_input"]["facts"]["selected_record_ids"] = (
    stale["decision_input"]["facts"]["selected_record_ids"][:1]
)
a_stale = rr_api.decide_audited(stale)
check(
    "closure:stale-selected-now-omission",
    a_stale["audited_behavior_class"] == "OMISSION_OR_INCOMPLETE",
    a_stale["audited_behavior_class"],
)
check(
    "closure:stale-selected-c3-fired",
    any(
        f.get("fired") and f["closure_id"].startswith("OBL-30-C3")
        for f in a_stale["audit"]["closure_findings"]
    ),
)

# record references derived, not hardcoded-empty
check(
    "references:obl30-carries-pool-ids",
    "REC_A" in clean["audit"]["record_references"],
    str(clean["audit"]["record_references"]),
)

# 5. GOVERNANCE - audited decisions identify the exact policy bytes that
#    governed them (ERRATA E8), and an errored closure evaluator can never
#    silently certify VALID (ERRATA E9).
gov = clean["audit"]["governing_authorities"]
check(
    "governance:closed-key-set",
    set(gov)
    == {
        "closure_policy_sha256",
        "authority_register_sha256",
        "engine_capabilities_sha256",
        "engine_runner_sha256",
        "decision_table_contract_sha256",
        "composed_contract_sha256",
    },
    str(sorted(gov)),
)
for gov_key, gov_path in (
    ("closure_policy_sha256", HERE / "closures_0_4.json"),
    ("authority_register_sha256", HERE / "authority_register_0_4.json"),
    (
        "engine_capabilities_sha256",
        REPO / "baseline-run" / "implementation-output-0.3" / "b1_capabilities.py",
    ),
    (
        "engine_runner_sha256",
        REPO / "baseline-run" / "implementation-output-0.3" / "pcb_runner.py",
    ),
    (
        "decision_table_contract_sha256",
        REPO / "baseline-run" / "control" / "B1_PRIMARY_IMPLEMENTER_CONTRACT_0_1.json",
    ),
    (
        "composed_contract_sha256",
        REPO / "supplemental-0_3" / "control" / "B1_SUPPLEMENTAL_COMPARATOR_CONTRACT_0_3.json",
    ),
):
    check(
        f"governance:{gov_key}-matches-disk",
        gov[gov_key] == b1.sha256_upper(gov_path.read_bytes()),
        gov[gov_key],
    )
check("governance:format-bumped", clean["format_version"] == "B1-AUDITED-DECISION-0.4.2")
gov_mut = copy.deepcopy(clean)
gov_mut["audit"]["governing_authorities"]["closure_policy_sha256"] = "0" * 64
check(
    "governance:seal-covers-governing-digests",
    b1.self_zero_sha256(gov_mut, "audit_sha256") != clean["audit_sha256"],
)
# 0.4.2: the law itself is sealed. Before this, two parties running different
# decision tables produced byte-identical governing_authorities, so an envelope
# could not identify the law that decided it.
for _new_key in ("decision_table_contract_sha256", "composed_contract_sha256"):
    _law_mut = copy.deepcopy(clean)
    _law_mut["audit"]["governing_authorities"][_new_key] = "0" * 64
    check(
        f"governance:seal-covers-{_new_key}",
        b1.self_zero_sha256(_law_mut, "audit_sha256") != clean["audit_sha256"],
    )
_obl30_rows = rr_api._CLOSURES.get("OBL-30", [])
_broken_row = {
    "closure_id": "TEST-BROKEN-EVALUATOR",
    "predicate": {"op": "NO_SUCH_OPERATOR"},
    "tightens_to": "BINDING_OR_CONFLICT",
    "statement": "forced evaluator error for the E9 regression",
}
_obl30_rows.append(_broken_row)
try:
    incomplete = rr_api.decide_audited(r30)
finally:
    _obl30_rows.remove(_broken_row)
check(
    "governance:evaluator-error-fails-closed",
    incomplete["audited_behavior_class"] == "AUDIT_INCOMPLETE",
    incomplete["audited_behavior_class"],
)
check(
    "governance:evaluator-error-recorded",
    any(
        "evaluator_error" in finding
        for finding in incomplete["audit"]["closure_findings"]
    ),
)
check(
    "governance:clean-baseline-unaffected",
    rr_api.decide_audited(r30)["audited_behavior_class"] == "VALID",
)
check(
    "governance:reference-truncation-disclosed-false",
    clean["audit"]["record_references_truncated"] is False,
)
_many = {"pool_record_ids": [f"REC_{i:04d}" for i in range(70)]}
_refs_capped, _refs_flag = rr_api._derive_record_references_full(_many)
check(
    "governance:reference-truncation-caps-at-64-and-flags",
    len(_refs_capped) == 64 and _refs_flag is True,
    f"{len(_refs_capped)} {_refs_flag}",
)
_exact = {"pool_record_ids": [f"REC_{i:04d}" for i in range(64)]}
_refs_capped, _refs_flag = rr_api._derive_record_references_full(_exact)
check(
    "governance:reference-exact-64-not-flagged",
    len(_refs_capped) == 64 and _refs_flag is False,
    f"{len(_refs_capped)} {_refs_flag}",
)

# 6. MATURATION - every closure that gives a formerly inert field its
#    classification authority names a defect, fires on it, and tightens to the
#    class it declares, while the clean fixture it was derived from stays
#    VALID. The sealed class is asserted VALID in each case, so what is being
#    proved is that the CLOSURE did the work and not the frozen table.
VALID_ENTRIES: dict[str, dict] = {}
for _rel in PACKS:
    for _entry in load_pack(_rel)["entries"]:
        _ob = _entry["semantic_request"]["obligation_id"]
        if "-IO-" in _entry["entry_id"] and _ob not in VALID_ENTRIES:
            VALID_ENTRIES[_ob] = _entry


def clean_request(obligation: str) -> dict:
    entry = VALID_ENTRIES[obligation]
    return json.loads(
        base64.b64decode(entry["semantic_request_jcs_lf_base64"]).decode("utf-8")
    )


def _set(**values):
    def mutate(facts):
        facts.update(values)

    return mutate


def _pool_field(record_id: str, field: str, value):
    def mutate(facts):
        for row in facts["candidate_pool"]:
            if row["record_id"] == record_id:
                row[field] = value

    return mutate


def _alias_record(facts):
    facts["support_record_sha256"] = facts["provenance_record_sha256"]


MATURATION_CASES = [
    # (obligation, closure id, defect the caller commits, expected class)
    ("OBL-08", "OBL-08-C1-assumption-id-set-integrity",
     _set(assumption_ids=["ASSUMPTION_A", "ASSUMPTION_A"]), "MALFORMED_OR_BOUNDARY"),
    ("OBL-12", "OBL-12-C1-contextual-parameters-stated",
     _set(subject_id=None), "OMISSION_OR_INCOMPLETE"),
    ("OBL-12", "OBL-12-C1-contextual-parameters-stated",
     _set(information_type=None), "OMISSION_OR_INCOMPLETE"),
    ("OBL-12", "OBL-12-C1-contextual-parameters-stated",
     _set(context_id=None), "OMISSION_OR_INCOMPLETE"),
    ("OBL-12", "OBL-12-C1-contextual-parameters-stated",
     _set(purpose_id=None), "OMISSION_OR_INCOMPLETE"),
    ("OBL-14", "OBL-14-C1-edge-endpoints-declared",
     _set(dependency_edges=[{"from": "NODE_A", "to": "NODE_UNDECLARED"}]),
     "MALFORMED_OR_BOUNDARY"),
    ("OBL-14", "OBL-14-C1-edge-endpoints-declared",
     _set(parent_edges=[{"from": "NODE_UNDECLARED", "to": "NODE_B"}]),
     "MALFORMED_OR_BOUNDARY"),
    ("OBL-14", "OBL-14-C2-node-id-set-integrity",
     _set(node_ids=["NODE_A", "NODE_A", "NODE_B"]), "MALFORMED_OR_BOUNDARY"),
    ("OBL-16", "OBL-16-C1-record-sources-pairwise-distinct",
     _alias_record, "OMISSION_OR_INCOMPLETE"),
    ("OBL-16", "OBL-16-C2-declared-missing-evidence",
     _set(missing_evidence_ids=["EVIDENCE_WE_DO_NOT_HOLD"]), "OMISSION_OR_INCOMPLETE"),
    ("OBL-16", "OBL-16-C3-id-set-integrity",
     _set(obligation_ids=["OBL-A", "OBL-A"]), "MALFORMED_OR_BOUNDARY"),
    ("OBL-16", "OBL-16-C3-id-set-integrity",
     _set(assumption_ids=["ASSUMPTION_A", "ASSUMPTION_A"]), "MALFORMED_OR_BOUNDARY"),
    ("OBL-22", "OBL-22-C1-binding-not-self-asserted",
     _set(binding_sha256s=["B" * 63 + "8"], self_asserted_trust_sha256s=["B" * 63 + "8"]),
     "BINDING_OR_CONFLICT"),
    ("OBL-22", "OBL-22-C2-evidence-digest-set-integrity",
     _set(tool_output_sha256s=["F" * 63 + "1", "F" * 63 + "1"]), "MALFORMED_OR_BOUNDARY"),
    ("OBL-24", "OBL-24-C1-covered-modality-set-integrity",
     _set(covered_modality_ids=["MODALITY_A", "MODALITY_A"]), "MALFORMED_OR_BOUNDARY"),
    ("OBL-30", "OBL-30-C4-compatible-episode-agreement",
     _pool_field("REC_A", "episode_id", "EPISODE_OTHER"), "BINDING_OR_CONFLICT"),
    ("OBL-30", "OBL-30-C5-compatible-purpose-agreement",
     _pool_field("REC_A", "purpose_id", "PURPOSE_OTHER"), "BINDING_OR_CONFLICT"),
    ("OBL-30", "OBL-30-C6-compatible-scope-agreement",
     _pool_field("REC_A", "scope_ref", "SCOPE_OTHER"), "BINDING_OR_CONFLICT"),
    ("OBL-30", "OBL-30-C7-compatible-action-class-agreement",
     _pool_field("REC_A", "action_class", "ACTION_CLASS_OTHER"), "BINDING_OR_CONFLICT"),
    ("OBL-30", "OBL-30-C8-compatible-version-agreement",
     _pool_field("REC_A", "version_sha256", "A" * 63 + "7"), "BINDING_OR_CONFLICT"),
]

exercised_closures: set[str] = {
    finding["closure_id"]
    for audited in (a_inv, a_stale)
    for finding in audited["audit"]["closure_findings"]
    if finding.get("fired")
}

for obligation, closure_id, mutate, expected_class in MATURATION_CASES:
    request = clean_request(obligation)
    baseline = rr_api.decide_audited(request)
    check(
        f"maturation:{closure_id}:baseline-valid",
        baseline["audited_behavior_class"] == "VALID",
        f"{obligation} {baseline['audited_behavior_class']}",
    )
    mutate(request["decision_input"]["facts"])
    audited = rr_api.decide_audited(request)
    sealed_class = (
        (audited["sealed_response"].get("output") or {}).get("result_object") or {}
    ).get("behavior_class")
    fired = {
        finding["closure_id"]
        for finding in audited["audit"]["closure_findings"]
        if finding.get("fired")
    }
    exercised_closures |= fired
    check(
        f"maturation:{closure_id}:frozen-table-still-seals-valid",
        sealed_class == "VALID",
        str(sealed_class),
    )
    check(f"maturation:{closure_id}:fires", closure_id in fired, str(sorted(fired)))
    check(
        f"maturation:{closure_id}:tightens-to-{expected_class}",
        audited["audited_behavior_class"] == expected_class,
        audited["audited_behavior_class"],
    )
    check(
        f"maturation:{closure_id}:no-evaluator-error",
        not [f for f in audited["audit"]["closure_findings"] if "evaluator_error" in f],
        str(audited["audit"]["closure_findings"]),
    )

# Negative control: the intent-agreement closures test only the records the
# caller vouched for. A record the caller declared INCOMPATIBLE may differ
# from the declared intent in any way it likes — that is what incompatible
# means, and holding on it would be the false hold this design must not make.
drifted = clean_request("OBL-30")
_pool_field("REC_LURE", "episode_id", "EPISODE_ANYTHING")(
    drifted["decision_input"]["facts"]
)
a_drifted = rr_api.decide_audited(drifted)
check(
    "maturation:incompatible-record-may-drift",
    a_drifted["audited_behavior_class"] == "VALID",
    a_drifted["audited_behavior_class"],
)

# A closure with no positive control is an unscored check. Every row of the
# declared closure table must have fired somewhere in this suite.
declared_closures = {
    row["closure_id"] for rows in rr_api._CLOSURES.values() for row in rows
}
check(
    "maturation:every-declared-closure-has-a-positive-control",
    declared_closures <= exercised_closures,
    str(sorted(declared_closures - exercised_closures)),
)

# Every field the register says a closure checks must belong to an obligation
# the runtime closure table actually carries. lint_contract L4 proves the
# stronger per-field correspondence; this ties the shipped register to the
# closures this process loaded.
_register = json.load(open(HERE / "authority_register_0_4.json", encoding="utf-8"))
_closure_backed = {
    (operation["obligation_id"], field["field"])
    for operation in _register["operations"]
    for field in operation["fields"]
    if field["status"].endswith("_closure")
}
check(
    "maturation:register-closure-statuses-have-runtime-closures",
    all(obligation in rr_api._CLOSURES for obligation, _field in _closure_backed),
    str(sorted({ob for ob, _f in _closure_backed if ob not in rr_api._CLOSURES})),
)
check(
    "maturation:no-field-left-inert-without-a-recorded-boundary",
    all(
        "0.5" in field["rationale"] or not field["status"].startswith("inert")
        for operation in _register["operations"]
        for field in operation["fields"]
    ),
    str(
        [
            f"{operation['obligation_id']}.{field['field']}"
            for operation in _register["operations"]
            for field in operation["fields"]
            if field["status"].startswith("inert") and "0.5" not in field["rationale"]
        ]
    ),
)

print(f"grounded-0.4 regression: checks={checks} failures={failures}")
sys.exit(1 if failures else 0)
