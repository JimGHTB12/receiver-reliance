"""Public-surface regressions: the supported decision API binds facts and closures.

Pins the 2026-08-16 hardening (deep-scan csf_abbd6848 / csf_0479d1a9):

  1. WITHDRAWAL — the package exports no bare `decide`; frozen execution is
     reachable only as the explicitly non-evidentiary conformance surface.
  2. FACT BINDING — audited decisions over materially different facts never
     share a `decision_input_sha256` (the bare route's receipts did).
  3. CLOSURE AUTHORITY — an OBL-30 request with inverted
     `compatibility_verdicts` classifies as a defect on the supported
     surface even though the frozen engine seals VALID for the same bytes.

Run: py -3.12 -B grounded-0_4/test_public_surface.py
"""
from __future__ import annotations

import copy
import hashlib
import io
import json
import pathlib
import sys
import tempfile
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "grounded-0_4"))

CHECKS = 0


def check(name: str, cond: bool) -> None:
    global CHECKS
    CHECKS += 1
    if not cond:
        raise AssertionError(name)


def load_pack() -> dict:
    pack = REPO / "baseline-run" / "fixtures" / "PRIMARY_BASELINE_SEMANTIC_FIXTURE_PACK_0_2.json"
    return json.loads(pack.read_text(encoding="utf-8"))


def load_pack03() -> dict:
    pack = REPO / "supplemental-0_3" / "fixtures" / "B1_SUPPLEMENTAL_SEMANTIC_FIXTURE_PACK_0_3.json"
    return json.loads(pack.read_text(encoding="utf-8"))


def entry_for(pack: dict, obligation_id: str, kind: str = "-IO-") -> dict:
    for e in pack["entries"]:
        if e["obligation_id"] == obligation_id and kind in e["entry_id"]:
            return copy.deepcopy(e["semantic_request"])
    raise AssertionError(f"no {kind} entry for {obligation_id}")


def main() -> int:
    # Ambient same-name modules must not replace the repository implementations.
    ambient_names = ("authority_surface", "b1_capabilities", "pcb_runner")
    absent = object()
    previous = {name: sys.modules.get(name, absent) for name in ambient_names}
    for name in ambient_names:
        sys.modules[name] = types.ModuleType(name)
    try:
        import receiver_reliance as rr
    finally:
        for name, module in previous.items():
            if module is absent:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module

    # --- 1. withdrawal ------------------------------------------------------
    check("no top-level decide attribute", not hasattr(rr, "decide"))
    check("decide absent from __all__", "decide" not in rr.__all__)
    check("decide_audited exported", "decide_audited" in rr.__all__)
    from receiver_reliance import conformance

    pkg_api = sys.modules["receiver_reliance._rr_api"]
    check(
        "ambient collision cannot replace authority implementation",
        pathlib.Path(pkg_api.authority_surface.__file__).resolve()
        == REPO / "grounded-0_4" / "authority_surface.py",
    )
    check(
        "ambient collision cannot replace frozen capabilities",
        pathlib.Path(pkg_api.b1.__file__).resolve()
        == REPO / "baseline-run" / "implementation-output-0.3" / "b1_capabilities.py",
    )
    check(
        "ambient collision cannot replace frozen runner",
        pathlib.Path(pkg_api.pcb_runner.__file__).resolve()
        == REPO / "baseline-run" / "implementation-output-0.3" / "pcb_runner.py",
    )
    check(
        "conformance.execute is the renamed frozen executor",
        conformance.execute is pkg_api.conformance_execute,
    )
    check(
        "rr_api exports no bare decide",
        not hasattr(pkg_api, "decide"),
    )

    pack = load_pack()

    # --- 2. fact binding on the supported surface ---------------------------
    base = entry_for(pack, "OBL-26")
    variant = copy.deepcopy(base)
    variant["decision_input"]["facts"]["invocation_nonce"] = "NONCE_PUBLIC_SURFACE_VARIANT"
    a = rr.decide_audited(base)
    b = rr.decide_audited(variant)
    check(
        "different facts => different audited input seals",
        a["audit"]["decision_input_sha256"] != b["audit"]["decision_input_sha256"],
    )
    raw_base = pkg_api.b1.jcs_bytes(base) + b"\n"
    check(
        "bounded object conversion preserves valid wire bytes",
        pkg_api._bounded_object_wire(base) == raw_base,
    )
    check(
        "valid object and bytes calls remain byte-identical",
        pkg_api.b1.jcs_bytes(rr.decide_audited(base))
        == pkg_api.b1.jcs_bytes(rr.decide_audited(raw_base)),
    )

    cyclic: dict = {}
    cyclic["self"] = cyclic
    cyclic_audit = rr.decide_audited(cyclic)
    check(
        "cyclic object returns a protocol error",
        cyclic_audit["audited_behavior_class"] == "PROTOCOL_ERROR"
        and cyclic_audit["audit"]["object_request_error"] == "ERR_JSON"
        and cyclic_audit["audit"]["request_raw_sha256"] is None,
    )
    cyclic_response, _cyclic_exit = conformance.execute(cyclic)
    check(
        "conformance object path is total too",
        cyclic_response["errors"][0]["code"] == "ERR_JSON",
    )
    deep: dict = {}
    for _index in range(pkg_api.b1.MAX_NESTING + 1):
        deep = {"nested": deep}
    deep_audit = rr.decide_audited(deep)
    check(
        "deep object is rejected before recursive serialization",
        deep_audit["audit"]["object_request_error"] == "ERR_LIMIT",
    )
    object_error_cases = (
        ("non-string-key", {1: "value"}, "ERR_JSON"),
        ("non-finite-number", {"value": float("nan")}, "ERR_NUMBER"),
        ("lone-surrogate", {"value": "\ud800"}, "ERR_JSON"),
        (
            "aggregate-members",
            {"values": [None] * (pkg_api.b1.MAX_MEMBERS_OR_ITEMS + 1)},
            "ERR_LIMIT",
        ),
    )
    for label, invalid_object, expected_code in object_error_cases:
        result = rr.decide_audited(invalid_object)
        check(
            f"bounded object conversion normalizes {label}",
            result["audit"]["object_request_error"] == expected_code,
        )

    # --- 3. closure authority on the supported surface ----------------------
    pack03 = load_pack03()
    clean_obl30 = copy.deepcopy(
        next(e for e in pack03["entries"] if "OBL-30-IO" in e["entry_id"])["semantic_request"]
    )
    obl30 = copy.deepcopy(clean_obl30)
    facts = obl30["decision_input"]["facts"]
    verdicts = facts.get("compatibility_verdicts")
    check("OBL-30 fixture carries compatibility_verdicts rows", isinstance(verdicts, list) and verdicts)
    for row in verdicts:
        check("verdict row carries a boolean", isinstance(row.get("compatible"), bool))
        row["compatible"] = not row["compatible"]
    audited = rr.decide_audited(obl30)
    sealed_class = (
        (audited["sealed_response"].get("output") or {}).get("result_object") or {}
    ).get("behavior_class")
    audited_class = audited["audited_behavior_class"]
    check("frozen engine still seals VALID for contradicted bookkeeping", sealed_class == "VALID")
    check(
        "supported surface tightens inverted verdicts to a defect class",
        audited_class == "BINDING_OR_CONFLICT",
    )
    fired = [f for f in audited["audit"]["closure_findings"] if f.get("fired")]
    check("at least one OBL-30 closure fired", len(fired) >= 1)

    projection_cases = []
    candidate_mismatch = copy.deepcopy(clean_obl30)
    candidate_facts = candidate_mismatch["decision_input"]["facts"]
    candidate_facts["pool_record_ids"][0] = "REC_PHANTOM"
    for field in ("compatible_record_ids", "selected_record_ids"):
        candidate_facts[field] = [
            "REC_PHANTOM" if value == "REC_A" else value
            for value in candidate_facts[field]
        ]
    for row in candidate_facts["compatibility_verdicts"]:
        if row["record_id"] == "REC_A":
            row["record_id"] = "REC_PHANTOM"
    projection_cases.append(
        (candidate_mismatch, "OBL-30-R1-candidate-pool-record-id-projection")
    )

    verdict_mismatch = copy.deepcopy(clean_obl30)
    verdict_facts = verdict_mismatch["decision_input"]["facts"]
    verdict_facts["compatibility_verdicts"][0]["record_id"] = "REC_B"
    verdict_facts["compatible_record_ids"] = ["REC_B"]
    projection_cases.append(
        (verdict_mismatch, "OBL-30-R2-verdict-record-id-projection")
    )

    exclusion_mismatch = copy.deepcopy(clean_obl30)
    exclusion_mismatch["decision_input"]["facts"]["excluded_records"][0][
        "record_id"
    ] = "REC_A"
    projection_cases.append(
        (exclusion_mismatch, "OBL-30-R3-exclusion-record-id-projection")
    )

    for projection_request, expected_finding in projection_cases:
        result = rr.decide_audited(projection_request)
        sealed_class = (
            (result["sealed_response"].get("output") or {}).get("result_object") or {}
        ).get("behavior_class")
        fired_ids = {
            finding["closure_id"]
            for finding in result["audit"]["closure_findings"]
            if finding.get("fired")
        }
        check(f"{expected_finding}:frozen-gap-reproduced", sealed_class == "VALID")
        check(
            f"{expected_finding}:audited-fail-closed",
            result["audited_behavior_class"] == "MALFORMED_OR_BOUNDARY"
            and expected_finding in fired_ids,
        )

    # --- 4. authenticated authority and total register parsing --------------
    authority = pkg_api.authority_surface
    canonical_register = json.loads(
        (REPO / "grounded-0_4" / "authority_register_0_4.json").read_bytes()
    )
    for field, replacement in (
        ("format_version", "B1-AUTHORITY-REGISTER-999"),
        ("status", "synthetic_open_status"),
    ):
        candidate = copy.deepcopy(canonical_register)
        if field == "format_version":
            candidate[field] = replacement
        else:
            candidate["operations"][0]["fields"][0][field] = replacement
        try:
            authority.all_operation_authorities(candidate)
        except authority.AuthorityRegisterError:
            rejected = True
        else:
            rejected = False
        check(f"authority rejects unsupported {field}", rejected)

    with tempfile.TemporaryDirectory(prefix="rr-w3-public-") as temporary:
        temporary_root = pathlib.Path(temporary)
        substituted = temporary_root / "authority_register_0_4.json"
        substituted.write_bytes(b"{}")
        original_register_path = authority.AUTHORITY_REGISTER_PATH
        authority.AUTHORITY_REGISTER_PATH = substituted
        try:
            try:
                pkg_api.authority_for_operation("OBL-01")
            except authority.AuthorityRegisterError:
                authenticated_rejection = True
            else:
                authenticated_rejection = False
        finally:
            authority.AUTHORITY_REGISTER_PATH = original_register_path
        check(
            "runtime authority query authenticates adjacent register bytes",
            authenticated_rejection,
        )

        substituted_policy = temporary_root / "closures_0_4.json"
        substituted_policy.write_bytes(b"{}")
        # The expected digest is read from the live policy rather than
        # transcribed: a literal here goes stale the first time the closure
        # table changes, and a stale literal still passes this check while no
        # longer asserting anything about the policy actually loaded.
        live_policy_sha256 = hashlib.sha256(
            (REPO / "grounded-0_4" / "closures_0_4.json").read_bytes()
        ).hexdigest().upper()
        try:
            pkg_api._read_pinned_bytes(
                substituted_policy,
                2,
                live_policy_sha256,
                "grounded closure policy",
            )
        except pkg_api.RuntimeIntegrityError:
            closure_rejected = True
        else:
            closure_rejected = False
        check("closure policy substitution fails authentication", closure_rejected)

        deep_register = temporary_root / "deep-register.json"
        deep_register.write_bytes(b"[" * 128 + b"]" * 128)
        try:
            authority.read_authority_register(deep_register)
        except authority.AuthorityRegisterError:
            deep_rejected = True
        else:
            deep_rejected = False
        check("deep authority register fails closed", deep_rejected)

    # --- 5. unterminated batch records have a finite work ceiling -----------
    import rr_batch

    class EndlessLine:
        def __init__(self) -> None:
            self.calls = 0

        def readline(self, size: int = -1) -> bytes:
            if size < 0:
                raise AssertionError("unbounded batch read")
            self.calls += 1
            return b"x" * size

    source = EndlessLine()
    sink = io.BytesIO()
    batch_exit = rr_batch.serve(source, sink)
    batch_error = json.loads(sink.getvalue())
    check(
        "unterminated overlimit batch work is bounded",
        source.calls
        == rr_batch._MAX_PHYSICAL_LINE_BYTES // rr_batch._READ_CHUNK_BYTES + 1,
    )
    check(
        "unterminated overlimit batch fails deterministically",
        batch_exit == batch_error["exit_code"]
        and batch_exit != 0
        and batch_error["audit"]["request_raw_sha256"] is None
        and batch_error["audit"]["transport_error"] == "ERR_BATCH_RECORD_LIMIT",
    )

    print(f"PUBLIC-SURFACE PASS: {CHECKS} checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
