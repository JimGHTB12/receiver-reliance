"""Meta-tests proving the grounded 0.4 contract lint fails closed.

Each case stages the linter and its exact authority inputs in an isolated OS
temporary directory, mutates only that staged copy, and executes the staged
``lint_contract.py --gate`` in a fresh Python process.  The repository's
authoritative files are therefore never modified.

No randomized test data is used; every mutation is fixed and deterministic.
Exit 0 with ``failures=0`` only when the baseline is accepted and every
representative mutation is rejected with its intended lint finding.
"""
from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from typing import Any

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent

LINTER = pathlib.Path("grounded-0_4/lint_contract.py")
REGISTER = pathlib.Path("grounded-0_4/authority_register_0_4.json")
CLOSURES = pathlib.Path("grounded-0_4/closures_0_4.json")

# Minimal exact authority set needed by b1_capabilities.authority_documents().
STAGED_FILES = (
    LINTER,
    REGISTER,
    CLOSURES,
    pathlib.Path("baseline-run/implementation-output-0.3/b1_capabilities.py"),
    pathlib.Path("baseline-run/control/B1_PRIMARY_IMPLEMENTER_CONTRACT_0_1.json"),
    pathlib.Path("supplemental-0_3/control/B1_SUPPLEMENTAL_COMPARATOR_CONTRACT_0_3.json"),
    pathlib.Path("supplemental-0_3/control/B1_COMPOSED_CAPABILITY_MATRIX_0_3.json"),
    pathlib.Path("access/SANITIZED_PRIMARY_BASELINE_IMPLEMENTER_PACKET_0_1.json"),
    pathlib.Path("access/A2_SHARED_DOMAIN_VOCABULARY_BASELINE_PROJECTION_0_1.schema.json"),
)

Mutation = Callable[[pathlib.Path], str]


def read_json(path: pathlib.Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise AssertionError(f"expected object in {path}")
    return value


def write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def stage_repo(target: pathlib.Path) -> None:
    for relative in STAGED_FILES:
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO / relative, destination)


def mutate_deleted_register_entry(staged: pathlib.Path) -> str:
    path = staged / REGISTER
    register = read_json(path)
    operation = register["operations"][0]
    removed = operation["fields"].pop(0)
    write_json(path, register)
    return (
        f"L1: {operation['obligation_id']}.{removed['field']} required by schema "
        "but absent from register"
    )


def mutate_semantic_to_inert(staged: pathlib.Path) -> str:
    path = staged / REGISTER
    register = read_json(path)
    for operation in register["operations"]:
        for field in operation["fields"]:
            if field["status"] == "semantic":
                field["status"] = "inert_registered_debt"
                write_json(path, register)
                return (
                    f"L1: {operation['obligation_id']}.{field['field']} registered "
                    "inert_registered_debt but predicates DO reference it semantically "
                    "(stale register)"
                )
    raise AssertionError("baseline register has no semantic field to falsify")


def mutate_dual_use_semantic_to_presence_only(staged: pathlib.Path) -> str:
    """Recreate the independently reproduced WP2 under-classification."""
    path = staged / REGISTER
    register = read_json(path)
    operation = next(
        row for row in register["operations"] if row["obligation_id"] == "OBL-02"
    )
    field = next(row for row in operation["fields"] if row["field"] == "exact_reference")
    if field["status"] != "semantic":
        raise AssertionError("corrected OBL-02.exact_reference is not semantic")
    field["status"] = "presence_only"
    field["rationale"] = (
        "required-and-non-null is the tested property; value carries no "
        "classification authority"
    )
    write_json(path, register)
    return (
        "L1: OBL-02.exact_reference registered presence_only but predicates "
        "DO reference it semantically (stale register)"
    )


def mutate_dual_use_derivation_regression(staged: pathlib.Path) -> str:
    """Reintroduce set subtraction so presence use erases value authority."""
    path = staged / LINTER
    source = path.read_text(encoding="utf-8")
    corrected = (
        "semantic_fields = {top_field(pointer) for pointer in value_refs} - {None}"
    )
    regressed = (
        "semantic_fields = {top_field(pointer) for pointer in value_refs - presence_refs} - {None}"
    )
    if source.count(corrected) != 1:
        raise AssertionError("could not identify corrected per-atomic derivation")
    path.write_text(source.replace(corrected, regressed), encoding="utf-8")
    return (
        "L1: OBL-04.provenance_subject_id registered semantic but no "
        "value-comparing predicate references it"
    )


def mutate_inert_to_semantic(staged: pathlib.Path) -> str:
    path = staged / REGISTER
    register = read_json(path)
    for operation in register["operations"]:
        for field in operation["fields"]:
            if field["status"].startswith("inert"):
                field["status"] = "semantic"
                write_json(path, register)
                return (
                    f"L1: {operation['obligation_id']}.{field['field']} registered "
                    "semantic but no value-comparing predicate references it"
                )
    raise AssertionError("baseline register has no inert field to falsify")


def mutate_stale_extra_field(staged: pathlib.Path) -> str:
    path = staged / REGISTER
    register = read_json(path)
    operation = register["operations"][0]
    field_name = "synthetic_stale_field"
    operation["fields"].append(
        {
            "field": field_name,
            "status": "inert_registered_debt",
            "rationale": "deterministic lint meta-test mutation",
        }
    )
    write_json(path, register)
    return (
        f"L1: {operation['obligation_id']}.{field_name} in register but not "
        "schema-required (stale register)"
    )


def mutate_duplicate_wire_format(staged: pathlib.Path) -> str:
    path = staged / REGISTER
    register = read_json(path)
    # Expose the present duplicate as an unapproved synthetic collision.
    register["grandfathered_wire_format_collisions"] = []
    write_json(path, register)
    return (
        "L2: wire format 'B1-SEMANTIC-DECISION-REQUEST-0.2' shared by "
        "['accepted-0.2', 'composed-0.3'] without a grandfathered erratum"
    )


def mutate_closure_to_valid(staged: pathlib.Path) -> str:
    path = staged / CLOSURES
    closures = read_json(path)
    obligation, rows = next(iter(closures["closures_by_obligation"].items()))
    if not rows:
        raise AssertionError(f"baseline closure list for {obligation} is empty")
    closure = rows[0]
    closure["tightens_to"] = "VALID"
    write_json(path, closures)
    return (
        f"L3: closure {closure['closure_id']} tightens_to 'VALID' "
        "(must be a defect class)"
    )


def _first_closure_status_field(register: dict[str, Any], status: str) -> tuple[dict, dict]:
    for operation in register["operations"]:
        for field in operation["fields"]:
            if field["status"] == status:
                return operation, field
    raise AssertionError(f"baseline register has no {status} field to falsify")


def mutate_closure_status_without_closure(staged: pathlib.Path) -> str:
    """Claim closure authority for a field no closure predicate reads."""
    path = staged / REGISTER
    register = read_json(path)
    operation = next(
        row for row in register["operations"] if row["obligation_id"] == "OBL-10"
    )
    field = next(row for row in operation["fields"] if row["field"] == "principal_id")
    field["status"] = "semantic_closure"
    write_json(path, register)
    return (
        "L4: OBL-10.principal_id registered semantic_closure but no value-comparing "
        "closure predicate references it"
    )


def mutate_delete_closure_the_register_relies_on(staged: pathlib.Path) -> str:
    """Withdraw a closure while the register still claims its authority."""
    path = staged / CLOSURES
    closures = read_json(path)
    register = read_json(staged / REGISTER)
    operation, field = _first_closure_status_field(register, "semantic_closure")
    obligation = operation["obligation_id"]
    if obligation not in closures["closures_by_obligation"]:
        raise AssertionError(f"{obligation} declares no closures to withdraw")
    del closures["closures_by_obligation"][obligation]
    write_json(path, closures)
    return (
        f"L4: {obligation}.{field['field']} registered semantic_closure but "
        f"{obligation} declares no closures"
    )


def mutate_matured_field_back_to_inert(staged: pathlib.Path) -> str:
    """Re-hide a checked field under an inert status."""
    path = staged / REGISTER
    register = read_json(path)
    operation, field = _first_closure_status_field(register, "semantic_closure")
    field["status"] = "inert_registered_debt"
    write_json(path, register)
    return (
        f"L4: {operation['obligation_id']}.{field['field']} registered "
        "inert_registered_debt but a closure references it (stale register)"
    )


def mutate_closure_pointer_under_unknown_key(staged: pathlib.Path) -> str:
    """Hide a closure's pointer behind a key the reference scan does not read."""
    path = staged / CLOSURES
    closures = read_json(path)
    closure = closures["closures_by_obligation"]["OBL-24"][0]
    closure["predicate"] = {
        "op": "NOT_UNIQUE",
        "undeclared_pointer_key": "/facts/covered_modality_ids",
    }
    write_json(path, closures)
    return (
        f"L4: closure {closure['closure_id']} carries pointer "
        "'/facts/covered_modality_ids' under a key absent from CLOSURE_PATH_KEYS"
    )


CASES: tuple[tuple[str, Mutation | None], ...] = (
    ("baseline-accepted", None),
    ("deleted-register-entry-rejected", mutate_deleted_register_entry),
    ("semantic-to-inert-rejected", mutate_semantic_to_inert),
    ("dual-use-semantic-to-presence-rejected", mutate_dual_use_semantic_to_presence_only),
    ("dual-use-derivation-regression-rejected", mutate_dual_use_derivation_regression),
    ("inert-to-semantic-rejected", mutate_inert_to_semantic),
    ("stale-extra-field-rejected", mutate_stale_extra_field),
    ("duplicate-wire-format-rejected", mutate_duplicate_wire_format),
    ("closure-to-valid-rejected", mutate_closure_to_valid),
    ("closure-status-without-closure-rejected", mutate_closure_status_without_closure),
    ("withdrawn-closure-rejected", mutate_delete_closure_the_register_relies_on),
    ("matured-field-back-to-inert-rejected", mutate_matured_field_back_to_inert),
    ("closure-pointer-hidden-rejected", mutate_closure_pointer_under_unknown_key),
)


def main() -> int:
    failures = 0
    with tempfile.TemporaryDirectory(prefix="rr-lint-gate-") as temporary:
        temp_root = pathlib.Path(temporary)
        for index, (name, mutation) in enumerate(CASES):
            staged = temp_root / f"case-{index}"
            stage_repo(staged)
            expected = "lint: 0 findings" if mutation is None else mutation(staged)
            completed = subprocess.run(
                [sys.executable, "-B", str(staged / LINTER), "--gate"],
                cwd=staged,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=30,
                check=False,
            )
            output = completed.stdout + completed.stderr
            exit_ok = completed.returncode == 0 if mutation is None else completed.returncode != 0
            finding_ok = expected in output
            if exit_ok and finding_ok:
                print(f"PASS {name}: exit={completed.returncode}; finding={expected}")
            else:
                failures += 1
                print(
                    f"FAIL {name}: exit={completed.returncode}; "
                    f"expected_finding={expected!r}; output={output.strip()!r}"
                )

    print(f"lint-gate meta-test: checks={len(CASES)} failures={failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
