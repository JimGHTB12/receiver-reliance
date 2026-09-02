#!/usr/bin/env python3
"""Dense register/table/API agreement and fail-closed drift checks.

This suite independently parses the committed Markdown table, compares every
field to the canonical JSON register and both public operation selectors, runs
the predicate/register lint gate, and stages deterministic drift mutations in
OS temporary directories.  Repository authority files are never mutated.
"""
from __future__ import annotations

import copy
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from typing import Any


HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent
REGISTER_PATH = HERE / "authority_register_0_4.json"
TABLE_PATH = HERE / "AUTHORITY_TABLE.md"
GENERATOR_PATH = HERE / "generate_authority_table.py"
LINTER_PATH = HERE / "lint_contract.py"
MAX_FAILURE_DETAILS = 20

sys.path.insert(0, str(HERE))
import authority_surface  # noqa: E402
import generate_authority_table as generator  # noqa: E402
import lint_contract as contract_lint  # noqa: E402

# Taken from the generator rather than transcribed: a second copy of the
# column list drifts the first time a status is added, and the drift shows up
# as a parse failure in this test instead of as the register error it is.
NON_SEMANTIC_STATUSES = generator.NON_SEMANTIC_STATUSES
import rr_api  # noqa: E402


checks = 0
failure_count = 0
failures: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    global checks, failure_count
    checks += 1
    if not condition:
        failure_count += 1
        if len(failures) < MAX_FAILURE_DETAILS:
            suffix = f" -- {detail}" if detail else ""
            failures.append(f"FAIL {name}{suffix}")


def expected_surface(register: dict[str, Any], operation: dict[str, Any]) -> dict[str, Any]:
    return {
        "authority_register_format_version": register["format_version"],
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


def parse_code_cell(cell: str) -> list[str]:
    if cell == "—":
        return []
    values = []
    for token in cell.split("<br>"):
        match = re.fullmatch(r"`([^`|\r\n]+)`", token)
        if match is None:
            raise AssertionError(f"malformed generated table cell: {cell!r}")
        values.append(match.group(1))
    return values


def parse_table(raw: bytes) -> tuple[str, dict[str, dict[str, set[str]]]]:
    text = raw.decode("utf-8")
    digest_match = re.search(r"^Exact source SHA-256: `([0-9A-F]{64})`\.$", text, re.MULTILINE)
    if digest_match is None:
        raise AssertionError("table lacks exact source digest")
    parsed: dict[str, dict[str, set[str]]] = {}
    for line in text.splitlines():
        if not line.startswith("| `OBL-"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 2 + len(NON_SEMANTIC_STATUSES):
            raise AssertionError(f"table row has {len(cells)} cells: {line!r}")
        obligation_values = parse_code_cell(cells[0])
        handle_values = parse_code_cell(cells[1])
        if len(obligation_values) != 1 or len(handle_values) != 1:
            raise AssertionError(f"invalid operation selectors in row: {line!r}")
        obligation_id = obligation_values[0]
        if obligation_id in parsed:
            raise AssertionError(f"duplicate table row: {obligation_id}")
        parsed[obligation_id] = {
            "operation_handle": {handle_values[0]},
            **{
                status: set(parse_code_cell(cell))
                for status, cell in zip(NON_SEMANTIC_STATUSES, cells[2:])
            },
        }
    return digest_match.group(1), parsed


def run(command: list[str], cwd: pathlib.Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
        check=False,
    )


register_raw = REGISTER_PATH.read_bytes()
register = json.loads(register_raw)
table_raw = TABLE_PATH.read_bytes()

# 1. The committed file is exactly the deterministic generator's byte stream.
expected_table_raw = generator.render_table(register_raw, register)
check("table:exact-generated-bytes", table_raw == expected_table_raw)
check("table:lf-only", b"\r" not in table_raw and table_raw.endswith(b"\n"))
generator_check = run(
    [sys.executable, "-B", str(GENERATOR_PATH), "--check"], REPO
)
check("generator-check:exit-zero", generator_check.returncode == 0, generator_check.stdout)
check("generator-check:stderr-empty", generator_check.stderr == "", generator_check.stderr)

# 2. Every operation and field agrees exactly between raw register and API.
all_surfaces = authority_surface.all_operation_authorities(register)
check("api:operation-count", len(all_surfaces) == len(register["operations"]))
for operation in register["operations"]:
    obligation_id = operation["obligation_id"]
    operation_handle = operation["operation_handle"]
    expected = expected_surface(register, operation)
    by_obligation = rr_api.authority_for_operation(obligation_id)
    by_handle = rr_api.authority_for_operation(operation_handle)
    check(f"api:{obligation_id}:obligation-selector", by_obligation == expected)
    check(f"api:{obligation_id}:handle-selector", by_handle == expected)
    check(f"api:{obligation_id}:selectors-equal", by_obligation == by_handle)
    check(
        f"api:{obligation_id}:field-order-exact",
        [field["field"] for field in by_obligation["fields"]]
        == [field["field"] for field in operation["fields"]],
    )

# Returned objects cannot mutate a later runtime query.
freshness_target = register["operations"][0]
mutated_surface = rr_api.authority_for_operation(freshness_target["obligation_id"])
mutated_surface["fields"][0]["status"] = "synthetic_mutation"
check(
    "api:fresh-register-read-and-copy",
    rr_api.authority_for_operation(freshness_target["obligation_id"])
    == expected_surface(register, freshness_target),
)
for selector in ("OBL-00-NOT-REAL", "OPR_NOT_REAL"):
    try:
        rr_api.authority_for_operation(selector)
    except KeyError:
        check(f"api:unknown:{selector}:rejected", True)
    except Exception as error:  # noqa: BLE001 - wrong failure class is a regression
        check(f"api:unknown:{selector}:rejected", False, repr(error))
    else:
        check(f"api:unknown:{selector}:rejected", False, "did not raise")
try:
    rr_api.authority_for_operation(None)  # type: ignore[arg-type]
except TypeError:
    check("api:non-string:rejected", True)
except Exception as error:  # noqa: BLE001 - wrong failure class is a regression
    check("api:non-string:rejected", False, repr(error))
else:
    check("api:non-string:rejected", False, "did not raise")

# 3. Independently parse Markdown and reconstruct every non-semantic mapping.
table_source_digest, parsed_table = parse_table(table_raw)
check(
    "table:source-digest-exact",
    table_source_digest == hashlib.sha256(register_raw).hexdigest().upper(),
)
check("table:one-row-per-operation", len(parsed_table) == len(register["operations"]))
register_counts: Counter[str] = Counter()
table_counts: Counter[str] = Counter()
for operation in register["operations"]:
    obligation_id = operation["obligation_id"]
    row = parsed_table.get(obligation_id)
    check(f"table:{obligation_id}:row-present", row is not None)
    if row is None:
        continue
    check(
        f"table:{obligation_id}:handle-exact",
        row["operation_handle"] == {operation["operation_handle"]},
        repr(row["operation_handle"]),
    )
    all_documented_fields: set[str] = set()
    for status in NON_SEMANTIC_STATUSES:
        expected_fields = {
            field["field"] for field in operation["fields"] if field["status"] == status
        }
        actual_fields = row[status]
        check(
            f"table:{obligation_id}:{status}:exact",
            actual_fields == expected_fields,
            f"actual={sorted(actual_fields)!r} expected={sorted(expected_fields)!r}",
        )
        check(
            f"table:{obligation_id}:{status}:no-cross-column-duplicate",
            all_documented_fields.isdisjoint(actual_fields),
        )
        all_documented_fields.update(actual_fields)
        register_counts[status] += len(expected_fields)
        table_counts[status] += len(actual_fields)
    semantic_fields = {
        field["field"] for field in operation["fields"] if field["status"] == "semantic"
    }
    check(
        f"table:{obligation_id}:no-semantic-fields",
        all_documented_fields.isdisjoint(semantic_fields),
    )
check("table:global-status-counts", table_counts == register_counts, repr(table_counts))

# 4. Pin per-atomic use semantics. A path used by both presence and value
# atoms remains value-authoritative; the exact 30-field correction is derived
# from the contract tables and compared with the corrected register.
synthetic_presence_refs: set[str] = set()
synthetic_value_refs: set[str] = set()
contract_lint.collect_refs(
    {
        "all": [
            {"op": "PRESENT", "path": "/facts/dual_use"},
            {"op": "EQ", "path": "/facts/dual_use", "value": "bound"},
        ]
    },
    synthetic_value_refs,
    synthetic_presence_refs,
)
check(
    "atomic-uses:dual-use-presence-retained",
    synthetic_presence_refs == {"/facts/dual_use"},
    repr(synthetic_presence_refs),
)
check(
    "atomic-uses:dual-use-value-retained",
    synthetic_value_refs == {"/facts/dual_use"},
    repr(synthetic_value_refs),
)

expected_corrected_dual_use = {
    ("OBL-02", "exact_reference"),
    ("OBL-03", "declared_scope_sha256"),
    ("OBL-03", "recorded_use_scope_sha256"),
    ("OBL-04", "provenance_record_sha256"),
    ("OBL-04", "provenance_subject_id"),
    ("OBL-05", "assessed_claim_version_sha256"),
    ("OBL-05", "evidence_claim_version_sha256"),
    ("OBL-07", "authorization_decision"),
    ("OBL-07", "authorization_record_sha256"),
    ("OBL-08", "manifest_effect_sha256"),
    ("OBL-08", "requested_effect_sha256"),
    ("OBL-12", "sender_id"),
    ("OBL-13", "validation_result"),
    ("OBL-18", "last_authority_arrival_sequence"),
    ("OBL-19", "invocation_sha256"),
    ("OBL-20", "authorized_effect_sha256"),
    ("OBL-20", "invoked_effect_sha256"),
    ("OBL-20", "observed_effect_sha256"),
    ("OBL-26", "effect_sha256"),
    ("OBL-26", "execution_receipt_effect_sha256"),
    ("OBL-26", "invocation_nonce"),
    ("OBL-26", "revoked_at"),
    ("OBL-28", "action_manifest_bytes_base64"),
    ("OBL-28", "executed_effect_bytes_base64"),
    ("OBL-28", "trusted_render_bytes_base64"),
    ("OBL-29", "affordable_covering_query_id"),
    ("OBL-29", "asked_addressee_id"),
    ("OBL-29", "asked_query_cost"),
    ("OBL-29", "asked_query_id"),
    ("OBL-29", "asked_query_target_fact_id"),
}
documents = contract_lint.b1.authority_documents()
decision_rows = list(
    documents["base_contract"]["semantic_decision_contract"][
        "operation_decision_table"
    ]
)
decision_rows.extend(
    documents["contract"]["semantic_decision_contract_supplement"][
        "supplemental_operation_decision_table"
    ]
)
derived_dual_use: set[tuple[str, str]] = set()
for decision_row in decision_rows:
    presence_refs: set[str] = set()
    value_refs: set[str] = set()
    for predicate in decision_row["class_predicates"].values():
        contract_lint.collect_refs(predicate, value_refs, presence_refs)
    dual_fields = {
        contract_lint.top_field(pointer) for pointer in value_refs & presence_refs
    } - {None}
    derived_dual_use.update(
        (decision_row["obligation_id"], field) for field in dual_fields
    )
check(
    "atomic-uses:exact-30-field-correction",
    derived_dual_use == expected_corrected_dual_use,
    (
        f"missing={sorted(expected_corrected_dual_use - derived_dual_use)!r} "
        f"extra={sorted(derived_dual_use - expected_corrected_dual_use)!r}"
    ),
)
register_field_map = {
    (operation["obligation_id"], field["field"]): field
    for operation in register["operations"]
    for field in operation["fields"]
}
for obligation_id, field_name in sorted(expected_corrected_dual_use):
    entry = register_field_map[(obligation_id, field_name)]
    check(
        f"atomic-uses:{obligation_id}.{field_name}:semantic",
        entry
        == {
            "field": field_name,
            "status": "semantic",
            "rationale": "referenced by a value-comparing predicate",
        },
        repr(entry),
    )

# 5. Predicate/register lint is part of the agreement chain and must be green.
lint = run([sys.executable, "-B", str(LINTER_PATH), "--gate"], REPO)
check("lint:gate-exit-zero", lint.returncode == 0, lint.stdout + lint.stderr)
check("lint:zero-findings", "lint: 0 findings" in lint.stdout, lint.stdout)
check("lint:stderr-empty", lint.stderr == "", lint.stderr)

# 6. The diff gate fails on stale table bytes, any exact register-byte drift,
# and missing output.  All mutations live in isolated staged copies.
staged_files = (
    "authority_surface.py",
    "generate_authority_table.py",
    "authority_register_0_4.json",
    "AUTHORITY_TABLE.md",
)
with tempfile.TemporaryDirectory(prefix="rr-authority-legibility-") as temporary:
    temporary_root = pathlib.Path(temporary)
    for case_index, case_name in enumerate(
        ("status-drift", "rationale-only-drift", "table-byte-drift", "missing-table")
    ):
        staged = temporary_root / f"case-{case_index}" / "grounded-0_4"
        staged.mkdir(parents=True)
        for name in staged_files:
            shutil.copy2(HERE / name, staged / name)
        if case_name in ("status-drift", "rationale-only-drift"):
            staged_register_path = staged / "authority_register_0_4.json"
            staged_register = json.loads(staged_register_path.read_bytes())
            first_field = staged_register["operations"][0]["fields"][0]
            if case_name == "status-drift":
                first_field["status"] = (
                    "presence_only"
                    if first_field["status"] == "semantic"
                    else "semantic"
                )
            else:
                first_field["rationale"] += " (deterministic refuter mutation)"
            staged_register_path.write_text(
                json.dumps(staged_register, ensure_ascii=False, indent=1) + "\n",
                encoding="utf-8",
                newline="\n",
            )
        elif case_name == "table-byte-drift":
            with (staged / "AUTHORITY_TABLE.md").open(
                "ab"
            ) as stream:
                stream.write(b"deterministic-refuter-mutation\n")
        else:
            (staged / "AUTHORITY_TABLE.md").unlink()
        drift = run(
            [sys.executable, "-B", str(staged / "generate_authority_table.py"), "--check"],
            staged.parent,
        )
        check(f"drift:{case_name}:exit-nonzero", drift.returncode != 0, drift.stdout)
        check(
            f"drift:{case_name}:diagnostic",
            "authority table drift:" in drift.stdout,
            drift.stdout + drift.stderr,
        )

# 7. Duplicate and cross-namespace operation selectors fail before a surface
# can be returned.
for case_name, mutate in (
    (
        "duplicate-obligation",
        lambda value: value["operations"][1].__setitem__(
            "obligation_id", value["operations"][0]["obligation_id"]
        ),
    ),
    (
        "duplicate-handle",
        lambda value: value["operations"][1].__setitem__(
            "operation_handle", value["operations"][0]["operation_handle"]
        ),
    ),
    (
        "duplicate-field",
        lambda value: value["operations"][0]["fields"].append(
            copy.deepcopy(value["operations"][0]["fields"][0])
        ),
    ),
    (
        "obligation-collides-with-handle",
        lambda value: value["operations"][1].__setitem__(
            "obligation_id", value["operations"][0]["operation_handle"]
        ),
    ),
    (
        "handle-collides-with-obligation",
        lambda value: value["operations"][1].__setitem__(
            "operation_handle", value["operations"][0]["obligation_id"]
        ),
    ),
    (
        "same-operation-cross-namespace",
        lambda value: value["operations"][0].__setitem__(
            "operation_handle", value["operations"][0]["obligation_id"]
        ),
    ),
):
    candidate = copy.deepcopy(register)
    mutate(candidate)
    try:
        authority_surface.all_operation_authorities(candidate)
    except authority_surface.AuthorityRegisterError:
        check(f"register:{case_name}:rejected", True)
    except Exception as error:  # noqa: BLE001 - wrong failure class is a regression
        check(f"register:{case_name}:rejected", False, repr(error))
    else:
        check(f"register:{case_name}:rejected", False, "did not raise")

for failure in failures:
    print(failure)
if failure_count > MAX_FAILURE_DETAILS:
    print(f"FAIL ... {failure_count - MAX_FAILURE_DETAILS} additional details omitted")
print(
    "authority legibility: "
    f"operations={len(register['operations'])} fields={sum(len(row['fields']) for row in register['operations'])} "
    f"non_semantic={sum(register_counts.values())} checks={checks} failures={failure_count}"
)
raise SystemExit(1 if failure_count else 0)
