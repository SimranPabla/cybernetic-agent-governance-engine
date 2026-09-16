# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

from tests.support.provider_06_agent_integrity_cli import (
    BASE_COMMIT,
    FIXTURE_ROOT,
    PROTECTED_PATHS,
    copy_fixture_project,
    run_agent_integrity_verify,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _request(project: Path, name: str) -> dict[str, object]:
    return json.loads((project / name).read_text(encoding="utf-8"))


def _finding_codes(result: object) -> list[str]:
    output = result.stdout  # type: ignore[attr-defined]
    findings = output.get("findings", [])
    return [finding["code"] for finding in findings if isinstance(finding, dict)]


def test_valid_fixture_returns_pass(tmp_path: Path) -> None:
    fixture = copy_fixture_project(tmp_path)
    result = run_agent_integrity_verify(fixture, _request(fixture.project_root, "request-pass.json"))
    assert (result.returncode, result.stdout["status"], _finding_codes(result)) == (0, "PASS", [])


def test_ambiguous_support_returns_review(tmp_path: Path) -> None:
    fixture = copy_fixture_project(tmp_path)
    result = run_agent_integrity_verify(fixture, _request(fixture.project_root, "request-review.json"))
    assert (result.returncode, result.stdout["status"]) == (2, "REVIEW")
    assert _finding_codes(result) == ["claim.support_ambiguous"]


def test_blocked_fixture_returns_blocked(tmp_path: Path) -> None:
    fixture = copy_fixture_project(tmp_path)
    result = run_agent_integrity_verify(fixture, _request(fixture.project_root, "request-blocked.json"))
    assert (result.returncode, result.stdout["status"]) == (3, "BLOCKED")
    assert _finding_codes(result) == ["decision.rejected"]


def test_response_mutation_never_passes(tmp_path: Path) -> None:
    fixture = copy_fixture_project(tmp_path)
    request = _request(fixture.project_root, "request-pass.json")
    envelope = request["envelope"]
    assert isinstance(envelope, dict)
    response = envelope["response"]
    assert isinstance(response, dict)
    response["content"] = f"{response['content']} Mutated."
    result = run_agent_integrity_verify(fixture, request)
    assert result.returncode != 0
    assert result.stdout.get("status") != "PASS"


def test_source_mutation_never_passes(tmp_path: Path) -> None:
    fixture = copy_fixture_project(tmp_path)
    (fixture.project_root / "docs/source.md").write_text("mutated source bytes\n", encoding="utf-8")
    result = run_agent_integrity_verify(fixture, _request(fixture.project_root, "request-pass.json"))
    assert result.returncode != 0
    assert result.stdout.get("status") != "PASS"
    assert "source.digest_mismatch" in _finding_codes(result)


def test_missing_source_never_passes(tmp_path: Path) -> None:
    fixture = copy_fixture_project(tmp_path)
    (fixture.project_root / "docs/source.md").unlink()
    result = run_agent_integrity_verify(fixture, _request(fixture.project_root, "request-pass.json"))
    assert result.returncode != 0
    assert result.stdout.get("status") != "PASS"
    assert "source.collection_failed" in _finding_codes(result)


def test_invalid_trusted_config_never_passes(tmp_path: Path) -> None:
    fixture = copy_fixture_project(tmp_path)
    config = json.loads(fixture.trusted_config_path.read_text(encoding="utf-8"))
    config["allowedRoots"] = ["not-docs"]
    fixture.trusted_config_path.write_text(json.dumps(config), encoding="utf-8")
    result = run_agent_integrity_verify(fixture, _request(fixture.project_root, "request-pass.json"))
    assert result.returncode != 0
    assert result.stdout.get("status") != "PASS"


def test_fixture_envelopes_exclude_cage_action_keys() -> None:
    forbidden = {"amount", "symbol", "magnitude", "context"}

    def visit(value: object) -> None:
        if isinstance(value, dict):
            assert forbidden.isdisjoint(value)
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    for path in sorted(FIXTURE_ROOT.glob("request-*.json")):
        visit(json.loads(path.read_text(encoding="utf-8"))["envelope"])


def test_protected_runtime_and_schema_files_match_base() -> None:
    repo_root = FIXTURE_ROOT.parents[3]
    for relative in PROTECTED_PATHS:
        expected = subprocess.run(
            ["git", "show", f"{BASE_COMMIT}:{relative}"],
            cwd=repo_root,
            check=True,
            capture_output=True,
        ).stdout
        assert (repo_root / relative).read_bytes() == expected


def test_branch_diff_introduces_no_domain_plugin_registration() -> None:
    repo_root = FIXTURE_ROOT.parents[3]
    diff = subprocess.run(
        ["git", "diff", "--no-ext-diff", "--unified=0", f"{BASE_COMMIT}...HEAD"],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    added_by_path: dict[str, list[str]] = {}
    current_path = ""
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            current_path = line.removeprefix("+++ b/")
        elif line.startswith("+") and not line.startswith("+++"):
            added_by_path.setdefault(current_path, []).append(line[1:])

    executable_added = "\n".join(
        line
        for path, lines in added_by_path.items()
        if not path.startswith("tests/")
        and Path(path).suffix in {".py", ".toml", ".cfg", ".ini"}
        for line in lines
    )
    assert "GovernanceTierPlugin" not in executable_added
    assert "InvariantModel" not in executable_added
    assert "DomainToolProvider" not in executable_added
    assert "cage.plugins" not in executable_added

    for config_path in (repo_root / "pyproject.toml", repo_root / "setup.cfg", repo_root / "setup.py"):
        if config_path.exists():
            relative = config_path.relative_to(repo_root).as_posix()
            expected = subprocess.run(
                ["git", "show", f"{BASE_COMMIT}:{relative}"],
                cwd=repo_root,
                check=True,
                capture_output=True,
            ).stdout
            assert config_path.read_bytes() == expected


def test_result_artifact_matches_live_required_scenarios(tmp_path: Path) -> None:
    artifact_path = FIXTURE_ROOT.parents[2] / "artifacts/provider_06_agent_integrity_conformance_result.json"
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    by_name = {scenario["name"]: scenario for scenario in artifact["scenarios"]}

    def observe(name: str, request_name: str, mutate: object | None = None) -> None:
        fixture = copy_fixture_project(tmp_path / name)
        request = _request(fixture.project_root, request_name)
        if callable(mutate):
            mutate(fixture, request)
        result = run_agent_integrity_verify(fixture, request)
        expected = by_name[name]["actual"]
        assert result.returncode == expected["exitCode"]
        assert result.stdout.get("status") == expected["status"]
        assert _finding_codes(result) == expected["findingCodes"]

    observe("valid_fixture", "request-pass.json")
    observe("ambiguous_support", "request-review.json")
    observe("blocked_decision", "request-blocked.json")

    def response_mutation(_fixture: object, request: dict[str, object]) -> None:
        envelope = request["envelope"]
        assert isinstance(envelope, dict)
        response = envelope["response"]
        assert isinstance(response, dict)
        response["content"] = f"{response['content']} Mutated."

    def source_mutation(fixture: object, _request_value: object) -> None:
        project_root = fixture.project_root  # type: ignore[attr-defined]
        (project_root / "docs/source.md").write_text("mutated source bytes\n", encoding="utf-8")

    def missing_source(fixture: object, _request_value: object) -> None:
        project_root = fixture.project_root  # type: ignore[attr-defined]
        (project_root / "docs/source.md").unlink()

    def invalid_config(fixture: object, _request_value: object) -> None:
        config_path = fixture.trusted_config_path  # type: ignore[attr-defined]
        config = json.loads(config_path.read_text(encoding="utf-8"))
        config["allowedRoots"] = ["not-docs"]
        config_path.write_text(json.dumps(config), encoding="utf-8")

    observe("response_mutation", "request-pass.json", response_mutation)
    observe("source_mutation", "request-pass.json", source_mutation)
    observe("missing_source", "request-pass.json", missing_source)
    observe("invalid_trusted_config", "request-pass.json", invalid_config)
    assert artifact["requiredScenariosPassed"] == 7
    assert artifact["requiredScenariosTotal"] == 7
    assert artifact["verdict"] == "PASS"


def test_prose_result_matches_machine_readable_artifact() -> None:
    artifact_path = FIXTURE_ROOT.parents[2] / "artifacts/provider_06_agent_integrity_conformance_result.json"
    prose_path = FIXTURE_ROOT.parents[3] / "docs/architecture/provider_06_agent_integrity_conformance_result.md"
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    prose = prose_path.read_text(encoding="utf-8")
    pattern = re.compile(
        r"<!-- scenario:(?P<name>\S+) expected:(?P<expected>\S+) "
        r"actual:(?P<actual>\S+) findings:(?P<findings>\S+) passed:(?P<passed>true|false) -->"
    )
    rows = {match.group("name"): match.groupdict() for match in pattern.finditer(prose)}
    assert len(rows) == artifact["requiredScenariosTotal"]
    for scenario in artifact["scenarios"]:
        row = rows[scenario["name"]]
        assert row["expected"] == f"{scenario['expected']['exitCode']}/{scenario['expected']['status']}"
        assert row["actual"] == f"{scenario['actual']['exitCode']}/{scenario['actual']['status']}"
        assert row["findings"] == (",".join(scenario["actual"]["findingCodes"]) or "-")
        assert row["passed"] == str(scenario["passed"]).lower()
