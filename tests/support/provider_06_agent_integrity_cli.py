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
import shutil
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path

BASE_COMMIT = "94e9d717be22bafcf6307efd9434fdb04754ac6a"
REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = REPO_ROOT / "tests/fixtures/provider_06_conformance/project"
AGENT_INTEGRITY_ROOT = REPO_ROOT / "third_party/agent-integrity"
CLI_PATH = AGENT_INTEGRITY_ROOT / "packages/cli/dist/cli.js"
PROTECTED_PATHS = (
    "src/integrations/provider_06/adapter.py",
    "src/integrations/provider_06/mock_endpoint.py",
    "third_party/agent-integrity/schemas/integrity-envelope.schema.json",
    "third_party/agent-integrity/schemas/integrity-receipt.schema.json",
)

_BUILD_LOCK = threading.Lock()
_BUILD_COMPLETE = False
_MAX_OUTPUT_BYTES = 128 * 1024
_BUILD_TIMEOUT_SECONDS = 180
_VERIFY_TIMEOUT_SECONDS = 30


@dataclass(frozen=True)
class VerificationResult:
    returncode: int
    stdout: dict[str, object]
    stderr: str


@dataclass(frozen=True)
class FixtureProject:
    project_root: Path
    policy_path: Path
    trusted_config_path: Path


def _executable(name: str) -> str:
    resolved = shutil.which(name)
    if resolved is None:
        raise RuntimeError(f"required executable is unavailable: {name}")
    return resolved


def _bounded(value: bytes, label: str) -> str:
    if len(value) > _MAX_OUTPUT_BYTES:
        raise RuntimeError(f"Agent Integrity {label} exceeds {_MAX_OUTPUT_BYTES} bytes")
    return value.decode("utf-8", errors="replace")


def _parse_one_object(raw: str) -> dict[str, object]:
    stripped = raw.lstrip()
    value, end = json.JSONDecoder().raw_decode(stripped)
    if stripped[end:].strip():
        raise RuntimeError("Agent Integrity stdout contains trailing content")
    if not isinstance(value, dict):
        raise RuntimeError("Agent Integrity stdout must contain one JSON object")
    return value


def ensure_agent_integrity_cli() -> None:
    global _BUILD_COMPLETE
    with _BUILD_LOCK:
        if _BUILD_COMPLETE:
            return
        node = _executable("node")
        npm = _executable("npm")
        version = subprocess.run(
            [node, "--version"],
            check=True,
            capture_output=True,
            cwd=AGENT_INTEGRITY_ROOT,
            timeout=10,
        ).stdout.decode("ascii").strip()
        try:
            major = int(version.removeprefix("v").split(".", maxsplit=1)[0])
        except (ValueError, IndexError) as error:
            raise RuntimeError(f"unrecognized Node.js version: {version}") from error
        if major < 22:
            raise RuntimeError(f"Node.js 22 or newer is required, found {version}")
        for args in ([npm, "ci"], [npm, "run", "build"]):
            completed = subprocess.run(
                args,
                check=False,
                capture_output=True,
                cwd=AGENT_INTEGRITY_ROOT,
                timeout=_BUILD_TIMEOUT_SECONDS,
            )
            if completed.returncode != 0:
                stderr = _bounded(completed.stderr, "build stderr")[-4000:]
                raise RuntimeError(f"Agent Integrity locked build failed: {stderr}")
        if not CLI_PATH.is_file():
            raise RuntimeError("Agent Integrity CLI build did not produce packages/cli/dist/cli.js")
        _BUILD_COMPLETE = True


def copy_fixture_project(tmp_path: Path) -> FixtureProject:
    project_root = tmp_path / "project"
    shutil.copytree(FIXTURE_ROOT, project_root)
    trusted_config_path = project_root / "integrity/trusted-config.json"
    config = json.loads(trusted_config_path.read_text(encoding="utf-8"))
    if config.get("projectRoot") != "__PROJECT_ROOT__":
        raise RuntimeError("committed trusted config must contain the project-root placeholder")
    config["projectRoot"] = str(project_root.resolve())
    trusted_config_path.write_text(
        json.dumps(config, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return FixtureProject(
        project_root=project_root,
        policy_path=project_root / "integrity/policy.yaml",
        trusted_config_path=trusted_config_path,
    )


def run_agent_integrity_verify(
    fixture: FixtureProject,
    request: dict[str, object],
) -> VerificationResult:
    ensure_agent_integrity_cli()
    completed = subprocess.run(
        [
            _executable("node"),
            str(CLI_PATH),
            "verify",
            "--trusted-policy",
            str(fixture.policy_path),
            "--trusted-config",
            str(fixture.trusted_config_path),
        ],
        input=json.dumps(request, separators=(",", ":"), ensure_ascii=False),
        text=True,
        encoding="utf-8",
        check=False,
        capture_output=True,
        cwd=AGENT_INTEGRITY_ROOT,
        timeout=_VERIFY_TIMEOUT_SECONDS,
    )
    stdout = _bounded(completed.stdout.encode("utf-8"), "stdout")
    stderr = _bounded(completed.stderr.encode("utf-8"), "stderr")
    try:
        parsed = _parse_one_object(stdout)
    except (json.JSONDecodeError, RuntimeError) as error:
        raise RuntimeError(f"Agent Integrity returned invalid JSON: {error}; stderr={stderr[-2000:]}") from error
    return VerificationResult(
        returncode=completed.returncode,
        stdout=parsed,
        stderr=stderr[-4000:],
    )
