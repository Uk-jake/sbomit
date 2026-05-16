#!/usr/bin/env python3
"""
models.py — Data contracts shared across the SBOMit pipeline.

These dataclasses replace the fragile "print string + regex parsing" contract
that previously coupled experiment.py to run_pipeline.py. Instead of parsing
stdout for "OK: <step>" lines, the pipeline now returns StepResult / ProjectResult
objects directly.

Design notes:
  - StepResult carries everything a caller needs to know about one build step,
    including the path to its captured log (the missing piece that made the
    cri-o / cubefs failures impossible to diagnose).
  - failure_reason is intentionally free-form for now. Once witness_runner.py
    captures per-step output, a later step can classify it (cgo header missing,
    go cache permission denied, external tool missing, etc.).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ── Status constants ──────────────────────────────────────────────────────────
# Using a small set of string constants rather than an Enum keeps JSON
# serialization trivial (result.json) while still giving callers named values.
STATUS_OK = "ok"
STATUS_FAILED = "failed"
STATUS_SKIPPED = "skipped"


@dataclass
class StepResult:
    """Result of attesting a single build step with witness.

    Attributes:
        name:             Step / target name (e.g. "go-build", "server").
        status:           One of STATUS_OK / STATUS_FAILED / STATUS_SKIPPED.
        command:          The shell command that was attested (for the record).
        attestation_path: Path to the witness output JSON, if it was written.
        log_path:         Path to the captured stdout+stderr of this step.
                          This is the key addition — it makes per-step failure
                          diagnosis possible instead of "no output captured".
        exit_code:        Process exit code of the witness invocation.
        failure_reason:   Short human-readable cause, filled in for failed steps
                          (left None until a later classification step exists).
        duration_s:       Wall-clock duration of the step, if measured.
    """

    name: str
    status: str
    command: Optional[str] = None
    attestation_path: Optional[Path] = None
    log_path: Optional[Path] = None
    exit_code: Optional[int] = None
    failure_reason: Optional[str] = None
    duration_s: Optional[float] = None

    # ── Convenience predicates ────────────────────────────────────────────────
    @property
    def ok(self) -> bool:
        return self.status == STATUS_OK

    @property
    def failed(self) -> bool:
        return self.status == STATUS_FAILED

    @property
    def skipped(self) -> bool:
        return self.status == STATUS_SKIPPED

    def to_dict(self) -> dict:
        """Serialize for result.json. Path objects become plain strings."""
        return {
            "name": self.name,
            "status": self.status,
            "command": self.command,
            "attestation_path": str(self.attestation_path)
            if self.attestation_path else None,
            "log_path": str(self.log_path) if self.log_path else None,
            "exit_code": self.exit_code,
            "failure_reason": self.failure_reason,
            "duration_s": self.duration_s,
        }


@dataclass
class ProjectResult:
    """Result of running the full pipeline against one project.

    This is what pipeline.run() returns, replacing the dict-of-dicts that
    experiment.py used to reconstruct by parsing stdout.

    Attributes:
        project:        Project name (directory name under projects/).
        build_system:   Detected build system ("makefile", "go", "cargo", ...).
        steps:          One StepResult per attempted step, in execution order.
        exit_code:      Overall pipeline exit code.
        duration_s:     Total wall-clock duration of the pipeline.
        hygiene:        Outcome of the environment-preparation phase. Typed as
                        Optional[object] rather than environment.HygieneResult
                        to avoid an import cycle (environment.py sits below
                        models.py in the dependency graph). Any object with a
                        to_dict() method works; see environment.HygieneResult.
    """

    project: str
    build_system: Optional[str] = None
    steps: list[StepResult] = field(default_factory=list)
    exit_code: int = 0
    duration_s: Optional[float] = None
    hygiene: Optional[object] = None

    # ── Aggregate views ───────────────────────────────────────────────────────
    @property
    def ok_steps(self) -> list[StepResult]:
        return [s for s in self.steps if s.ok]

    @property
    def failed_steps(self) -> list[StepResult]:
        return [s for s in self.steps if s.failed]

    @property
    def skipped_steps(self) -> list[StepResult]:
        return [s for s in self.steps if s.skipped]

    def add(self, step: StepResult) -> StepResult:
        """Append a step result and return it (convenient for the runner)."""
        self.steps.append(step)
        return step

    def to_dict(self) -> dict:
        """Serialize for result.json."""
        # hygiene is environment.HygieneResult (a dataclass). Use asdict()
        # rather than importing the type, keeping models.py free of an
        # environment.py import. Falls back gracefully if hygiene is None or
        # is some other object.
        hygiene_dict = None
        if self.hygiene is not None:
            import dataclasses
            if dataclasses.is_dataclass(self.hygiene):
                hygiene_dict = dataclasses.asdict(self.hygiene)
            elif hasattr(self.hygiene, "to_dict"):
                hygiene_dict = self.hygiene.to_dict()

        return {
            "project": self.project,
            "build_system": self.build_system,
            "exit_code": self.exit_code,
            "duration_s": self.duration_s,
            "hygiene": hygiene_dict,
            "summary": {
                "total": len(self.steps),
                "ok": len(self.ok_steps),
                "failed": len(self.failed_steps),
                "skipped": len(self.skipped_steps),
            },
            "steps": [s.to_dict() for s in self.steps],
        }