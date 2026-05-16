#!/usr/bin/env python3
"""
pipeline.py — Orchestrate witness attestation across a project's build steps.

This is the refactored core of the old run_pipeline.py. Two structural changes:

  1. Build-system detection is delegated to buildsystems.py (data-driven table)
     instead of an inline if/elif chain.

  2. run() RETURNS a ProjectResult object. The old run_pipeline() printed
     "OK:"/"FAIL:" lines and then ended; experiment.py had to launch it as a
     subprocess and regex-parse stdout to reconstruct what happened. Now a
     caller simply does:

         from sbomit import pipeline
         result = pipeline.run(project_dir)
         for step in result.failed_steps: ...

     The subprocess boundary — and the fragile string contract — is gone.

Dependency position: imports models, config, buildsystems, witness_runner.
It does NOT import experiment / sbom_server (those sit above it).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

from . import buildsystems, config
from .models import ProjectResult, StepResult, STATUS_SKIPPED
from .witness_runner import run_step


# ── Default locations ─────────────────────────────────────────────────────────
# SBOMIT_DIR is where witness, the signing key, and the attestations/ tree live.
# It can be overridden via the environment, matching experiment.py's convention.
SBOMIT_DIR = Path(os.environ.get("SBOMIT_DIR", Path(__file__).parent.parent.resolve()))


def _resolve_witness() -> str:
    """Locate the witness binary: PATH first, then alongside SBOMIT_DIR."""
    return shutil.which("witness") or str(SBOMIT_DIR / "witness")


def warm_go_cache(project_dir: Path) -> None:
    """Run 'go mod download' to populate the module cache before attestation.

    NOTE: this is kept here for behavior-preservation only. Cache warming is
    really an environment-hygiene concern and is a candidate to move into the
    upcoming environment.py — together with the Go module cache permission
    fix that the cri-o / cubefs failure reports call for ([CRIT]
    prewarm_permission_denied). Left in place for now so this refactor step
    changes structure, not behavior.
    """
    if (project_dir / "go.mod").exists():
        print("Pre-warming Go module cache...")
        result = subprocess.run(
            ["go", "mod", "download"],
            cwd=project_dir,
            capture_output=True, text=True,
        )
        lines = (result.stdout + result.stderr).strip().splitlines()
        for line in lines[-5:]:
            print(line)
        print("Go cache ready.")


def warm_cargo_cache(project_dir: Path) -> None:
    """Run 'cargo fetch' to populate the Cargo cache before attestation."""
    if (project_dir / "Cargo.toml").exists():
        print("Pre-warming Cargo cache...")
        subprocess.run(["cargo", "fetch"], cwd=project_dir, capture_output=True)
        print("Cargo cache ready.")


def run(project_dir: Path,
        skip_targets: Optional[set[str]] = None,
        prewarm: bool = False,
        witness_path: Optional[str] = None,
        signing_key: Optional[Path] = None,
        attestations_root: Optional[Path] = None) -> ProjectResult:
    """Detect the build system and attest every (non-skipped) build step.

    Args:
        project_dir:       Path to the project to build/attest.
        skip_targets:      Extra step names to skip, on top of GLOBAL_SKIP and
                           the project's PROJECT_SKIP entry.
        prewarm:           If True, warm the Go / Cargo dependency cache first.
        witness_path:      Path to the witness binary (auto-resolved if None).
        signing_key:       Path to the signing key (defaults to
                           SBOMIT_DIR/signing.key).
        attestations_root: Where per-project attestation dirs are created
                           (defaults to SBOMIT_DIR/attestations).

    Returns:
        A ProjectResult. Steps that fail to build are recorded as failed and
        the pipeline continues — a failed step is a normal outcome, not an
        error that aborts the run.
    """
    project_dir = project_dir.resolve()
    project_name = project_dir.name

    witness_path = witness_path or _resolve_witness()
    signing_key = signing_key or (SBOMIT_DIR / "signing.key")
    attestations_root = attestations_root or (SBOMIT_DIR / "attestations")

    attestation_dir = attestations_root / project_name
    attestation_dir.mkdir(parents=True, exist_ok=True)

    result = ProjectResult(project=project_name)

    # ── Detect build system ───────────────────────────────────────────────────
    build_system = buildsystems.detect(project_dir)
    if build_system is None:
        print(f"ERROR: No recognized build system in {project_dir}")
        result.exit_code = 1
        return result  # return, not sys.exit — the caller decides what to do

    result.build_system = build_system.name
    print(f"Detected: {build_system.name} ({build_system.detect_file})")

    # ── Pre-warm dependency caches if requested ───────────────────────────────
    if prewarm:
        warm_go_cache(project_dir)
        warm_cargo_cache(project_dir)

    # ── Derive steps and apply skip curation ──────────────────────────────────
    steps = buildsystems.steps_for(build_system, project_dir)
    if not steps:
        print(f"WARNING: no build steps derived for {project_name}")

    skip_set = config.skip_set_for(project_name, extra=skip_targets)

    # ── Run from inside the project directory ─────────────────────────────────
    # witness / make / go are invoked with the project as the working dir.
    prev_cwd = Path.cwd()
    t0 = time.time()
    try:
        os.chdir(project_dir)
        for step_name, cmd in steps:
            if step_name in skip_set:
                print(f"SKIP: {step_name}")
                result.add(StepResult(name=step_name,
                                      status=STATUS_SKIPPED,
                                      command=cmd))
                continue

            step_result = run_step(
                step_name=step_name,
                cmd=cmd,
                attestation_dir=attestation_dir,
                witness_path=witness_path,
                signing_key=signing_key,
                skip_set=skip_set,
            )
            result.add(step_result)
    finally:
        os.chdir(prev_cwd)  # always restore cwd, even if a step raises

    result.duration_s = round(time.time() - t0, 1)

    # ── Summary line ──────────────────────────────────────────────────────────
    print(f"\nDone. {len(result.ok_steps)}/{len(result.steps)} steps OK "
          f"({len(result.failed_steps)} failed, {len(result.skipped_steps)} skipped)")
    print(f"Attestations saved to: {attestation_dir}")

    return result