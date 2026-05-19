#!/usr/bin/env python3
"""
run_batch.py — Run the SBOMit experiment across many projects in one go.

Workflow:
  1. Clone the projects you want to test into projects/.
  2. List their directory names in projects.txt (one per line).
  3. Run:  python3 run_batch.py

For each listed project this runs experiment.py as a SEPARATE PROCESS. That
process isolation is deliberate: one project crashing (a build that segfaults,
a bad witness invocation, an uncaught exception) cannot take the batch down
with it — the batch reads the child's exit code and moves on.

Exit codes from experiment.py (see experiment.py main()/die()):
    0  — SBOMs were generated          -> counted as SUCCESS
    1  — pipeline ran, no SBOM         -> counted as NO_SBOM
    2+ — could not run / crashed       -> counted as ERROR

Design decisions (chosen for this lab's workflow):
  - Failure handling: record and continue. A failed project never stops the
    batch; everything is summarized at the end.
  - Project selection: projects.txt only. Explicit list, not "everything under
    projects/", so a stray clone is not picked up by accident.
  - Re-runs: projects that already have experiments/<name>/summary.txt are
    SKIPPED, so an interrupted batch can be resumed cheaply. Use --force to
    re-run them anyway.

Usage:
  python3 run_batch.py                  # run projects.txt, skip done ones
  python3 run_batch.py --force          # re-run even completed projects
  python3 run_batch.py --list other.txt # use a different list file
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


SCRIPT_DIR      = Path(__file__).resolve().parent
EXPERIMENT_PY   = SCRIPT_DIR / "experiment.py"
PROJECTS_BASE   = SCRIPT_DIR / "projects"
EXPERIMENTS_DIR = SCRIPT_DIR / "experiments"
DEFAULT_LIST    = SCRIPT_DIR / "projects.txt"

# experiment.py exit code -> outcome label.
OUTCOME_SUCCESS = "SUCCESS"
OUTCOME_NO_SBOM = "NO_SBOM"
OUTCOME_ERROR   = "ERROR"
OUTCOME_SKIPPED = "SKIPPED"


def log(msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[batch {ts}] {msg}", flush=True)


def read_project_list(list_path: Path) -> list[str]:
    """Read project names from the list file.

    One name per line. Blank lines and lines starting with '#' are ignored,
    so the file can carry comments.
    """
    if not list_path.exists():
        log(f"ERROR: project list not found: {list_path}")
        log(f"Create it with one project name per line. Example:")
        log(f"  echo 'go-tuf' >> {list_path.name}")
        sys.exit(2)

    names: list[str] = []
    for raw in list_path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        names.append(line)
    return names


def classify(exit_code: int) -> str:
    """Map an experiment.py exit code to an outcome label."""
    if exit_code == 0:
        return OUTCOME_SUCCESS
    if exit_code == 1:
        return OUTCOME_NO_SBOM
    return OUTCOME_ERROR  # 2 and anything else


def already_done(project: str) -> bool:
    """True if this project already has a completed experiment.

    'Completed' means experiments/<project>/summary.txt exists — that file is
    written last, so its presence means the previous run reached the end.
    """
    return (EXPERIMENTS_DIR / project / "summary.txt").exists()


def run_one(project: str, only: str = "") -> tuple[str, float]:
    """Run experiment.py for a single project as a child process.

    Args:
        project: Project directory name.
        only:    If non-empty, passed straight through as experiment.py's
                 --only value (comma-separated step names). The batch does not
                 interpret it — experiment.py / pipeline.py validate it, and a
                 bad step name comes back as exit 2 (-> OUTCOME_ERROR).

    Returns (outcome_label, duration_seconds). Never raises for an ordinary
    experiment failure — the failure is encoded in the returned label.
    """
    t0 = time.time()

    cmd = [sys.executable, str(EXPERIMENT_PY), "--project", project]
    if only:
        cmd += ["--only", only]

    # The child inherits stdout/stderr, so its log streams to the console
    # live — the batch does not capture or hide it.
    try:
        proc = subprocess.run(cmd, cwd=SCRIPT_DIR)
        outcome = classify(proc.returncode)
    except KeyboardInterrupt:
        # Let Ctrl-C abort the whole batch cleanly.
        raise
    except Exception as e:
        # The batch runner itself failed to launch the child — rare, but do
        # not let it kill the batch.
        log(f"  could not launch experiment.py for {project}: {e}")
        outcome = OUTCOME_ERROR

    return outcome, round(time.time() - t0, 1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the SBOMit experiment across the projects in "
                    "projects.txt.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  python3 run_batch.py --force",
    )
    parser.add_argument(
        "--list", default=str(DEFAULT_LIST),
        help=f"Project list file (default: {DEFAULT_LIST.name}).",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Re-run projects that already have results in experiments/.",
    )
    parser.add_argument(
        "--only", default="",
        help="Comma-separated step names to run EXCLUSIVELY, applied to every "
             "project in the batch (passed through to experiment.py --only). "
             "Useful for checking just the build step across many large "
             "projects, e.g. --only build. A project that lacks a named step "
             "is reported as ERROR.",
    )
    args = parser.parse_args()

    projects = read_project_list(Path(args.list))
    if not projects:
        log(f"Project list is empty: {args.list}")
        sys.exit(0)

    log("=" * 56)
    log(f"SBOMit batch — {len(projects)} project(s) listed")
    log(f"  list file : {args.list}")
    log(f"  force     : {args.force}")
    if args.only:
        log(f"  only      : {args.only}")
    log("=" * 56)

    # results: project -> (outcome, duration)
    results: dict[str, tuple[str, float]] = {}
    batch_start = time.time()

    for i, project in enumerate(projects, 1):
        prefix = f"[{i}/{len(projects)}] {project}"

        # Validate the project directory exists before bothering to launch.
        if not (PROJECTS_BASE / project).is_dir():
            log(f"{prefix}: ERROR — not found under projects/ "
                f"(clone it first)")
            results[project] = (OUTCOME_ERROR, 0.0)
            continue

        # Skip already-completed projects unless --force.
        if not args.force and already_done(project):
            log(f"{prefix}: SKIPPED — results already exist "
                f"(use --force to re-run)")
            results[project] = (OUTCOME_SKIPPED, 0.0)
            continue

        log(f"{prefix}: starting")
        outcome, duration = run_one(project, only=args.only)
        results[project] = (outcome, duration)
        log(f"{prefix}: {outcome} ({duration}s)")

    # ── Batch summary ─────────────────────────────────────────────────────────
    total_duration = round(time.time() - batch_start, 1)
    counts = {
        OUTCOME_SUCCESS: 0, OUTCOME_NO_SBOM: 0,
        OUTCOME_ERROR: 0, OUTCOME_SKIPPED: 0,
    }
    for outcome, _ in results.values():
        counts[outcome] += 1

    print()
    log("=" * 56)
    log("Batch summary")
    log("=" * 56)
    for project, (outcome, duration) in results.items():
        suffix = f"  ({duration}s)" if duration else ""
        log(f"  {outcome:8s}  {project}{suffix}")
    log("-" * 56)
    log(f"  SUCCESS: {counts[OUTCOME_SUCCESS]}   "
        f"NO_SBOM: {counts[OUTCOME_NO_SBOM]}   "
        f"ERROR: {counts[OUTCOME_ERROR]}   "
        f"SKIPPED: {counts[OUTCOME_SKIPPED]}")
    log(f"  total time: {total_duration}s")
    log("=" * 56)

    # Exit non-zero if anything genuinely failed (NO_SBOM or ERROR), so the
    # batch can be used in a larger script / CI step. SKIPPED does not count
    # as failure.
    failed = counts[OUTCOME_NO_SBOM] + counts[OUTCOME_ERROR]
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        log("interrupted by user — stopping batch")
        sys.exit(130)