#!/usr/bin/env python3
"""
compare_steps.py — Compare which packages each build step's attestation saw.

This is a POST-ANALYSIS tool, not an experiment. It reads the decoded
attestations that experiment.py / run_batch.py already produced and asks a
research question:

    For this project, does attesting only the build step capture every
    dependency — or do other steps (notably test) reveal packages the build
    step never touched?

That question is the heart of the SBOM-coverage work: static-build languages
(Go, Rust) are expected to expose all runtime dependencies at build time, while
dynamic ones (Python, Node.js) may only reveal some during test. This tool
turns that expectation into measured data.

How it works, per project:
  1. Read experiments/<project>/attestations/decoded/*.decoded.json
  2. For each step file, run attestation.extract_used_packages()
  3. Split steps into "build-like" and "other"
  4. Report: packages common to both, build-only, and other-only

Requires that experiment.py (or run_batch.py) has already run for the
project(s) — the decoded/ directory must exist.

Usage:
  python3 compare_steps.py --project go-tuf      # one project
  python3 compare_steps.py --all                 # every project in projects.txt
  python3 compare_steps.py --project go-tuf --json-only
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from core import attestation


SCRIPT_DIR      = Path(__file__).resolve().parent
EXPERIMENTS_DIR = SCRIPT_DIR / "experiments"
DEFAULT_LIST    = SCRIPT_DIR / "projects.txt"

# A step is treated as "build-like" if its name contains any of these.
# This is a heuristic: build targets are named inconsistently across projects
# (build, go-build, bin/crio, compile, ...). It is intentionally simple and
# can be refined as more projects are observed.
BUILD_STEP_HINTS = ("build", "compile", "default")


def is_build_step(step_name: str) -> bool:
    """True if a step name looks like a build step (heuristic)."""
    low = step_name.lower()
    return any(hint in low for hint in BUILD_STEP_HINTS)


def step_name_from_file(decoded_file: Path) -> str:
    """Recover the step name from a decoded filename.

    collect() writes 'build.json' -> 'decoded/build.decoded.json', so the step
    name is the filename with the '.decoded.json' suffix removed.
    """
    name = decoded_file.name
    if name.endswith(".decoded.json"):
        return name[: -len(".decoded.json")]
    return decoded_file.stem


def analyze_project(project: str) -> dict | None:
    """Analyze one project's decoded attestations.

    Returns a result dict, or None if the project has no decoded attestations
    (experiment.py was never run for it, or produced nothing).
    """
    decoded_dir = EXPERIMENTS_DIR / project / "attestations" / "decoded"
    if not decoded_dir.is_dir():
        print(f"  [{project}] no decoded attestations at {decoded_dir}")
        print(f"  [{project}] run experiment.py for it first.")
        return None

    decoded_files = sorted(decoded_dir.glob("*.decoded.json"))
    if not decoded_files:
        print(f"  [{project}] decoded/ exists but is empty.")
        return None

    # Per-step analysis.
    steps: dict[str, dict] = {}
    for f in decoded_files:
        step = step_name_from_file(f)
        pkg_info = attestation.extract_used_packages(f)
        steps[step] = {
            "is_build": is_build_step(step),
            "go_packages": pkg_info["go_packages"],
            "category_counts": pkg_info["category_counts"],
            "total_files": pkg_info["total_files"],
        }

    # Union of Go packages across build-like steps vs other steps.
    build_pkgs: set[str] = set()
    other_pkgs: set[str] = set()
    for step, info in steps.items():
        target = build_pkgs if info["is_build"] else other_pkgs
        target.update(info["go_packages"])

    common      = build_pkgs & other_pkgs
    build_only  = build_pkgs - other_pkgs
    other_only  = other_pkgs - build_pkgs   # packages ONLY non-build steps saw

    return {
        "project": project,
        "steps": steps,
        "comparison": {
            "build_step_count": sum(1 for s in steps.values() if s["is_build"]),
            "other_step_count": sum(1 for s in steps.values()
                                    if not s["is_build"]),
            "build_packages": sorted(build_pkgs),
            "other_packages": sorted(other_pkgs),
            "common": sorted(common),
            "build_only": sorted(build_only),
            "other_only": sorted(other_only),
        },
    }


def print_report(result: dict) -> None:
    """Print a human-readable comparison table for one project."""
    project = result["project"]
    steps = result["steps"]
    comp = result["comparison"]
    bar = "=" * 68

    print()
    print(bar)
    print(f"  Step coverage comparison — {project}")
    print(bar)

    # ── Per-step breakdown ────────────────────────────────────────────────────
    print()
    print(f"  {'step':<24}{'kind':<8}{'go pkgs':>9}{'files':>9}"
          f"{'other':>9}")
    print(f"  {'-' * 24}{'-' * 8}{'-' * 9}{'-' * 9}{'-' * 9}")
    for step, info in steps.items():
        kind = "build" if info["is_build"] else "other"
        cc = info["category_counts"]
        non_go = cc["system_lib"] + cc["project"] + cc["other"]
        print(f"  {step:<24}{kind:<8}"
              f"{len(info['go_packages']):>9}"
              f"{info['total_files']:>9}"
              f"{non_go:>9}")

    # ── Build vs other ────────────────────────────────────────────────────────
    print()
    print(f"  Build-like steps : {comp['build_step_count']}  "
          f"({len(comp['build_packages'])} Go packages total)")
    print(f"  Other steps      : {comp['other_step_count']}  "
          f"({len(comp['other_packages'])} Go packages total)")
    print()
    print(f"  Common to both         : {len(comp['common'])}")
    print(f"  Build-only             : {len(comp['build_only'])}")
    print(f"  Other-only (build miss): {len(comp['other_only'])}")

    # The headline result: packages that ONLY non-build steps revealed.
    # If this is non-empty, attesting build alone would miss them.
    if comp["other_only"]:
        print()
        print("  >>> Packages seen ONLY outside the build step:")
        for pkg in comp["other_only"]:
            print(f"        {pkg}")
        print("  >>> Attesting only the build step would miss these.")
    else:
        print()
        print("  >>> No packages are exclusive to non-build steps.")
        print("  >>> For this project, the build step covers all Go packages.")

    print(bar)


def save_json(result: dict) -> Path:
    """Write the result to experiments/<project>/step_comparison.json."""
    out_path = EXPERIMENTS_DIR / result["project"] / "step_comparison.json"
    out_path.write_text(json.dumps(result, indent=2))
    return out_path


def read_project_list(list_path: Path) -> list[str]:
    """Read project names from projects.txt (blank / '#' lines ignored)."""
    if not list_path.exists():
        print(f"ERROR: project list not found: {list_path}", file=sys.stderr)
        sys.exit(2)
    names: list[str] = []
    for raw in list_path.read_text().splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            names.append(line)
    return names


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare per-step package coverage from decoded "
                    "attestations.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python3 compare_steps.py --project go-tuf\n"
               "  python3 compare_steps.py --all",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--project", help="Analyze a single project.")
    group.add_argument("--all", action="store_true",
                       help="Analyze every project in projects.txt.")
    parser.add_argument("--list", default=str(DEFAULT_LIST),
                        help=f"Project list file (default: {DEFAULT_LIST.name}).")
    parser.add_argument("--json-only", action="store_true",
                        help="Write JSON but do not print the table.")
    args = parser.parse_args()

    if args.all:
        projects = read_project_list(Path(args.list))
    else:
        projects = [args.project]

    analyzed = 0
    for project in projects:
        result = analyze_project(project)
        if result is None:
            continue
        analyzed += 1
        if not args.json_only:
            print_report(result)
        out = save_json(result)
        print(f"  [{project}] comparison saved to: {out}")

    print()
    print(f"Analyzed {analyzed}/{len(projects)} project(s).")
    if analyzed == 0:
        # Nothing analyzed — likely experiment.py was never run.
        sys.exit(1)


if __name__ == "__main__":
    main()