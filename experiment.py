#!/usr/bin/env python3
"""
experiment.py — SBOMit pipeline experiment driver.

This is the single entry point. A human runs it; everything in core/ is a
library it composes.

What it does, for one project:
  1. Run the attestation pipeline           -> core.pipeline.run()
  2. Collect + decode the attestations      -> core.attestation.collect()
  3. Upload them and fetch SBOMs            -> core.sbom_server.SbomServer
  4. Write a result.json + summary.txt report

How this differs from the old experiment.py:
  - The old version launched run_pipeline.py as a SUBPROCESS and rebuilt its
    state by regex-parsing stdout ("OK: <step>" lines). That fragile contract
    is gone: pipeline.run() is imported and returns a ProjectResult object.
  - Per-step logs, environment-hygiene results, and decode counts are now real
    data on those objects, so the report can show *why* a step failed instead
    of just listing its name.

Usage:
  sudo -E python3 experiment.py --project curl

  (witness needs root for the eBPF attestor. Note: if git complains about
   "dubious ownership" under sudo, run without sudo and let witness_runner's
   per-step `sudo witness ...` handle privilege escalation instead.)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from core import attestation, pipeline
from core.sbom_server import SbomServer


# ── Locations & server config (env-overridable, matching the old script) ──────
SCRIPT_DIR    = Path(__file__).resolve().parent
SBOMIT_DIR    = Path(os.environ.get("SBOMIT_DIR", SCRIPT_DIR))
PROJECTS_BASE = Path(os.environ.get("PROJECTS_BASE", SBOMIT_DIR / "projects"))
EXPERIMENTS_DIR = SBOMIT_DIR / "experiments"

SERVER_URL   = os.environ.get("SERVER_URL", "http://10.10.20.2:5000")
SERVER_TOKEN = os.environ.get("SERVER_TOKEN", "sbomit-dev-token")


# ── Small logging helper ──────────────────────────────────────────────────────
def log(msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def die(msg: str, code: int = 2) -> None:
    # Exit code 2 (not 1): a batch runner reads exit 1 as "pipeline ran but no
    # SBOM" and exit 2 as "could not run the experiment at all" (bad project
    # path, missing inputs). Keeping these distinct lets the batch summary
    # report them separately.
    print(f"[experiment] ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


# ──────────────────────────────────────────────────────────────────────────────
# Report writers.
#
# The report surfaces the data the refactor made available: per-step log paths,
# failure exit codes, environment-hygiene results, and decode counts. The old
# summary listed failed steps by name only — which is exactly why the cri-o /
# cubefs reports said "no output captured". Now each failed step points at its
# log file.
# ──────────────────────────────────────────────────────────────────────────────
def write_result_json(experiment_dir, project_result, collect_result,
                       upload_result, sbom_results) -> dict:
    """Write machine-readable result.json.

    Most of the structure comes straight from ProjectResult.to_dict() (which
    already serializes steps and hygiene). This function adds the attestation
    collection and SBOM-generation sections.
    """
    result = project_result.to_dict()
    result["completed_at"] = datetime.now(timezone.utc).isoformat()

    result["attestations"] = {
        "collected": len(collect_result.original_files),
        "decoded": collect_result.decoded_count,
        "decode_failed": collect_result.failed_count,
        "uploaded": upload_result.succeeded if upload_result else 0,
        "upload_attempted": upload_result.attempted if upload_result else 0,
        "notes": collect_result.notes
        + (upload_result.notes if upload_result else []),
    }

    result["sbom_generation"] = {
        fmt: r.to_dict() for fmt, r in sbom_results.items()
    }

    out_path = experiment_dir / "result.json"
    out_path.write_text(json.dumps(result, indent=2))
    return result


def write_summary_txt(experiment_dir, project_result, collect_result,
                      upload_result, sbom_results) -> str:
    """Write a human-readable summary.txt and return its text.

    Sections: header, environment hygiene, step results (with log paths for
    failures), attestations, SBOM generation, verdict.
    """
    L: list[str] = []
    bar = "=" * 64

    # ── Header ────────────────────────────────────────────────────────────────
    L.append(bar)
    L.append(f"  SBOMit Experiment Report — {project_result.project}")
    L.append(bar)
    L.append("")
    L.append(f"  Build system : {project_result.build_system}")
    L.append(f"  Duration     : {project_result.duration_s}s")
    L.append(f"  Pipeline exit: {project_result.exit_code}")
    L.append("")

    # ── Environment hygiene ───────────────────────────────────────────────────
    L.append("  Environment hygiene:")
    hy = project_result.hygiene
    if hy is None:
        L.append("    (not recorded)")
    else:
        if hy.git_clean_ran:
            L.append(f"    git clean    : removed {hy.git_clean_removed} "
                     f"untracked path(s)")
        else:
            L.append("    git clean    : not run")
        if hy.go_cache_normalized:
            L.append(f"    go cache     : normalized to '{hy.go_cache_owner}'")
        else:
            L.append("    go cache     : not normalized")
        L.append(f"    caches warmed: {', '.join(hy.caches_warmed) or 'none'}")
        for note in hy.notes:
            L.append(f"    NOTE: {note}")
    L.append("")

    # ── Step results ──────────────────────────────────────────────────────────
    L.append("  Step results:")
    steps = project_result.steps
    if not steps:
        L.append("    (no steps — build system may be unsupported)")
    else:
        for s in steps:
            if s.ok:
                L.append(f"    [OK  ] {s.name}")
            elif s.skipped:
                L.append(f"    [SKIP] {s.name}")
            else:
                # Failed: point at the captured log — the whole reason the
                # refactor started. Include exit code for a quick signal.
                log_name = s.log_path.name if s.log_path else "no log"
                L.append(f"    [FAIL] {s.name}  "
                         f"(exit {s.exit_code}, log: {log_name})")
        L.append("")
        L.append(f"    Total: {len(project_result.ok_steps)}/{len(steps)} "
                 f"steps OK, {len(project_result.failed_steps)} failed, "
                 f"{len(project_result.skipped_steps)} skipped")
    L.append("")

    # ── Attestations ──────────────────────────────────────────────────────────
    L.append("  Attestations:")
    L.append(f"    Collected : {len(collect_result.original_files)}")
    L.append(f"    Decoded   : {collect_result.decoded_count} "
             f"(failed: {collect_result.failed_count})")
    if upload_result:
        L.append(f"    Uploaded  : {upload_result.succeeded}"
                 f"/{upload_result.attempted}")
    else:
        L.append("    Uploaded  : 0 (upload not attempted)")
    L.append("")

    # ── SBOM generation ───────────────────────────────────────────────────────
    L.append("  SBOM generation (eBPF only, no syft catalog):")
    if not sbom_results:
        L.append("    (not attempted)")
    else:
        for fmt, r in sbom_results.items():
            if r.success:
                L.append(f"    [OK  ] {fmt:10s} {r.packages} packages, "
                         f"{r.size_bytes} bytes")
            else:
                L.append(f"    [FAIL] {fmt:10s} {r.error}")
    L.append("")

    # ── Verdict ───────────────────────────────────────────────────────────────
    # Coverage metric (current definition): did SBOM files get generated?
    L.append("  Verdict:")
    if sbom_results:
        all_ok = all(r.success for r in sbom_results.values())
        any_pkgs = any(r.packages > 0 for r in sbom_results.values()
                       if r.success)
        if all_ok and any_pkgs:
            L.append("    SBOM generation: SUCCESS")
        elif all_ok:
            L.append("    SBOM generation: PARTIAL (formats ok but empty)")
        else:
            L.append("    SBOM generation: FAILED (one or more formats failed)")
    else:
        L.append("    SBOM generation: NOT ATTEMPTED (no attestations)")
    L.append("")
    L.append(bar)

    summary = "\n".join(L)
    (experiment_dir / "summary.txt").write_text(summary)
    return summary


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the SBOMit pipeline experiment on a project.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  sudo -E python3 experiment.py --project curl",
    )
    parser.add_argument(
        "--project", required=True,
        help="Project name (a directory under projects/).",
    )
    parser.add_argument(
        "--skip-targets", default="",
        help="Comma-separated extra step names to skip.",
    )
    parser.add_argument(
        "--only", default="",
        help="Comma-separated step names to run EXCLUSIVELY; every other "
             "detected step is skipped. Useful for checking just the build "
             "step of a large project, e.g. --only build. If a named step "
             "does not exist in the project, the run aborts and lists the "
             "available steps.",
    )
    # Hygiene toggles — default on, surfaced for debugging (see environment.py).
    parser.add_argument("--no-git-clean", action="store_true",
                        help="Do not run 'git clean -xfd' before building.")
    parser.add_argument("--no-go-cache", action="store_true",
                        help="Do not normalize Go module cache ownership.")
    parser.add_argument("--no-warm", action="store_true",
                        help="Do not pre-warm dependency caches.")
    args = parser.parse_args()

    project_name = args.project
    project_path = PROJECTS_BASE / project_name

    if not project_path.exists():
        die(f"Project directory not found: {project_path}")
    if not project_path.is_dir():
        die(f"Not a directory: {project_path}")

    # Prepare the experiment output directory.
    experiment_dir = EXPERIMENTS_DIR / project_name
    experiment_dir.mkdir(parents=True, exist_ok=True)
    (experiment_dir / "sboms").mkdir(exist_ok=True)

    log("=" * 60)
    log(f"SBOMit Experiment — project: {project_name}")
    log(f"  SBOMIT_DIR     : {SBOMIT_DIR}")
    log(f"  Project path   : {project_path}")
    log(f"  Experiment dir : {experiment_dir}")
    log(f"  Server         : {SERVER_URL}")
    log("=" * 60)

    skip_targets = {t.strip() for t in args.skip_targets.split(",") if t.strip()}
    only = {t.strip() for t in args.only.split(",") if t.strip()}

    # ── Step 1: run the attestation pipeline ──────────────────────────────────
    # No subprocess, no stdout parsing — a ProjectResult comes back directly.
    log("Step 1: running attestation pipeline")
    if only:
        log(f"  --only active: running just {sorted(only)}")
    try:
        project_result = pipeline.run(
            project_path,
            skip_targets=skip_targets,
            only=only or None,
            do_git_clean=not args.no_git_clean,
            do_go_cache=not args.no_go_cache,
            do_warm=not args.no_warm,
        )
    except pipeline.PipelineConfigError as e:
        # A bad --only (a step name that does not exist) is a user mistake;
        # die() exits 2 so the batch / caller sees "could not run", not
        # "ran but produced no SBOM".
        die(str(e))
    log(f"  build system: {project_result.build_system}")
    log(f"  steps: {len(project_result.ok_steps)} ok, "
        f"{len(project_result.failed_steps)} failed, "
        f"{len(project_result.skipped_steps)} skipped")

    # ── Step 2: collect + decode attestations ─────────────────────────────────
    log("Step 2: collecting attestations")
    src_dir = SBOMIT_DIR / "attestations" / project_name
    dst_dir = experiment_dir / "attestations"
    collect_result = attestation.collect(src_dir, dst_dir)
    log(f"  collected {len(collect_result.original_files)} file(s); "
        f"decoded {collect_result.decoded_count}, "
        f"failed {collect_result.failed_count}")
    for note in collect_result.notes:
        log(f"  NOTE: {note}")

    # ── Step 3: upload attestations and fetch SBOMs ───────────────────────────
    server = SbomServer(SERVER_URL, SERVER_TOKEN)
    upload_result = None
    sbom_results = {}

    if collect_result.original_files:
        log("Step 3: uploading attestations and fetching SBOMs")
        server.clear(project_name)
        upload_result = server.upload(collect_result.original_files)
        log(f"  uploaded {upload_result.succeeded}/{upload_result.attempted}")
        for note in upload_result.notes:
            log(f"  NOTE: {note}")

        if upload_result.succeeded > 0:
            sbom_results = server.fetch_sboms(experiment_dir / "sboms")
            for fmt, r in sbom_results.items():
                status = "OK" if r.success else f"FAIL ({r.error})"
                log(f"  SBOM {fmt}: {status}")
        else:
            log("  skipping SBOM fetch — nothing uploaded")
    else:
        log("Step 3: skipped — no attestations were generated")

    # ── Step 4: write report ──────────────────────────────────────────────────
    log("Step 4: writing report")
    write_result_json(experiment_dir, project_result, collect_result,
                      upload_result, sbom_results)
    summary = write_summary_txt(experiment_dir, project_result, collect_result,
                                upload_result, sbom_results)
    print(summary)

    log(f"Results saved to: {experiment_dir}")

    # ── Exit code ─────────────────────────────────────────────────────────────
    # The pipeline running to completion is NOT the same as the experiment
    # succeeding. A batch runner needs to tell apart:
    #   exit 0 — SBOMs were generated (the experiment's actual goal)
    #   exit 1 — pipeline ran but produced no usable SBOM
    # A crash or bad invocation exits non-zero on its own (exception / die()),
    # so the batch runner sees three outcomes: 0, 1, and "other".
    sbom_ok = bool(sbom_results) and any(r.success for r in sbom_results.values())
    sys.exit(0 if sbom_ok else 1)


if __name__ == "__main__":
    main()