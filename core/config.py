#!/usr/bin/env python3
"""
config.py — Centralized constants for the SBOMit pipeline.

Everything here is pure data: no imports from other sbomit modules, no logic.
This is deliberately the bottom of the dependency graph so every other module
can import it without risk of a cycle.

Previously these constants were scattered across the top of run_pipeline.py.
Collecting them here means:
  - Adding per-project skip rules (e.g. for cri-o / cubefs) is a one-place edit.
  - The curation policy is visible as data, separate from execution logic.
"""

from __future__ import annotations


# ──────────────────────────────────────────────────────────────────────────────
# Global skip set — targets never worth attesting, in ANY project.
# These are Makefile bookkeeping targets, not real build steps.
# ──────────────────────────────────────────────────────────────────────────────
GLOBAL_SKIP: set[str] = set()

# ──────────────────────────────────────────────────────────────────────────────
# Per-project skip sets — targets to skip for a specific project.
#
# The pipeline attests every detected target by default. For large projects
# that produces a lot of noise: release/docs/lint/codegen targets fail or are
# irrelevant to the build-provenance SBOM we care about. Listing them here keeps
# the experiment focused on real build steps.
#
# NOTE (cri-o / cubefs): these two are the projects from the recent failure
# reports. cri-o attempted 70 steps with 46 failures; many failures were
# non-build targets (release, prettier, docs-validation, push-oci-artifacts,
# completions-generation, ...). They are good candidates to add here once the
# curation policy is confirmed with the professor — left empty for now so this
# refactor stays behavior-preserving.
# ──────────────────────────────────────────────────────────────────────────────
PROJECT_SKIP: dict[str, set[str]] = {
    "kyverno":  set(),
    "argo-cd":  set(),
    "flux2":    set(),
    "protobom": set(),
    "in-toto":  set(),
}

# ──────────────────────────────────────────────────────────────────────────────
# Helper: resolve the effective skip set for a project.
# ──────────────────────────────────────────────────────────────────────────────
def skip_set_for(project_name: str | None, extra: set[str] | None = None) -> set[str]:
    """Return the full set of step names to skip for a given project.

    Combines:
      - GLOBAL_SKIP (always),
      - PROJECT_SKIP[project_name] (if the project has specific rules),
      - extra (e.g. targets passed on the command line via --skip-targets).

    Robustness: GLOBAL_SKIP / PROJECT_SKIP entries are coerced to sets before
    use. This matters because an empty `{}` in the source is a *dict*, not a
    set (an empty set must be written `set()`), and commenting out every entry
    of a `{...}` block silently leaves an empty dict behind. Coercing here
    means such a slip degrades to "skip nothing", not a TypeError that blocks
    every configured project.

    Args:
        project_name: Project directory name, or None.
        extra:        Additional step names to skip (optional).

    Returns:
        A new set; callers may mutate it freely.
    """
    result: set[str] = set(GLOBAL_SKIP)

    if project_name and project_name in PROJECT_SKIP:
        entry = PROJECT_SKIP[project_name]
        # set(dict) yields the dict's KEYS, so a properly-written skip set and
        # an accidental empty/explicit dict both coerce sensibly here.
        result |= set(entry)

    if extra:
        result |= set(extra)

    return result