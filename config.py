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
GLOBAL_SKIP: set[str] = {
    "help", "all", "clean", "distclean", "mrproper",
    ".PHONY", ".DEFAULT", ".SUFFIXES",
}


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
    "kyverno": {
        "install-tools", "build-images", "ko-build", "docker-build",
        "kind-create-cluster", "kind-delete-cluster", "deploy",
    },
    "argo-cd": {
        "mockgen", "gogen", "protogen", "protogen-fast", "openapigen",
        "clientgen", "clidocsgen", "actionsdocsgen", "resourceiconsgen",
        "codegen", "codegen-local", "codegen-local-fast",
        "notification-catalog", "notification-docs",
        "build-ui", "dep-ui", "dep-ui-local", "lint-ui", "lint-ui-local",
        "image", "armimage", "builder-image", "test-tools-image",
        "test-e2e", "test-e2e-local", "start-e2e", "start-e2e-local",
        "debug-test-server", "debug-test-client", "start-test-k8s",
        "install-tools-local", "install-test-tools-local",
        "install-codegen-tools-local", "install-go-tools-local",
        "release", "release-cli", "release-precheck",
        "build-docs", "build-docs-local", "serve-docs", "serve-docs-local",
        "manifests", "manifests-local",
        "checksums", "snyk-container-tests", "snyk-non-container-tests",
        "snyk-report", "list", "start", "start-local", "run",
        "mod-vendor", "mod-vendor-local", "mod-download-local", "mod-download",
    },
    "flux2": {
        "setup-kind", "cleanup-kind", "e2e", "test-with-kind",
        "install-envtest", "setup-envtest", "envtest",
        "setup-bootstrap-patch", "setup-image-automation", "tidy", "mod-tidy",
    },
    "protobom": {
        "proto",
        "help", "conformance-test", "conformance", "fakes",
        "buf-format", "buf-lint",
    },
    "in-toto": {
        # Permission tests fail under sudo (root bypasses DAC checks).
        # Affects py310, py311, py39, with-sslib-main.
        "py310", "py311", "py39", "with-sslib-main",
        # Python 3.8 incompatible with attrs>=26.0 (project dependency).
        "py38",
    },
}


# ──────────────────────────────────────────────────────────────────────────────
# Trace policy — which steps should / should not use witness --trace.
#
# Currently informational: run_step() in witness_runner.py passes --trace
# unconditionally (matching the old behavior, where get_trace_flag was commented
# out). These sets are kept so a future change can reintroduce selective tracing
# without re-deriving the policy.
# ──────────────────────────────────────────────────────────────────────────────
NO_TRACE_STEPS: set[str] = {"test", "go-test", "install-tools"}
DEEP_TRACE_STEPS: set[str] = {"build", "install"}


# ──────────────────────────────────────────────────────────────────────────────
# Helper: resolve the effective skip set for a project.
# ──────────────────────────────────────────────────────────────────────────────
def skip_set_for(project_name: str | None, extra: set[str] | None = None) -> set[str]:
    """Return the full set of step names to skip for a given project.

    Combines:
      - GLOBAL_SKIP (always),
      - PROJECT_SKIP[project_name] (if the project has specific rules),
      - extra (e.g. targets passed on the command line via --skip-targets).

    Args:
        project_name: Project directory name, or None.
        extra:        Additional step names to skip (optional).

    Returns:
        A new set; callers may mutate it freely.
    """
    result: set[str] = set(GLOBAL_SKIP)
    if project_name and project_name in PROJECT_SKIP:
        result |= PROJECT_SKIP[project_name]
    if extra:
        result |= extra
    return result