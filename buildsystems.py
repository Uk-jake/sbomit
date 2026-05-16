#!/usr/bin/env python3
"""
buildsystems.py — Detect a project's build system and derive its build steps.

This replaces the hardcoded if/elif chain that lived inside run_pipeline():

    if (project_dir / "Makefile").exists():      ...
    elif (project_dir / "tox.ini").exists():     ...
    elif (project_dir / "go.mod").exists():      ...
    elif (project_dir / "pyproject.toml").exists(): ...
    elif (project_dir / "Cargo.toml").exists():  ...

The problem with that chain: adding a new build system (e.g. Node.js) meant
editing the function body, and the detection order was implicit in the elif
ordering. Here, build systems are DATA (the BUILD_SYSTEMS list). Adding Node.js
becomes a one-line table entry, not surgery on a function.

Two concepts:
  - detect(): which build system does this project use?
  - steps_for(): given the build system, what (step_name, command) pairs should
    be attested?

Dependency position: imports parsers.py only. No import of pipeline/runner.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from . import parsers


# ──────────────────────────────────────────────────────────────────────────────
# Build model: how build-time observation maps to runtime dependencies.
#
#   "static"  — Go, Rust: the build step links everything; observing the build
#               captures the packages used at runtime.
#   "dynamic" — Python, Node.js: imports are resolved at runtime, so the build
#               step alone is incomplete; test steps must also be attested to
#               see what is actually used.
#
# Not consumed by any logic yet. It is here so that, once the Coverage metric
# is settled with the professor, a policy ("static -> attest build only,
# dynamic -> attest build + test") can be expressed against this field instead
# of being hardcoded.
# ──────────────────────────────────────────────────────────────────────────────
BUILD_MODEL_STATIC = "static"
BUILD_MODEL_DYNAMIC = "dynamic"


@dataclass
class BuildSystem:
    """Describes one recognizable build system.

    Attributes:
        name:          Identifier ("makefile", "go", "cargo", "tox", "python").
        detect_file:   File whose presence in the project root signals this
                       build system (e.g. "go.mod").
        build_model:   BUILD_MODEL_STATIC or BUILD_MODEL_DYNAMIC.
        default_steps: Steps to attest when the build system has no build file
                       to parse (e.g. a bare go.mod). List of (name, command).
        derive_steps:  Optional callable(project_dir) -> list[(name, command)]
                       for build systems whose steps come from parsing a file
                       (Makefile, tox.ini). Takes precedence over default_steps
                       when present.
    """

    name: str
    detect_file: str
    build_model: str
    default_steps: list[tuple[str, str]] = field(default_factory=list)
    derive_steps: Optional[Callable[[Path], list[tuple[str, str]]]] = None


# ──────────────────────────────────────────────────────────────────────────────
# Step-derivation functions for parse-based build systems.
# ──────────────────────────────────────────────────────────────────────────────
def _derive_makefile_steps(project_dir: Path) -> list[tuple[str, str]]:
    """Parse the Makefile and return one (target, 'make <target>') per target.

    Mirrors the old run_pipeline() behavior, including the special case: if the
    project is a Go module whose Makefile has no 'build' target, an explicit
    'go build ./...' step is appended so the actual code still gets compiled
    and attested.

    Skip-list filtering is NOT applied here — pipeline.py applies it via
    config.skip_set_for(). This function only enumerates what exists.
    """
    targets = parsers.parse_makefile(project_dir / "Makefile")
    steps: list[tuple[str, str]] = [(t, f"make {t}") for t in targets]

    # Go project with a Makefile that lacks an explicit 'build' target:
    # ensure the code is still compiled + attested.
    if (project_dir / "go.mod").exists() and "build" not in targets:
        steps.append(("go-build", "go build ./..."))

    return steps


def _derive_tox_steps(project_dir: Path) -> list[tuple[str, str]]:
    """Parse tox.ini and return one (env, 'tox -e <env>') per environment.

    If tox.ini has no discoverable environments, fall back to a single bare
    'tox' step (matching the old behavior).
    """
    envs = parsers.parse_tox(project_dir / "tox.ini")
    if not envs:
        return [("tox", "tox")]
    return [(env, f"tox -e {env}") for env in envs]


# ──────────────────────────────────────────────────────────────────────────────
# The build system table.
#
# ORDER MATTERS: detect() returns the first match. Makefile is checked before
# go.mod / Cargo.toml because a project may have both, and the Makefile is the
# project's own description of how it wants to be built. tox.ini is checked
# before pyproject.toml for the same reason.
#
# To add Node.js, append one line — no function changes needed:
#   BuildSystem("npm", "package.json", BUILD_MODEL_DYNAMIC,
#               default_steps=[("build", "npm run build"), ("test", "npm test")]),
# ──────────────────────────────────────────────────────────────────────────────
BUILD_SYSTEMS: list[BuildSystem] = [
    BuildSystem(
        name="makefile",
        detect_file="Makefile",
        build_model=BUILD_MODEL_STATIC,  # nominal; real model depends on the
                                         # underlying language, refined later.
        derive_steps=_derive_makefile_steps,
    ),
    BuildSystem(
        name="tox",
        detect_file="tox.ini",
        build_model=BUILD_MODEL_DYNAMIC,
        derive_steps=_derive_tox_steps,
    ),
    BuildSystem(
        name="go",
        detect_file="go.mod",
        build_model=BUILD_MODEL_STATIC,
        default_steps=[
            ("go-build", "go build ./..."),
            ("go-test", "go test ./..."),
            ("go-fmt", "gofmt -l ."),
        ],
    ),
    BuildSystem(
        name="python",
        detect_file="pyproject.toml",
        build_model=BUILD_MODEL_DYNAMIC,
        default_steps=[
            ("python-build", "python3 -m build"),
        ],
    ),
    BuildSystem(
        name="cargo",
        detect_file="Cargo.toml",
        build_model=BUILD_MODEL_STATIC,
        default_steps=[
            ("build", "cargo build --all"),
            ("test", "cargo test --all"),
            ("fmt", "cargo fmt --all -- --check"),
        ],
    ),
]


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────
def detect(project_dir: Path) -> Optional[BuildSystem]:
    """Return the BuildSystem for a project, or None if none is recognized.

    Returns the FIRST entry in BUILD_SYSTEMS whose detect_file exists in the
    project root. See the table comment for why ordering matters.
    """
    for bs in BUILD_SYSTEMS:
        if (project_dir / bs.detect_file).exists():
            return bs
    return None


def steps_for(build_system: BuildSystem,
              project_dir: Path) -> list[tuple[str, str]]:
    """Return the list of (step_name, command) pairs to attest for a project.

    If the build system has a derive_steps function (Makefile, tox.ini), it is
    used. Otherwise default_steps is returned.

    The returned list is unfiltered: pipeline.py is responsible for dropping
    skipped steps via config.skip_set_for().
    """
    if build_system.derive_steps is not None:
        return build_system.derive_steps(project_dir)
    return list(build_system.default_steps)