#!/usr/bin/env python3
"""
environment.py — Environment hygiene for the SBOMit pipeline.

This module addresses the [CRIT] diagnostics from the cri-o / cubefs failure
reports — the problems that no amount of "install the build tool" can fix:

  [CRIT] prewarm_permission_denied
      The Go module cache (~/go/pkg/mod) ends up with a mix of root-owned and
      user-owned files. Cause: experiment.py runs as the normal user (it must,
      because of git's "dubious ownership" check), but witness_runner runs the
      build under `sudo` (eBPF needs root). Root-created cache files then block
      later user-level steps with "permission denied".
      -> normalize_go_cache() makes the cache consistently one owner.

  cubefs "File exists" on build/out/snappy-1.1.7/build
      Stale build artifacts from a previous run survive into the next run.
      Those artifact directories are .gitignore'd, so only `git clean -x`
      removes them.
      -> reset_project() runs `git clean -xfd`.

Also hosts dependency-cache warming (moved here from pipeline.py): warming is a
hygiene concern, and keeping it next to the cache permission fix keeps all
"prepare the environment" logic in one place.

Design:
  - prepare_environment() is the single entry point pipeline.run() calls before
    attesting any step. It always runs (per the agreed policy) but each
    sub-action is individually controllable for debugging.
  - Nothing here raises on ordinary failure: hygiene is best-effort. A failed
    `git clean` should be reported, not abort the experiment.

Dependency position: imports nothing from other sbomit modules.
"""

from __future__ import annotations

import os
import pwd
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


# ──────────────────────────────────────────────────────────────────────────────
# Result type — so callers/reports can see what hygiene did.
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class HygieneResult:
    """Outcome of the environment-preparation phase."""
    git_clean_ran: bool = False
    git_clean_removed: int = 0          # number of paths reported removed
    go_cache_normalized: bool = False
    go_cache_owner: Optional[str] = None
    caches_warmed: list[str] = None     # e.g. ["go", "cargo"]
    notes: list[str] = None             # human-readable warnings / skips

    def __post_init__(self):
        if self.caches_warmed is None:
            self.caches_warmed = []
        if self.notes is None:
            self.notes = []


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────
def _run(cmd: list[str], cwd: Optional[Path] = None) -> subprocess.CompletedProcess:
    """Run a command, capturing output, never raising.

    If the executable itself is missing (e.g. 'go' or 'cargo' not installed),
    subprocess.run raises FileNotFoundError. Hygiene is best-effort, so we
    convert that into a non-zero CompletedProcess instead — callers already
    branch on returncode, so a missing tool is reported, not crashed on.
    """
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    except FileNotFoundError:
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=127,  # conventional shell code for "command not found"
            stdout="",
            stderr=f"{cmd[0]}: command not found",
        )


def _invoking_user() -> str:
    """Return the login name of the real user behind the process.

    When the pipeline runs under sudo, os.getlogin()/SUDO_USER identifies the
    human; getpass would return 'root'. We want the human's name because the
    Go cache lives under their home directory.
    """
    # SUDO_USER is set by sudo to the original user.
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        return sudo_user
    return pwd.getpwuid(os.getuid()).pw_name


# ──────────────────────────────────────────────────────────────────────────────
# 1. Project reset — git clean
# ──────────────────────────────────────────────────────────────────────────────
def _looks_like_permission_error(text: str) -> bool:
    """True if git output indicates it could not touch files due to ownership.

    After a `sudo witness ...` build, leftover files in the project directory
    are root-owned; a non-root `git clean` then reports 'Permission denied'
    while trying to open/remove them.
    """
    t = text.lower()
    return "permission denied" in t


def _reclaim_ownership(project_dir: Path, owner: str) -> tuple[bool, str]:
    """chown the project directory back to `owner`, using sudo.

    Needed because eBPF forces builds to run under sudo, so each run leaves
    root-owned artifacts behind that a later non-root `git clean` cannot
    remove. Reclaiming ownership lets the normal-user git clean succeed,
    without ever running git itself as root (which would trip git's
    "dubious ownership" check).

    Returns (ok, message).
    """
    r = _run(["sudo", "chown", "-R", owner, str(project_dir)])
    if r.returncode == 0:
        return True, f"reclaimed ownership of {project_dir} to '{owner}'"
    return False, f"sudo chown failed: {r.stderr.strip() or 'unknown error'}"


def reset_project(project_dir: Path, enabled: bool = True) -> tuple[bool, int, list[str]]:
    """Reset a project to a pristine state with `git clean -xfd`.

    Why -xfd:
      -f  required by git to actually delete anything
      -d  also remove untracked directories
      -x  ALSO remove .gitignore'd files — build artifacts (cubefs's
          build/out/snappy-1.1.7/) are gitignored, so without -x they survive
          and cause "File exists" failures on the next run.

    This only removes UNTRACKED content. Tracked source files are never
    touched, so a freshly cloned project is unaffected and a re-used project
    is returned to its as-cloned state.

    Root-owned leftovers: a previous run's `sudo witness ...` steps create
    root-owned files in the project directory. A non-root `git clean` cannot
    delete those and fails with 'Permission denied'. When that is detected,
    this function runs `sudo chown -R <user>` once to reclaim ownership, then
    retries the clean. git itself is never run as root, so git's
    "dubious ownership" protection is not triggered.

    Args:
        project_dir: Project root (must contain a .git directory).
        enabled:     If False, skip (returns immediately). For debugging.

    Returns:
        (ran, removed_count, notes)
    """
    notes: list[str] = []

    if not enabled:
        notes.append("git clean skipped (disabled by caller)")
        return False, 0, notes

    if not (project_dir / ".git").exists():
        notes.append(f"git clean skipped: {project_dir} is not a git repo")
        return False, 0, notes

    # --dry-run first so we can count and report what will be removed.
    dry = _run(["git", "clean", "-xfd", "--dry-run"], cwd=project_dir)

    # If the dry-run hit permission errors, reclaim ownership and retry once.
    if dry.returncode != 0 and _looks_like_permission_error(
            dry.stderr + dry.stdout):
        owner = _invoking_user()
        ok, msg = _reclaim_ownership(project_dir, owner)
        notes.append(msg)
        if ok:
            dry = _run(["git", "clean", "-xfd", "--dry-run"], cwd=project_dir)

    if dry.returncode != 0:
        # Still failing — surface the reason (dubious ownership, or a chown
        # that did not resolve it) and skip rather than abort the experiment.
        msg = dry.stderr.strip() or "git clean --dry-run failed"
        notes.append(f"git clean could not run: {msg}")
        return False, 0, notes

    would_remove = [ln for ln in dry.stdout.splitlines()
                    if ln.startswith("Would remove")]

    actual = _run(["git", "clean", "-xfd"], cwd=project_dir)

    # The actual clean can still hit permission errors if new root-owned files
    # appeared between dry-run and now; reclaim + retry once more.
    if actual.returncode != 0 and _looks_like_permission_error(
            actual.stderr + actual.stdout):
        owner = _invoking_user()
        ok, msg = _reclaim_ownership(project_dir, owner)
        notes.append(msg)
        if ok:
            actual = _run(["git", "clean", "-xfd"], cwd=project_dir)

    if actual.returncode != 0:
        notes.append(f"git clean failed: {actual.stderr.strip()}")
        return False, 0, notes

    return True, len(would_remove), notes


# ──────────────────────────────────────────────────────────────────────────────
# 2. Go module cache permission normalization
# ──────────────────────────────────────────────────────────────────────────────
def normalize_go_cache(enabled: bool = True,
                       owner: Optional[str] = None) -> tuple[bool, Optional[str], list[str]]:
    """Make the Go module cache consistently owned by one user.

    The cri-o / cubefs failures showed "permission denied" all over the Go
    module cache. Root cause: builds run under sudo create root-owned files in
    a cache whose other files are owned by the normal user. Mixed ownership ==
    later steps cannot write/lock the cache.

    Fix: chown the whole cache tree to a single owner (the invoking human user
    by default). This must be done with root privileges; if the pipeline is not
    running as root, the function reports that and does nothing destructive.

    The cache location follows Go's rules: $GOMODCACHE, else $GOPATH/pkg/mod,
    else ~/go/pkg/mod.

    Args:
        enabled: If False, skip. For debugging.
        owner:   User the cache should belong to (defaults to the invoking
                 human user — see _invoking_user).

    Returns:
        (normalized, owner_used, notes)
    """
    notes: list[str] = []
    if not enabled:
        notes.append("go cache normalization skipped (disabled by caller)")
        return False, None, notes

    owner = owner or _invoking_user()

    # Resolve the module cache directory.
    gomodcache = os.environ.get("GOMODCACHE")
    if gomodcache:
        cache_dir = Path(gomodcache)
    else:
        gopath = os.environ.get("GOPATH")
        if gopath:
            cache_dir = Path(gopath) / "pkg" / "mod"
        else:
            try:
                home = Path(pwd.getpwnam(owner).pw_dir)
            except KeyError:
                home = Path.home()
            cache_dir = home / "go" / "pkg" / "mod"

    if not cache_dir.exists():
        notes.append(f"go cache normalization skipped: {cache_dir} does not exist")
        return False, owner, notes

    # chown requires root. If we are not root, do not fail — just report, so
    # the experiment can still proceed (and the operator knows why a later
    # permission error might occur).
    if os.geteuid() != 0:
        notes.append(
            f"go cache at {cache_dir} not normalized: needs root to chown "
            f"(pipeline is running as uid {os.geteuid()}). If you hit "
            f"'permission denied' in the module cache, run: "
            f"sudo chown -R {owner} {cache_dir}"
        )
        return False, owner, notes

    # Go marks cache files read-only; chown is unaffected by that, -R is enough.
    result = _run(["chown", "-R", owner, str(cache_dir)])
    if result.returncode != 0:
        notes.append(f"chown of {cache_dir} failed: {result.stderr.strip()}")
        return False, owner, notes

    return True, owner, notes


# ──────────────────────────────────────────────────────────────────────────────
# 3. Dependency cache warming (moved here from pipeline.py)
# ──────────────────────────────────────────────────────────────────────────────
def warm_caches(project_dir: Path, enabled: bool = True) -> tuple[list[str], list[str]]:
    """Pre-populate the Go / Cargo dependency caches for a project.

    Warming downloads dependencies up front so the subsequent attested build
    is reproducible and (optionally) offline. Which cache is warmed depends on
    the files present in the project.

    Args:
        project_dir: Project root.
        enabled:     If False, skip. For debugging.

    Returns:
        (warmed, notes) — warmed is a list like ["go"] or ["cargo"].
    """
    warmed: list[str] = []
    notes: list[str] = []

    if not enabled:
        notes.append("cache warming skipped (disabled by caller)")
        return warmed, notes

    if (project_dir / "go.mod").exists():
        result = _run(["go", "mod", "download"], cwd=project_dir)
        if result.returncode == 0:
            warmed.append("go")
        else:
            tail = (result.stderr.strip().splitlines() or ["unknown error"])[-1]
            notes.append(f"go mod download had issues: {tail}")

    if (project_dir / "Cargo.toml").exists():
        result = _run(["cargo", "fetch"], cwd=project_dir)
        if result.returncode == 0:
            warmed.append("cargo")
        else:
            tail = (result.stderr.strip().splitlines() or ["unknown error"])[-1]
            notes.append(f"cargo fetch had issues: {tail}")

    return warmed, notes


def clean_go_testcache() -> None:
    """Clear the Go build/test cache results.

    Moved out of witness_runner.run_step (where it was a Go-specific wart in a
    build-system-agnostic module). pipeline.run() can call this before test
    steps when it knows the project is Go-based.

    Uses _run so a missing 'go' executable is a no-op, not a crash.
    """
    _run(["go", "clean", "-testcache"])


# ──────────────────────────────────────────────────────────────────────────────
# Single entry point
# ──────────────────────────────────────────────────────────────────────────────
def prepare_environment(project_dir: Path,
                        do_git_clean: bool = True,
                        do_go_cache: bool = True,
                        do_warm: bool = True) -> HygieneResult:
    """Prepare a clean, consistent environment before attesting a project.

    This is what pipeline.run() calls once, up front. Per the agreed policy it
    always runs; each sub-action has its own flag so a single piece of hygiene
    can be turned off while debugging without disabling the rest.

    Order matters:
      1. git clean  — get the project back to its as-cloned state.
      2. go cache   — normalize ownership BEFORE any go command touches it.
      3. warm       — now safe to download into a consistently-owned cache.

    Args:
        project_dir:  Project to prepare.
        do_git_clean: Run `git clean -xfd`.
        do_go_cache:  Normalize Go module cache ownership.
        do_warm:      Warm Go / Cargo caches.

    Returns:
        HygieneResult describing what was done (suitable for the report).
    """
    project_dir = project_dir.resolve()
    result = HygieneResult()

    print("Preparing environment...")

    # 1. git clean
    ran, removed, notes = reset_project(project_dir, enabled=do_git_clean)
    result.git_clean_ran = ran
    result.git_clean_removed = removed
    result.notes.extend(notes)
    if ran:
        print(f"  git clean -xfd: removed {removed} untracked path(s)")
    for n in notes:
        print(f"  NOTE: {n}")

    # 2. go cache ownership
    normalized, owner, notes = normalize_go_cache(enabled=do_go_cache)
    result.go_cache_normalized = normalized
    result.go_cache_owner = owner
    result.notes.extend(notes)
    if normalized:
        print(f"  go module cache normalized to owner '{owner}'")
    for n in notes:
        print(f"  NOTE: {n}")

    # 3. cache warming
    warmed, notes = warm_caches(project_dir, enabled=do_warm)
    result.caches_warmed = warmed
    result.notes.extend(notes)
    if warmed:
        print(f"  warmed caches: {', '.join(warmed)}")
    for n in notes:
        print(f"  NOTE: {n}")

    print("Environment ready.")
    return result