#!/usr/bin/env python3
"""
parsers.py — Build-file parsing: extract step/target names from Makefile & tox.ini.

Scope (deliberately narrow):
  This module ONLY extracts targets/environments from build files. It does NOT
  decide which ones to skip — that is curation policy and belongs to config.py
  (skip_set_for) applied by the caller (pipeline.py).

  The old run_pipeline.parse_makefile mixed both: it took a project_name and
  filtered against GLOBAL_SKIP / PROJECT_SKIP internally. Splitting that out
  keeps "parsing" and "curation" as separate, independently testable concerns.

Dependency position: imports nothing from other sbomit modules.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────
def expand_brace(s: str) -> list[str]:
    """Expand shell brace expressions: py{38,39,310} -> [py38, py39, py310].

    Handles nested braces recursively. If there is no brace, returns [s].
    """
    m = re.search(r'\{([^{}]+)\}', s)
    if not m:
        return [s]
    prefix, suffix = s[:m.start()], s[m.end():]
    results: list[str] = []
    for alt in m.group(1).split(','):
        for expanded in expand_brace(prefix + alt.strip() + suffix):
            results.append(expanded)
    return results


def is_fake_target(target: str) -> bool:
    """Return True for ALL_CAPS Makefile variable definitions (e.g. 'CFLAGS'),
    which match the target regex but are not real, runnable targets.
    """
    return bool(re.match(r'^[A-Z][A-Z0-9_]+$', target))


def _strip_define_blocks(content: str) -> str:
    """Remove `define ... endef` template blocks from Makefile content.

    Make's `define` directive declares a multi-line variable / canned recipe.
    The lines inside it (including any `.PHONY:` or `target:` lines) are a
    template, not real targets — the positional vars ($(1), $(5), ...) are only
    substituted when the block is later expanded via $(call ...). Scanning
    inside these blocks produces bogus targets such as "$(5)/$(1)" and
    "modtidy-$(1)", so the whole block is dropped before target extraction.
    """
    lines = content.split('\n')
    kept: list[str] = []
    in_define = False
    for line in lines:
        # `define NAME` opens a block; `endef` closes it. Both are directives
        # that may start after optional leading whitespace.
        if re.match(r'^\s*define\s+', line):
            in_define = True
            continue
        if re.match(r'^\s*endef\b', line):
            in_define = False
            continue
        if not in_define:
            kept.append(line)
    return '\n'.join(kept)

# ──────────────────────────────────────────────────────────────────────────────
# Makefile
# ──────────────────────────────────────────────────────────────────────────────
def parse_makefile(path: str | Path) -> dict[str, list[str]]:
    """Parse a Makefile and return {target: [recipe commands]}.

    This returns ALL real targets found, with fake (ALL_CAPS variable) targets
    removed. Skip-list filtering is NOT applied here — the caller is expected to
    drop unwanted targets using config.skip_set_for().

    Args:
        path: Path to the Makefile.

    Returns:
        Dict mapping each target name to its list of recipe command lines.
        Returns {} if the file cannot be read.
    """
    try:
        content = Path(path).read_text()
    except Exception as e:
        print(f"Error reading {path}: {e}", file=sys.stderr)
        return {}

    # Drop `define ... endef` template blocks before any target extraction:
    # their inner lines are templates with unsubstituted vars, not real targets.
    content = _strip_define_blocks(content)

    targets: dict[str, list[str]] = {}

    # Collect .PHONY declarations.
    phony: set[str] = set()
    for m in re.finditer(r'^\.PHONY\s*:\s*(.+)$', content, re.MULTILINE):
        for t in m.group(1).split():
            t = t.strip()
            # Skip unresolved Make variables: ".PHONY: $(phony)" lists a
            # variable, not literal target names. Such tokens ($(...), ${...})
            # are not runnable targets and must not become steps.
            if '$(' in t or '${' in t:
                continue
            phony.add(t)

    # Collect explicit target definitions (lines like "target: deps").
    #
    # The colon must NOT be followed by '=' — that would be a variable
    # assignment ("VAR := ..."). Using a negative lookahead (?![=]) instead of
    # a consuming [^=] is important: [^=] requires a character to exist after
    # the colon, so it silently fails to match a bare "build:" at end of line.
    # That old bug caused recipes of colon-at-EOL targets to be misattributed
    # to the next matched target.
    for m in re.finditer(r'^([a-zA-Z0-9_./-]+)\s*:(?![=])', content, re.MULTILINE):
        if m.group(1) not in targets:
            targets[m.group(1)] = []

    # Add PHONY targets even if not explicitly defined with a recipe.
    for t in phony:
        if t not in targets:
            targets[t] = []

    # Parse recipe lines (tab-indented lines following a target).
    current_target: str | None = None
    for line in content.split('\n'):
        # Same (?![=]) lookahead as above — see the explanatory comment there.
        m = re.match(r'^([a-zA-Z0-9_./-]+)\s*:(?![=])', line)
        if m:
            current_target = m.group(1)
            if current_target not in targets:
                targets[current_target] = []
        elif line.startswith('\t') and current_target:
            cmd = line.strip()
            if cmd and not cmd.startswith('#'):
                targets[current_target].append(cmd)

    # Drop fake (ALL_CAPS variable) targets only. No skip-list filtering here.
    return {t: cmds for t, cmds in targets.items() if not is_fake_target(t)}


# ──────────────────────────────────────────────────────────────────────────────
# tox.ini
# ──────────────────────────────────────────────────────────────────────────────
def parse_tox(path: str | Path) -> list[str]:
    """Parse a tox.ini and return a sorted list of environment names.

    Collects both explicit [testenv:name] sections and entries from the
    envlist setting (with brace expansion applied).

    Args:
        path: Path to tox.ini.

    Returns:
        Sorted list of environment names. Returns [] if the file cannot be read.
    """
    try:
        content = Path(path).read_text()
    except Exception as e:
        print(f"Error reading {path}: {e}", file=sys.stderr)
        return []

    envs: set[str] = set()

    # Named [testenv:name] sections.
    for m in re.finditer(r'^\[testenv:([^\]]+)\]', content, re.MULTILINE):
        envs.add(m.group(1).strip())

    # envlist block (may span multiple lines, may use brace expansion).
    envlist_block = re.search(
        r'^envlist\s*=\s*(.+?)(?=^\S|\Z)', content,
        re.MULTILINE | re.DOTALL,
    )
    if envlist_block:
        raw = re.sub(r'#[^\n]*', '', envlist_block.group(1))
        raw = raw.replace('\\\n', ' ')
        # Split on whitespace/commas, but only OUTSIDE brace groups so that
        # "py{38,39}" stays as one token until expand_brace handles it.
        tokens: list[str] = []
        depth, current = 0, []
        for ch in raw:
            if ch == '{':
                depth += 1
                current.append(ch)
            elif ch == '}':
                depth -= 1
                current.append(ch)
            elif ch in (',', ' ', '\t', '\n') and depth == 0:
                t = ''.join(current).strip()
                if t:
                    tokens.append(t)
                current = []
            else:
                current.append(ch)
        t = ''.join(current).strip()
        if t:
            tokens.append(t)

        for token in tokens:
            if token:
                for expanded in expand_brace(token):
                    if expanded:
                        envs.add(expanded)

    return sorted(envs)