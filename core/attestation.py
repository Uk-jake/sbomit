#!/usr/bin/env python3
"""
attestation.py — Decode and collect witness attestation files.

Witness writes each attested step as a DSSE envelope (a signed JSON wrapper
around an in-toto Statement). This module handles two concerns:

  1. decode()  — turn one DSSE envelope into a readable form (base64 payload
                 expanded into a JSON object), signatures preserved.
  2. collect() — gather a project's attestation files into the experiment
                 directory and decode them.

Scope boundary: this module deals with attestation *data*. It does NOT talk to
the SBOMit server — uploading/fetching lives in sbom_server.py. Keeping the two
apart means a change to the server API never touches decoding logic, and the
decoding can be unit-tested with no network.

This is also where attestation *analysis* will live later — e.g. extracting the
list of files/packages a build actually used from the eBPF attestor's output.
A placeholder, extract_used_files(), marks that seam.

Dependency position: imports nothing from other sbomit modules.
"""

from __future__ import annotations

import base64
import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ──────────────────────────────────────────────────────────────────────────────
# Result types
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class CollectResult:
    """Outcome of collecting + decoding a project's attestations.

    Attributes:
        original_files: Paths to the copied original (signed DSSE) files.
        decoded_files:  Paths to the decoded JSON files.
        decoded_count:  How many files decoded successfully.
        failed_count:   How many files failed to decode.
        notes:          Human-readable warnings (suitable for the report).
    """
    original_files: list[Path] = field(default_factory=list)
    decoded_files: list[Path] = field(default_factory=list)
    decoded_count: int = 0
    failed_count: int = 0
    notes: list[str] = field(default_factory=list)


# ──────────────────────────────────────────────────────────────────────────────
# DSSE decoding
# ──────────────────────────────────────────────────────────────────────────────
def decode(src_path: Path, dst_path: Path) -> bool:
    """Decode a DSSE-formatted attestation file written by witness.

    DSSE envelope structure (input):
        {
          "payloadType": "application/vnd.in-toto+json",
          "payload": "<base64-encoded in-toto Statement>",
          "signatures": [{"keyid": "...", "sig": "..."}]
        }

    Decoded result (output) — same shape, but payload expanded to a JSON object:
        {
          "payloadType": "application/vnd.in-toto+json",
          "payload": { ...in-toto Statement... },
          "signatures": [...]          # preserved for later verification
        }

    Args:
        src_path: Path to the original DSSE envelope file.
        dst_path: Path to write the decoded JSON to (parent dirs are created).

    Returns:
        True on success. False on failure — and on failure the source file is
        left untouched, so a failed decode never destroys data.
    """
    try:
        with open(src_path, "r", encoding="utf-8") as f:
            envelope = json.load(f)

        # A valid DSSE envelope must have a payload field.
        if "payload" not in envelope:
            return False

        payload = envelope["payload"]

        # If payload is already a decoded dict, keep it (idempotent decode).
        if isinstance(payload, dict):
            decoded_payload = payload
        else:
            try:
                decoded_bytes = base64.b64decode(payload)
                decoded_payload = json.loads(decoded_bytes.decode("utf-8"))
            except (ValueError, json.JSONDecodeError):
                return False

        decoded_envelope = {
            "payloadType": envelope.get("payloadType"),
            "payload": decoded_payload,
            "signatures": envelope.get("signatures", []),
        }

        dst_path.parent.mkdir(parents=True, exist_ok=True)
        with open(dst_path, "w", encoding="utf-8") as f:
            json.dump(decoded_envelope, f, indent=2, ensure_ascii=False)

        return True

    except Exception:
        # Any unexpected error -> treat as a failed decode, never raise.
        return False


# ──────────────────────────────────────────────────────────────────────────────
# Collection
# ──────────────────────────────────────────────────────────────────────────────
def collect(src_dir: Path, dst_dir: Path) -> CollectResult:
    """Collect a project's attestation files and decode them.

    Copies every *.json attestation from src_dir into dst_dir, then writes a
    decoded copy of each into dst_dir/decoded/. Previous copies in dst_dir and
    dst_dir/decoded are cleared first so a re-run starts clean.

    Args:
        src_dir: Where the pipeline wrote attestations
                 (e.g. SBOMIT_DIR/attestations/<project>).
        dst_dir: Where the experiment keeps its copy
                 (e.g. experiments/<project>/attestations).

    Returns:
        A CollectResult. Naming convention for decoded files:
            build.json  ->  decoded/build.decoded.json
    """
    result = CollectResult()

    if not src_dir.exists():
        result.notes.append(f"no attestations directory at {src_dir}")
        return result

    decoded_dir = dst_dir / "decoded"
    dst_dir.mkdir(parents=True, exist_ok=True)
    decoded_dir.mkdir(parents=True, exist_ok=True)

    # Clear previous copies (both originals and decoded) for a clean re-run.
    for f in dst_dir.glob("*.json"):
        f.unlink()
    for f in decoded_dir.glob("*.json"):
        f.unlink()

    files = sorted(src_dir.glob("*.json"))

    # Copy originals.
    for f in files:
        dst = dst_dir / f.name
        shutil.copy2(f, dst)
        result.original_files.append(dst)

    # Decode each one.
    for f in result.original_files:
        decoded_path = decoded_dir / f"{f.stem}.decoded.json"
        if decode(f, decoded_path):
            result.decoded_files.append(decoded_path)
            result.decoded_count += 1
        else:
            result.failed_count += 1
            result.notes.append(f"failed to decode {f.name} (original kept)")

    return result


# ──────────────────────────────────────────────────────────────────────────────
# Analysis — extracting what a build actually used
# ──────────────────────────────────────────────────────────────────────────────
#
# Attestation schema (confirmed against a real go-tuf build attestation):
#
#   payload
#     predicate
#       attestations[]                       <- list of sub-attestations
#         { type: ".../command-run/v0.1",
#           attestation: {
#             cmd, stdout, exitcode,
#             processes[]                     <- one per process the build ran
#               { processid, parentpid,
#                 openedfiles: {              <- files THIS process opened
#                   "<path>": {"sha256": "..."},
#                   ...
#                 }
#               }
#           }
#         }
#
# extract_used_files() collects every openedfiles path across every process.
# extract_used_packages() then classifies those paths (Go module / system /
# other) and turns Go module-cache paths into package@version identifiers.

COMMAND_RUN_TYPE_SUBSTR = "command-run"


def _load_decoded(decoded_path: Path) -> dict:
    """Load a decoded attestation file, returning {} on any error.

    decode() may produce a file whose `payload` is already a dict; this just
    reads JSON, so it works regardless.
    """
    try:
        with open(decoded_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def extract_used_files(decoded_path: Path) -> list[str]:
    """Return every file path the build opened, from a decoded attestation.

    Walks predicate.attestations[] for the command-run sub-attestation, then
    unions the openedfiles keys of every process. The result is the raw set of
    files touched during the build — packages, source, system libraries,
    /proc, telemetry, everything. Refining this into packages is the job of
    extract_used_packages().

    Args:
        decoded_path: A file produced by decode().

    Returns:
        Sorted list of unique file paths. Empty if the file is missing,
        unparseable, or has no command-run data.
    """
    data = _load_decoded(decoded_path)
    payload = data.get("payload", {})
    if not isinstance(payload, dict):
        return []

    predicate = payload.get("predicate", {})
    sub_attestations = predicate.get("attestations", []) \
        if isinstance(predicate, dict) else []

    files: set[str] = set()
    for sub in sub_attestations:
        if not isinstance(sub, dict):
            continue
        if COMMAND_RUN_TYPE_SUBSTR not in str(sub.get("type", "")):
            continue
        att = sub.get("attestation", {})
        if not isinstance(att, dict):
            continue
        for proc in att.get("processes", []):
            if not isinstance(proc, dict):
                continue
            opened = proc.get("openedfiles", {})
            if isinstance(opened, dict):
                files.update(opened.keys())

    return sorted(files)


# ── Path classification ───────────────────────────────────────────────────────
# Category labels for a file path.
CAT_GO_MODULE   = "go_module"     # under the Go module cache — a real dependency
CAT_SYSTEM_LIB  = "system_lib"    # /usr, /lib — system shared libraries
CAT_PROJECT     = "project"       # inside the project's own source tree
CAT_OTHER       = "other"         # /proc, /sys, telemetry, caches, etc. — noise


def _classify_path(path: str) -> str:
    """Classify a single file path into one of the CAT_* categories."""
    if "/go/pkg/mod/" in path:
        return CAT_GO_MODULE
    if path.startswith("/usr/") or path.startswith("/lib/"):
        return CAT_SYSTEM_LIB
    if "/sbomit/projects/" in path:
        return CAT_PROJECT
    return CAT_OTHER


def _path_to_go_package(path: str) -> Optional[str]:
    """Turn a Go module-cache path into a 'module@version' identifier.

    Go stores modules under two layouts; both carry the module path and the
    version, so both are handled:

      .../go/pkg/mod/cache/download/<module>/@v/<version>.<ext>
          -> module = <module>, version = <version>

      .../go/pkg/mod/<module>@<version>/<file...>
          -> module = <module>, version = <version>

    Returns None if the path is under the module cache but does not match a
    recognized layout (e.g. cache/lock files).
    """
    marker = "/go/pkg/mod/"
    idx = path.find(marker)
    if idx == -1:
        return None
    rest = path[idx + len(marker):]

    # Layout 1: cache/download/<module>/@v/<version>.<ext>
    dl_prefix = "cache/download/"
    if rest.startswith(dl_prefix):
        rest2 = rest[len(dl_prefix):]
        if "/@v/" in rest2:
            module, after = rest2.split("/@v/", 1)
            version = after.rsplit(".", 1)[0]  # strip .info/.mod/.zip/.ziphash
            if module and version:
                return f"{module}@{version}"
        return None

    # Layout 2: <module>@<version>/<file...>
    if "@" in rest:
        before_slash = rest.split("/", 1)[0]  # "<module>@<version>" segment
        if "@" in before_slash:
            module, version = before_slash.rsplit("@", 1)
            if module and version:
                return f"{module}@{version}"
    return None


def extract_used_packages(decoded_path: Path) -> dict:
    """Classify a build's opened files and extract Go module packages.

    Builds on extract_used_files(): every opened path is sorted into a
    category, Go module-cache paths are further resolved to package@version
    identifiers.

    The non-Go categories are COUNTED, not discarded. This is deliberate — if
    a Python or Rust project is analyzed, 'go_packages' will be empty but
    'category_counts' still shows hundreds of 'other'/'system_lib' paths,
    making it obvious that the Go-specific resolver simply did not apply
    (rather than misreading it as "this step used nothing").

    Args:
        decoded_path: A file produced by decode().

    Returns:
        {
          "go_packages": sorted list of "module@version" strings,
          "category_counts": {go_module, system_lib, project, other: int},
          "total_files": int,   # total unique opened files
        }
    """
    files = extract_used_files(decoded_path)

    counts = {CAT_GO_MODULE: 0, CAT_SYSTEM_LIB: 0,
              CAT_PROJECT: 0, CAT_OTHER: 0}
    go_packages: set[str] = set()

    for path in files:
        category = _classify_path(path)
        counts[category] += 1
        if category == CAT_GO_MODULE:
            pkg = _path_to_go_package(path)
            if pkg:
                go_packages.add(pkg)

    return {
        "go_packages": sorted(go_packages),
        "category_counts": counts,
        "total_files": len(files),
    }