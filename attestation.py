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
ptrace/material data that experiment.py's workflow description refers to. A
placeholder, extract_used_files(), marks that seam.

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
# Analysis (placeholder seam)
# ──────────────────────────────────────────────────────────────────────────────
def extract_used_files(decoded_path: Path) -> list[str]:
    """Extract the list of files/packages actually used, from a decoded
    attestation's eBPF/ptrace data.

    PLACEHOLDER. experiment.py's workflow describes a step that pulls the
    ptrace module out of each attestation; that logic belongs here, next to
    decoding, rather than in the experiment orchestrator. Implemented as a
    no-op for now so the module seam exists without changing behavior.

    Args:
        decoded_path: A file produced by decode().

    Returns:
        Currently always []. To be implemented against the real attestation
        schema once the SBOM-coverage work needs it.
    """
    return []