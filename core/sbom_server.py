#!/usr/bin/env python3
"""
sbom_server.py — Client for the SBOMit generator server.

The SBOMit server takes uploaded attestations and produces SBOMs. This module
wraps every interaction with it behind one class, SbomServer:

    server = SbomServer(url, token)
    server.clear(project)
    n = server.upload(attestation_files)
    results = server.fetch_sboms(output_dir)

Why a class instead of three loose functions (the old experiment.py shape):
  - url and token are shared state needed by every call. A class injects them
    once instead of threading them through every function or relying on module
    globals.
  - It gives one obvious place to change transport (today: curl subprocess;
    later: requests) without touching call sites.
  - experiment.py can be tested against a fake SbomServer with no network.

Scope boundary: this module only does network I/O with the server. Decoding /
collecting attestations is attestation.py's job; this module just uploads the
files it is handed.

Dependency position: imports nothing from other sbomit modules.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
import requests as _requests


# ──────────────────────────────────────────────────────────────────────────────
# SBOM formats requested from the server.
#
# catalog=syft is intentionally NOT used: the experiment evaluates the
# eBPF-only SBOM, i.e. what the attestations themselves can produce.
# ──────────────────────────────────────────────────────────────────────────────
SBOM_FORMATS: list[tuple[str, str]] = [
    ("spdx",      "sbom.spdx.json"),
    ("cyclonedx", "sbom.cyclonedx.json"),
    ("spdx22",    "sbom.spdx22.json"),
]


@dataclass
class SbomFetchResult:
    """Result of fetching one SBOM format from the server."""
    format: str
    filename: str
    success: bool = False
    packages: int = 0
    size_bytes: int = 0
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "format": self.format,
            "success": self.success,
            "packages": self.packages,
            "size_bytes": self.size_bytes,
            "error": self.error,
        }


@dataclass
class UploadResult:
    """Result of uploading a batch of attestation files."""
    attempted: int = 0
    succeeded: int = 0
    notes: list[str] = field(default_factory=list)


class SbomServer:
    """Client for one SBOMit generator server instance.

    Args:
        url:     Base URL of the server (e.g. "http://10.10.20.2:5000").
        token:   Bearer token for the Authorization header.
        timeout: Default per-request timeout in seconds.
    """

    def __init__(self, url: str, token: str, timeout: int = 300):
        self.url = url.rstrip("/")
        self.token = token
        self.timeout = timeout

    # ── Internal helpers ──────────────────────────────────────────────────────
    def _auth_header(self) -> list[str]:
        """curl args for the Authorization header."""
        return ["-H", f"Authorization: Bearer {self.token}"]

    def _curl(self, args: list[str], timeout: int | None = None
              ) -> subprocess.CompletedProcess:
        """Run curl with the given args, capturing output, never raising.

        A missing curl binary is converted to a non-zero result rather than a
        FileNotFoundError, so callers can branch on returncode uniformly.
        """
        try:
            return subprocess.run(
                ["curl", "-s", *args],
                capture_output=True, text=True,
                timeout=timeout or self.timeout,
            )
        except FileNotFoundError:
            return subprocess.CompletedProcess(
                args=["curl"], returncode=127,
                stdout="", stderr="curl: command not found",
            )
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(
                args=["curl"], returncode=28,  # curl's own timeout code
                stdout="", stderr="curl: request timed out",
            )

    # ── Public API ────────────────────────────────────────────────────────────
    def clear(self, project: str) -> bool:
        """Clear previously uploaded attestations for a project on the server.

        Returns True if the request succeeded. A failure is non-fatal — the
        caller may choose to continue — so this reports rather than raises.
        """
        r = self._curl([
            "-X", "POST", f"{self.url}/attestations/clear",
            *self._auth_header(),
            "-H", "Content-Type: application/json",
            "-d", json.dumps({"project": project}),
        ])
        return r.returncode == 0

    # def upload(self, attestation_files: list[Path]) -> UploadResult:
    #     """Upload a batch of attestation files to the server.

    #     Args:
    #         attestation_files: Paths to the (original, signed) attestation
    #                            JSON files to upload.

    #     Returns:
    #         An UploadResult with counts and any per-file notes.
    #     """
    #     result = UploadResult(attempted=len(attestation_files))

    #     for f in attestation_files:
    #         r = self._curl([
    #             "-X", "POST", f"{self.url}/attestations",
    #             *self._auth_header(),
    #             "-H", "Content-Type: application/json",
    #             "-d", f"@{f}",
    #         ], timeout=60)
    #         if r.returncode == 0:
    #             result.succeeded += 1
    #         else:
    #             msg = r.stderr.strip() or f"curl exit {r.returncode}"
    #             result.notes.append(f"upload failed for {f.name}: {msg}")

    #     return result
    def upload(self, attestation_files: list[Path]) -> UploadResult:
        result = UploadResult(attempted=len(attestation_files))

        for f in attestation_files:
            try:
                # 파일을 스트리밍으로 전송 — 메모리에 전체 로드 안 함
                with open(f, "rb") as fh:
                    resp = _requests.post(
                        f"{self.url}/attestations",
                        data=fh,          # ← 스트리밍: 청크 단위로 읽으며 전송
                        headers={
                            "Authorization": f"Bearer {self.token}",
                            "Content-Type": "application/json",
                        },
                        timeout=self.timeout,
                        stream=True,
                    )
                if resp.status_code == 200:
                    result.succeeded += 1
                else:
                    result.notes.append(
                        f"upload failed for {f.name}: HTTP {resp.status_code}"
                    )
            except Exception as e:
                result.notes.append(f"upload failed for {f.name}: {e}")

        return result

    def fetch_sboms(self, output_dir: Path,
                    formats: list[tuple[str, str]] | None = None
                    ) -> dict[str, SbomFetchResult]:
        """Fetch SBOMs in the configured formats and save them to output_dir.

        Args:
            output_dir: Directory to write the SBOM files into.
            formats:    List of (format, filename) pairs. Defaults to
                        SBOM_FORMATS.

        Returns:
            Dict mapping format name -> SbomFetchResult.
        """
        formats = formats or SBOM_FORMATS
        output_dir.mkdir(parents=True, exist_ok=True)
        results: dict[str, SbomFetchResult] = {}

        for fmt, filename in formats:
            out_path = output_dir / filename
            res = SbomFetchResult(format=fmt, filename=filename)

            r = self._curl([
                f"{self.url}/sbom?format={fmt}",
                *self._auth_header(),
                "-o", str(out_path),
            ])

            if r.returncode != 0:
                res.error = f"curl failed: {r.stderr.strip()}"
                results[fmt] = res
                continue

            if not out_path.exists() or out_path.stat().st_size == 0:
                res.error = "empty response"
                results[fmt] = res
                continue

            res.size_bytes = out_path.stat().st_size

            # Parse the SBOM to count packages. CycloneDX uses "components";
            # SPDX variants use "packages".
            try:
                data = json.loads(out_path.read_text())
                if fmt.startswith("cyclonedx"):
                    res.packages = len(data.get("components", []))
                else:
                    res.packages = len(data.get("packages", []))
                res.success = True
            except (json.JSONDecodeError, ValueError) as e:
                res.error = f"invalid JSON: {e}"

            results[fmt] = res

        return results