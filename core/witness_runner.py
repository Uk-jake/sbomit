#!/usr/bin/env python3
"""
witness_runner.py — Invoke witness for a single build step and capture output.

This module replaces run_step() from the old run_pipeline.py. The critical
change addresses the [CRIT] all_failures_empty diagnostic seen in the cri-o /
cubefs failure reports:

    "All failed steps have NO captured output between ATTESTING and FAIL.
     witness is invoked via subprocess.run() without capture_output=True,
     and sudo may detach the streams."

Old behavior:
    subprocess.run(witness_cmd, env=env)        # output lost
    if out_file.exists(): print("OK")           # status inferred from a side effect

New behavior:
    - witness stdout+stderr is streamed line-by-line, written to a per-step
      log file AND echoed to the console in real time (tee-style).
    - run_step() RETURNS a StepResult object instead of printing "OK:"/"FAIL:".
      The caller (pipeline.py) decides what to do with it; experiment.py no
      longer needs to regex-parse stdout.

This module deliberately does NOT decide which steps to skip or how to detect
build systems — those concerns live in config.py / buildsystems.py. It only
knows how to run one command under witness and report what happened.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Optional

from .models import StepResult, STATUS_OK, STATUS_FAILED, STATUS_SKIPPED


def _stream_to_file_and_console(proc: subprocess.Popen,
                                log_path: Path,
                                label: str) -> None:
    """Read proc.stdout line by line; write each line to log_path and echo it
    to the console with a [label] prefix.

    witness is launched with stderr redirected into stdout (see run_step), so a
    single stream carries everything. Reading line-by-line is what makes the
    output appear in real time rather than all at once when the process exits.
    """
    with open(log_path, "w", encoding="utf-8", errors="replace") as log_file:
        # proc.stdout is a text-mode file object because Popen is created with
        # text=True. Iterating over it yields one line at a time as they arrive.
        for line in proc.stdout:
            log_file.write(line)
            log_file.flush()  # flush so a crash mid-step still leaves a log
            # rstrip only the trailing newline; print adds its own.
            print(f"  [{label}] {line.rstrip()}", flush=True)


def run_step(step_name: str,
             cmd: str,
             attestation_dir: Path,
             witness_path: str,
             signing_key: Path,
             skip_set: Optional[set] = None) -> StepResult:
    """Attest a single build step with witness and return a StepResult.

    Args:
        step_name:       Name of the step / Makefile target.
        cmd:             Shell command to attest (e.g. "make build").
        attestation_dir: Directory where <step>.json and <step>.log are written.
        witness_path:    Path to the witness binary.
        signing_key:     Path to the signing key file.
        skip_set:        Optional set of step names to skip.

    Returns:
        StepResult describing what happened. Never raises for an ordinary build
        failure — a failed build is a normal, expected outcome that the caller
        records and continues past.
    """
    skip_set = skip_set or set()

    # ── Skip handling ─────────────────────────────────────────────────────────
    if step_name in skip_set:
        print(f"SKIP: {step_name}", flush=True)
        return StepResult(name=step_name, status=STATUS_SKIPPED, command=cmd)

    out_file = attestation_dir / f"{step_name}.json"
    log_file = attestation_dir / f"{step_name}.log"
    print(f"ATTESTING: {step_name}", flush=True)

    # Clear Go test cache before test steps so the attestation is fresh.
    if step_name in ("test", "go-test") or "test" in step_name.lower():
        subprocess.run(["go", "clean", "-testcache"], capture_output=True)

    # ── Build the witness command ─────────────────────────────────────────────
    # sudo + --ebpf: the eBPF environment attestor needs root.
    witness_cmd = [
        "sudo",
        str(witness_path), "run",
        "--step", step_name,
        "--signer-file-key-path", str(signing_key),
        "--attestations", "environment",
        "--trace",
        "--ebpf",
    ]

    cmd_parts = cmd.split()
    if cmd_parts and cmd_parts[0] == "make" \
            and step_name != "test" and "test" not in step_name.lower():
        # Tell Make to assume 'test' is up-to-date to prevent recursive testing.
        cmd_parts.extend(["-o", "test"])

    witness_cmd += ["-o", str(out_file), "--"] + cmd_parts

    # ── Run witness, streaming output to file + console ───────────────────────
    import os
    env = os.environ.copy()
    env["PATH"] = os.path.expanduser("~/.local/bin") + ":" + env.get("PATH", "")

    t0 = time.time()
    # stderr=STDOUT merges both streams so a single reader captures everything.
    # text=True gives us str lines; bufsize=1 requests line buffering.
    proc = subprocess.Popen(
        witness_cmd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    _stream_to_file_and_console(proc, log_file, label=step_name)
    exit_code = proc.wait()
    duration = round(time.time() - t0, 3)

    # ── Determine status ──────────────────────────────────────────────────────
    # A step succeeded only if witness actually wrote the attestation file.
    # exit_code alone is not enough — witness can exit non-zero for several
    # reasons — but a written out_file is the concrete artifact we need.
    if out_file.exists():
        size = subprocess.check_output(["du", "-h", str(out_file)]).decode().split()[0]
        print(f"OK: {step_name} ({size})", flush=True)
        return StepResult(
            name=step_name,
            status=STATUS_OK,
            command=cmd,
            attestation_path=out_file,
            log_path=log_file,
            exit_code=exit_code,
            duration_s=duration,
        )
    else:
        print(f"FAIL: {step_name} — output file not written "
              f"(exit {exit_code}, see {log_file.name})", flush=True)
        return StepResult(
            name=step_name,
            status=STATUS_FAILED,
            command=cmd,
            log_path=log_file,
            exit_code=exit_code,
            duration_s=duration,
            # failure_reason is left None here on purpose: a dedicated
            # classification step (a later refactor) will read log_path and
            # fill it in (cgo header missing / go cache permission / etc.).
            failure_reason=None,
        )