"""core — the SBOMit pipeline's building blocks.

This package holds the parts that the experiment driver (experiment.py, one
level up) composes. Nothing here is a program entry point: there is no main(),
no argparse. Each module owns one concern, and the dependency graph flows one
way (models/config/parsers at the bottom, pipeline near the top).

Module map:
    models         StepResult / ProjectResult — the shared data contract
    config         skip-set constants and skip_set_for()
    parsers        Makefile / tox.ini parsing
    witness_runner run a single step under witness, capturing output
    buildsystems   data-driven build-system detection
    environment    environment hygiene (git clean, cache permissions)
    pipeline       orchestration: detect -> run steps -> ProjectResult
    attestation    DSSE decoding and attestation collection
    sbom_server    client for the SBOMit generator server
"""