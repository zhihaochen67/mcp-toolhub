# Release checklist

Use this checklist for the `v0.1.0` release. Do not tag or publish unless every
validation step passes from a clean `main` checkout.

- [ ] Update local `main` with a fast-forward-only pull and verify
  `git status --short` is empty.
- [ ] Run `uv lock --check` and install the locked development environment with
  `uv sync --locked --all-groups`.
- [ ] Run the full local gate: `uv run pytest -q`, `uv run ruff check .`,
  `uv run ruff format --check .`, and
  `uv run python -m compileall -q src/mcp_toolhub`.
- [ ] Confirm the required GitHub Actions matrix is green on Ubuntu and Windows
  with Python 3.12 and 3.13.
- [ ] Remove stale local artifacts, run `uv build`, and confirm one sdist and one
  wheel were created in `dist/`.
- [ ] Run the installed-wheel validation outside the checkout:
  `uv run python scripts/artifact_smoke.py --dist-dir dist --venv <temporary-path> --repository .`.
- [ ] Confirm both the wheel metadata and `mcp-toolhub --version` report
  `0.1.0`, and confirm both `mcp-toolhub` and `mcp-toolhub-admin` entry points
  work from the isolated wheel environment.
- [ ] Run `uv run pytest -q tests/test_contract.py`, confirm Contract V1 is
  unchanged, and confirm the production server lists exactly 14 MCP tools.
- [ ] Inspect the wheel and sdist to confirm they contain `LICENSE`, and confirm
  the wheel metadata declares `License-Expression: MIT` and the expected
  repository, issue, and documentation URLs.
- [ ] Generate a SHA-256 checksum file for the wheel and sdist, then verify the
  recorded hashes against both artifacts.
- [ ] Prepare release notes stating that `v0.1.0` is validated on Ubuntu and
  Windows with Python 3.12 and 3.13, requires Python 3.12 or newer, and retains
  the security-model and platform limitations documented in the README.
- [ ] Create the annotated tag `v0.1.0` at the validated commit and push that
  tag.
- [ ] Create the GitHub Release for `v0.1.0`; attach the wheel, sdist, and
  SHA-256 checksum file, then verify the downloadable artifacts and hashes.
