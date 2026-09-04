# Release checklist

Use this checklist for the `v0.1.0` release. The tag-triggered release workflow
is the only publication path: do not create the GitHub Release or upload assets
manually.

## Before tagging

- [ ] Fast-forward local `main` to `origin/main`, confirm it is synchronized,
  and confirm `git status --short` is empty.
- [ ] Confirm the required CI matrix is green for the exact commit on Ubuntu
  and Windows with Python 3.12 and 3.13.
- [ ] Confirm `project.version` in `pyproject.toml` is `0.1.0` and
  `mcp-toolhub --version` reports `0.1.0`.
- [ ] Run `uv run pytest -q tests/test_contract.py`; confirm Contract V1 remains
  version `1.0`, its compatibility fixture is unchanged, and package and
  contract versions remain independent.
- [ ] Confirm the production server exposes exactly 14 MCP tools and contains
  no approval, rejection, or maintenance MCP endpoint.
- [ ] Review `CHANGELOG.md` and `docs/releases/v0.1.0.md` for accuracy, links,
  limitations, platform support, and the three expected release artifacts.
- [ ] Confirm neither the `v0.1.0` tag nor a GitHub Release named `v0.1.0`
  already exists locally or remotely.
- [ ] Create an annotated `v0.1.0` tag at the exact, validated `main` commit and
  verify the tag resolves to that commit.
- [ ] Push only the `v0.1.0` tag.

## Automated tag workflow

Pushing `v0.1.0` triggers `.github/workflows/release.yml`. On a GitHub-hosted
Ubuntu runner, the workflow:

1. Checks out the exact tagged commit and verifies it matches the push event.
2. Verifies the tag, `pyproject.toml`, and `mcp-toolhub --version` all identify
   version `0.1.0`, and requires `docs/releases/v0.1.0.md`.
3. Validates `uv.lock`, installs locked dependencies, runs Ruff lint and format
   checks, compiles the package, runs the full test suite, and reruns the
   Contract V1 tests explicitly.
4. Builds exactly one wheel and one sdist, then validates package contents,
   metadata, MIT licensing, console entry points, and the exact 14-tool
   inventory through the isolated installed-wheel smoke test.
5. Generates `dist/SHA256SUMS.txt` in deterministic filename order and verifies
   both recorded hashes immediately.
6. As its final step, creates the GitHub Release from the existing tag using
   `docs/releases/v0.1.0.md` and attaches the wheel, sdist, and
   `SHA256SUMS.txt`.

The workflow has only `contents: write` permission and does not publish to
PyPI. Any validation, build, smoke, metadata, or checksum failure occurs before
the release-creation step, so no GitHub Release is created.

## Reruns and duplicate releases

Runs for the same tag are serialized and are never cancelled in progress. The
final step refuses to continue if that tag already has a GitHub Release. A
rerun after successful publication therefore fails clearly without replacing
assets, deleting a release, or moving a tag. A rerun after a transient
pre-publication failure can proceed normally. A defect in the tagged commit
requires a reviewed fix and a new version/tag; tags must never be force-moved.

## After publication

- [ ] Confirm the `v0.1.0` GitHub Release page exists and uses the reviewed
  source-controlled notes.
- [ ] Download the wheel, sdist, and `SHA256SUMS.txt` from the release.
- [ ] Run `sha256sum --check SHA256SUMS.txt` in the download directory and
  confirm both artifacts pass.
- [ ] Confirm the release tag resolves to the intended validated `main` commit.
- [ ] Install the downloaded wheel in a clean environment and confirm
  `mcp-toolhub --version` reports `0.1.0`.
