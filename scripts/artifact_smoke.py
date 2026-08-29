"""Build-artifact smoke orchestration used locally and by GitHub Actions."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tarfile
from pathlib import Path
from zipfile import ZipFile

REQUIRED_WHEEL_PATHS = {
    "mcp_toolhub/admin.py",
    "mcp_toolhub/app.py",
    "mcp_toolhub/cli.py",
    "mcp_toolhub/contracts.py",
    "mcp_toolhub/security/paths.py",
    "mcp_toolhub/security/execution_environment.py",
    "mcp_toolhub/tools/control.py",
    "mcp_toolhub/tools/filesystem.py",
    "mcp_toolhub/observability/audit.py",
}


def _scripts_directory(venv: Path) -> Path:
    return venv / ("Scripts" if os.name == "nt" else "bin")


def _script(venv: Path, name: str) -> Path:
    suffix = ".exe" if os.name == "nt" else ""
    return _scripts_directory(venv) / f"{name}{suffix}"


def _run(command: list[str], *, cwd: Path, environment=None) -> None:
    subprocess.run(command, cwd=cwd, env=environment, check=True, timeout=180)


def _capture(command: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--dist-dir", type=Path, default=Path("dist"))
    parser.add_argument("--venv", type=Path, required=True)
    parser.add_argument("--repository", type=Path, required=True)
    args = parser.parse_args()

    repository = args.repository.resolve(strict=True)
    if args.wheel is None:
        wheels = list((repository / args.dist_dir).glob("*.whl"))
        if len(wheels) != 1:
            raise RuntimeError(f"Expected one wheel, found: {wheels}")
        wheel = wheels[0].resolve(strict=True)
        sdists = list((repository / args.dist_dir).glob("*.tar.gz"))
        if len(sdists) != 1:
            raise RuntimeError(f"Expected one sdist, found: {sdists}")
        with tarfile.open(sdists[0]) as archive:
            source_paths = {member.name for member in archive.getmembers()}
        missing_source = {
            f"src/{path}"
            for path in REQUIRED_WHEEL_PATHS
            if not any(name.endswith(f"/src/{path}") for name in source_paths)
        }
        if missing_source:
            raise RuntimeError(
                f"Sdist is missing implementation files: {sorted(missing_source)}"
            )
    else:
        wheel = args.wheel.resolve(strict=True)
    venv = args.venv.resolve()
    if venv.is_relative_to(repository):
        raise ValueError("Artifact smoke environment must be outside the checkout")

    with ZipFile(wheel) as archive:
        wheel_paths = set(archive.namelist())
        entry_points_path = next(
            name for name in wheel_paths if name.endswith(".dist-info/entry_points.txt")
        )
        entry_points = archive.read(entry_points_path).decode("utf-8")
    missing = REQUIRED_WHEEL_PATHS - wheel_paths
    if missing:
        raise RuntimeError(f"Wheel is missing implementation files: {sorted(missing)}")
    for script_name in ("mcp-toolhub", "mcp-toolhub-admin"):
        if script_name not in entry_points:
            raise RuntimeError(f"Wheel entry point is missing: {script_name}")

    _run(
        ["uv", "venv", "--clear", "--python", sys.executable, str(venv)],
        cwd=repository,
    )
    _run(
        ["uv", "pip", "install", "--python", str(venv), str(wheel)],
        cwd=repository,
    )

    launch_directory = venv.parent / "mcp-toolhub-wheel-launch"
    launch_directory.mkdir(exist_ok=True)
    server = _script(venv, "mcp-toolhub")
    admin = _script(venv, "mcp-toolhub-admin")
    python = _script(venv, "python")

    import_check = (
        "import importlib.util, pathlib, mcp_toolhub; "
        "location = pathlib.Path(mcp_toolhub.__file__).resolve(); "
        "assert 'site-packages' in str(location), location; "
        "assert importlib.util.find_spec('toolhub') is None"
    )
    _run([str(python), "-c", import_check], cwd=launch_directory)

    version = _capture([str(server), "--version"], cwd=launch_directory)
    if not version.stdout.strip():
        raise RuntimeError("Installed mcp-toolhub --version returned no version")
    admin_help = _capture([str(admin), "--help"], cwd=launch_directory)
    if "prune" not in admin_help.stdout:
        raise RuntimeError("Installed administrator CLI is missing maintenance")
    prune_help = _capture([str(admin), "prune", "--help"], cwd=launch_directory)
    for target in ("approvals", "audit"):
        if target not in prune_help.stdout:
            raise RuntimeError(
                f"Installed administrator maintenance target is missing: {target}"
            )

    environment = dict(os.environ)
    environment["TOOLHUB_TEST_SERVER"] = str(server)
    environment["TOOLHUB_TEST_ADMIN"] = str(admin)
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    _run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "--noconftest",
            str(repository / "tests" / "test_stdio_integration.py"),
        ],
        cwd=launch_directory,
        environment=environment,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
