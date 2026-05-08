#!/usr/bin/env python3
"""Assemble registry-hosted npm packages from cargo-dist artifacts."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import re
import tarfile
from pathlib import Path

PACKAGE = "@casualjim/heimdall-sandbox"
BINARY = "heimdall-sandbox"
TARGETS = {
    "x86_64-unknown-linux-gnu": {
        "package": "@casualjim/heimdall-sandbox-linux-x64",
        "os": "linux",
        "cpu": "x64",
    },
    "aarch64-unknown-linux-gnu": {
        "package": "@casualjim/heimdall-sandbox-linux-arm64",
        "os": "linux",
        "cpu": "arm64",
    },
    "aarch64-apple-darwin": {
        "package": "@casualjim/heimdall-sandbox-darwin-arm64",
        "os": "darwin",
        "cpu": "arm64",
    },
}


def workspace_version() -> str:
    manifest = Path("Cargo.toml").read_text(encoding="utf-8")
    in_workspace_package = False
    for line in manifest.splitlines():
        stripped = line.strip()
        if stripped == "[workspace.package]":
            in_workspace_package = True
            continue
        if stripped.startswith("[") and stripped != "[workspace.package]":
            in_workspace_package = False
        if in_workspace_package:
            match = re.match(r'version\s*=\s*"([^"]+)"', stripped)
            if match:
                return match.group(1)
    raise SystemExit("workspace.package.version not found in Cargo.toml")


def write_json(path: Path, data: dict[str, object]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def find_archive(artifacts_dir: Path, target: str) -> Path:
    matches = sorted(artifacts_dir.glob(f"{BINARY}-{target}.tar.*"))
    if not matches:
        raise SystemExit(f"missing cargo-dist archive for {target} in {artifacts_dir}")
    return matches[0]


def extract_binary(archive: Path, destination: Path) -> None:
    with tarfile.open(archive) as tar:
        for member in tar.getmembers():
            if Path(member.name).name != BINARY or not member.isfile():
                continue
            source = tar.extractfile(member)
            if source is None:
                raise SystemExit(f"archive {archive} could not read {member.name}")
            with destination.open("wb") as output:
                shutil.copyfileobj(source, output)
            destination.chmod(destination.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            return
    raise SystemExit(f"archive {archive} does not contain {BINARY}")


def package_slug(package_name: str) -> str:
    return package_name.removeprefix("@casualjim/")


def create_platform_package(out_dir: Path, target: str, meta: dict[str, str], version: str, artifacts_dir: Path | None) -> Path:
    package_dir = out_dir / package_slug(meta["package"])
    bin_dir = package_dir / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    binary_path = bin_dir / BINARY
    if artifacts_dir is None:
        write_executable(binary_path, "#!/usr/bin/env sh\necho 'placeholder binary for npm package dry-run validation'\n")
    else:
        extract_binary(find_archive(artifacts_dir, target), binary_path)

    write_json(
        package_dir / "package.json",
        {
            "name": meta["package"],
            "version": version,
            "description": f"Heimdall sandbox CLI binary for {target}.",
            "license": "MIT",
            "repository": {"type": "git", "url": "git+https://github.com/casualjim/heimdall-sandbox.git"},
            "homepage": "https://github.com/casualjim/heimdall-sandbox",
            "os": [meta["os"]],
            "cpu": [meta["cpu"]],
            "bin": {BINARY: f"bin/{BINARY}"},
            "files": ["bin", "README.md"],
        },
    )
    (package_dir / "README.md").write_text(
        f"# {meta['package']}\n\nPlatform binary package for `{PACKAGE}` on `{target}`.\n",
        encoding="utf-8",
    )
    return package_dir


def create_main_package(out_dir: Path, version: str) -> Path:
    package_dir = out_dir / "heimdall-sandbox"
    bin_dir = package_dir / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    optional_dependencies = {meta["package"]: version for meta in TARGETS.values()}
    write_json(
        package_dir / "package.json",
        {
            "name": PACKAGE,
            "version": version,
            "description": "Process sandbox runtime for Heimdall.",
            "license": "MIT",
            "repository": {"type": "git", "url": "git+https://github.com/casualjim/heimdall-sandbox.git"},
            "homepage": "https://github.com/casualjim/heimdall-sandbox",
            "bin": {BINARY: f"bin/{BINARY}.js"},
            "optionalDependencies": optional_dependencies,
            "files": ["bin", "README.md"],
        },
    )
    write_executable(
        bin_dir / f"{BINARY}.js",
        """#!/usr/bin/env node
const { spawnSync } = require('node:child_process');
const process = require('node:process');

const packages = {
  'linux:x64': '@casualjim/heimdall-sandbox-linux-x64',
  'linux:arm64': '@casualjim/heimdall-sandbox-linux-arm64',
  'darwin:arm64': '@casualjim/heimdall-sandbox-darwin-arm64',
};

const key = `${process.platform}:${process.arch}`;
const packageName = packages[key];
if (!packageName) {
  console.error(`Unsupported platform ${key}. Supported platforms: ${Object.keys(packages).join(', ')}`);
  process.exit(1);
}

let binary;
try {
  binary = require.resolve(`${packageName}/bin/heimdall-sandbox`);
} catch (error) {
  console.error(`Missing Heimdall platform package ${packageName}. Reinstall @casualjim/heimdall-sandbox and ensure optional dependencies are enabled.`);
  process.exit(1);
}

const result = spawnSync(binary, process.argv.slice(2), { stdio: 'inherit' });
if (result.error) {
  console.error(`Failed to execute ${binary}: ${result.error.message}`);
  process.exit(1);
}
process.exit(result.status ?? 1);
""",
    )
    (package_dir / "README.md").write_text(
        f"# {PACKAGE}\n\nRegistry-hosted Heimdall CLI package. Platform binaries are supplied by optional npm dependencies; no GitHub release asset download occurs during install or first run.\n",
        encoding="utf-8",
    )
    return package_dir


def npm_pack_dry_run(package_dir: Path) -> None:
    subprocess.run(["npm", "pack", "--dry-run"], cwd=package_dir, check=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", default=workspace_version())
    parser.add_argument("--artifacts-dir", type=Path)
    parser.add_argument("--out-dir", type=Path, default=Path("target/npm-packages"))
    parser.add_argument("--dry-run-placeholders", action="store_true")
    parser.add_argument("--pack-dry-run", action="store_true")
    args = parser.parse_args()

    artifacts_dir = None if args.dry_run_placeholders else args.artifacts_dir
    if artifacts_dir is None and not args.dry_run_placeholders:
        raise SystemExit("--artifacts-dir is required unless --dry-run-placeholders is set")

    if args.out_dir.exists():
        shutil.rmtree(args.out_dir)
    args.out_dir.mkdir(parents=True)

    package_dirs = [create_platform_package(args.out_dir, target, meta, args.version, artifacts_dir) for target, meta in TARGETS.items()]
    package_dirs.append(create_main_package(args.out_dir, args.version))

    if args.pack_dry_run:
        for package_dir in package_dirs:
            npm_pack_dry_run(package_dir)

    print(os.linesep.join(str(path) for path in package_dirs))


if __name__ == "__main__":
    main()
