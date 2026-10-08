#!/usr/bin/env python3
"""Run bundled official Agent Skills validation offline in disposable tooling state."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile
import tempfile
import venv

HERE = Path(__file__).resolve().parent


def checked_lock():
    lock = json.loads((HERE / "toolchain.lock.json").read_text())
    for item in lock["files"]:
        relative = Path(item["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Unsafe vendor path")
        path = HERE / relative
        if path.is_symlink() or not path.is_file() or path.stat().st_size != item["bytes"] or hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError("Vendor integrity failure: " + item["path"])
    return lock


def tooling(root, lock):
    venv_root = root / "venv"
    venv.EnvBuilder(with_pip=True).create(venv_root)
    python = venv_root / "bin/python"
    command = [str(python), "-m", "pip", "--isolated", "install", "--disable-pip-version-check",
               "--no-index", "--find-links", str(HERE / "vendor/wheelhouse"), "--require-hashes",
               "--only-binary=:all:", "-r", str(HERE / "requirements.lock")]
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise RuntimeError("Offline validator dependency install failed: " + result.stderr[-2000:])
    source = root / "source"
    source.mkdir()
    prefix = lock["source_prefix"]
    files = 0
    with tarfile.open(HERE / "vendor/agentskills-source.tar.gz", "r:gz") as archive:
        for item in archive:
            if not item.name.startswith(prefix):
                continue
            name = item.name[len(prefix):]
            if not name or item.isdir():
                continue
            rel = PurePosixPath(name)
            if not item.isfile() or rel.is_absolute() or ".." in rel.parts or item.size > 2 * 1024 * 1024:
                raise ValueError("Unsafe validator source archive member")
            destination = source.joinpath(*rel.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            reader = archive.extractfile(item)
            if reader is None:
                raise ValueError("Missing source archive content")
            with reader:
                destination.write_bytes(reader.read())
            files += 1
    if not files or not (source / "skills_ref/cli.py").is_file():
        raise ValueError("Official validator entrypoint missing")
    env = dict(os.environ)
    env.update(PYTHONPATH=str(source), PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1")
    return python, env


def validate(python, env, path, label, expected=0):
    entry = path / "SKILL.md"
    before = entry.read_bytes() if entry.is_file() else None
    command = [str(python), "-m", "skills_ref.cli", "validate", str(path)]
    result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=30)
    after = entry.read_bytes() if entry.is_file() else None
    return {"label": label, "path": str(path), "expected_exit_code": expected,
            "entry_sha256": hashlib.sha256(before).hexdigest() if before is not None else None,
            "entry_bytes": len(before) if before is not None else None,
            "input_unchanged": before == after,
            "exit_code": result.returncode, "passed": result.returncode == expected and before == after,
            "stdout": result.stdout.strip(), "stderr": result.stderr.strip()}


def self_tests(root, python, env):
    fixtures = [
        ("valid", "pi-agent-test-env", "---\nname: pi-agent-test-env\ndescription: Validate frozen local experiments.\n---\nInstructions.\n", 0),
        ("unsupported-field", "pi-agent-test-env", "---\nname: pi-agent-test-env\ndescription: Test.\nlanguage: en\n---\n", 1),
        ("malformed-yaml", "pi-agent-test-env", "---\nname: [broken\n---\n", 1),
        ("missing-frontmatter", "pi-agent-test-env", "No frontmatter.\n", 1),
        ("missing-description", "pi-agent-test-env", "---\nname: pi-agent-test-env\n---\n", 1),
        ("wrong-directory", "wrong-name", "---\nname: pi-agent-test-env\ndescription: Test.\n---\n", 1),
    ]
    results = []
    for label, folder, content, expected in fixtures:
        path = root / "fixtures" / label / folder
        path.mkdir(parents=True)
        (path / "SKILL.md").write_text(content)
        results.append(validate(python, env, path, label, expected))
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path, help="Complete extracted skill roots named pi-agent-test-env")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if not args.paths and not args.self_test:
        parser.error("Provide skill paths or --self-test")
    if sys.version_info < (3, 11) or os.name != "posix":
        parser.error("Development validator requires Python 3.11+ on macOS/Linux/WSL; runtime requirement is unchanged")
    try:
        lock = checked_lock()
        with tempfile.TemporaryDirectory(prefix="pi-standard-validator-") as temporary:
            root = Path(temporary)
            python, env = tooling(root, lock)
            results = self_tests(root, python, env) if args.self_test else []
            results.extend(validate(python, env, p.resolve(), str(p)) for p in args.paths)
        report = {"status": "pass" if all(r["passed"] for r in results) else "fail",
                  "upstream_commit": lock["upstream_commit"], "offline": True,
                  "toolchain_lock_sha256": hashlib.sha256((HERE / "toolchain.lock.json").read_bytes()).hexdigest(),
                  "verified_vendor_files": lock["files"], "python_version": sys.version,
                  "temporary_tooling_removed": True, "checks": results}
        print(json.dumps(report, indent=2))
        return 0 if report["status"] == "pass" else 1
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"status": "blocked", "reason": str(exc)}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
