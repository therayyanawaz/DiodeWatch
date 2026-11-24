"""A pin checker nobody has seen fail is a checker that may check nothing.

Each fault the lock can develop is planted here: a requirement the lock omits, an
entry pinned to a floating version, a duplicate entry, and an entry with no hash
when hashes are required. The offline checker must name each one, and the real
`requirements.lock` in the tree must pass.
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "checks" / "make_lock.py"
LOCK = REPO / "requirements.lock"


def _module():
    spec = importlib.util.spec_from_file_location("make_lock", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_the_shipped_lock_covers_every_requirement_at_an_exact_version():
    proc = subprocess.run([sys.executable, str(SCRIPT), "--check"],
                          capture_output=True, text=True, timeout=120, check=False)
    assert proc.returncode == 0, proc.stderr
    assert "lock OK" in proc.stdout


def test_an_omitted_requirement_is_reported(tmp_path):
    lock = tmp_path / "requirements.lock"
    lock.write_text("numpy==2.0.0\n", encoding="utf-8")
    problems = _module().check(lock)
    assert any("required but not locked" in p for p in problems), problems


def test_a_floating_version_is_reported(tmp_path):
    make_lock = _module()
    lines = ["numpy==*" if name == "numpy" else f"{name}==1.0"
             for name in make_lock.requirement_names()]
    lock = tmp_path / "requirements.lock"
    lock.write_text("\n".join(lines) + "\n", encoding="utf-8")
    problems = make_lock.check(lock)
    assert any("not pinned to an exact version" in p for p in problems), problems


def test_a_duplicate_entry_is_reported(tmp_path):
    make_lock = _module()
    names = make_lock.requirement_names()
    lines = [f"{n}==1.0" for n in names] + [f"{names[0]}==1.0"]
    lock = tmp_path / "requirements.lock"
    lock.write_text("\n".join(lines) + "\n", encoding="utf-8")
    problems = make_lock.check(lock)
    assert any("listed twice" in p for p in problems), problems


def test_require_hashes_rejects_an_entry_without_one(tmp_path):
    make_lock = _module()
    lines = [f"{n}==1.0" for n in make_lock.requirement_names()]
    lock = tmp_path / "requirements.lock"
    lock.write_text("\n".join(lines) + "\n", encoding="utf-8")
    # structurally fine without the flag, a failure with it
    assert not make_lock.check(lock, require_hashes=False)
    problems = make_lock.check(lock, require_hashes=True)
    assert all("carries no hash" in p for p in problems)
    assert len(problems) == len(make_lock.requirement_names())


def test_a_hashed_entry_satisfies_the_hash_requirement(tmp_path):
    make_lock = _module()
    digest = "a" * 64
    lines = []
    for name in make_lock.requirement_names():
        lines += [f"{name}==1.0 \\", f"    --hash=sha256:{digest}"]
    lock = tmp_path / "requirements.lock"
    lock.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not make_lock.check(lock, require_hashes=True)


def test_a_missing_lock_file_is_reported_not_crashed(tmp_path):
    problems = _module().check(tmp_path / "nope.lock")
    assert problems == ["nope.lock is missing"]
