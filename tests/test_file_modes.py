"""Every script that claims to be executable must actually be executable in git.

CI runs `ruff check src/ scripts/ tests/ apps/ waf/` on Linux, and ruff's
EXE001 fires when a file starts with `#!` but git recorded mode 100644. That
check cannot fail on Windows: the filesystem has no exec bit, so a shebang
script committed from here lands in CI unexecutable and the workflow goes red.
One such file (`waf/waf_replay.py`) did exactly that.

The mode is read from git's index rather than the filesystem, so this is the
same number a Linux checkout receives, and it is checkable from any OS.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _index_modes() -> dict[str, str] | None:
    """Every tracked path -> its recorded git mode, or None outside a checkout."""
    try:
        out = subprocess.run(["git", "ls-files", "-s"], cwd=REPO,
                             capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    modes = {}
    for line in out.splitlines():
        mode, _, path = line.partition(" ")
        # a rename entry prints "mode <sha> stage \0old\0new"; keep the new path
        path = path.rsplit("\0", 1)[-1].split("\t", 1)[-1]
        modes[path.strip('"')] = mode
    return modes


def test_shebang_scripts_are_recorded_executable():
    modes = _index_modes()
    if modes is None:
        pytest.skip("not a git checkout (an unpacked tarball has no modes)")

    shebanged = [p for p in modes
                 if p.endswith((".py", ".sh"))
                 and (REPO / p).read_bytes()[:2] == b"#!"]
    # if parsing ever degrades so far that nothing looks like a script, this
    # test must fail rather than quietly certify the whole repo
    assert len(shebanged) > 10, f"only {len(shebanged)} shebang scripts found"

    unexecutable = sorted(p for p in shebanged if modes[p] != "100755")
    assert not unexecutable, (
        "these files open with a shebang but git records mode 100644, so ruff "
        "raises EXE001 on Linux CI; fix with "
        "`git update-index --chmod=+x <path>`: " + ", ".join(unexecutable))
