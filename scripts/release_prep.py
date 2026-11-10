#!/usr/bin/env python3
"""Prepare a release: bump the version constant and roll the CHANGELOG.

Usage:
    python3 scripts/release_prep.py {patch|minor|major}

Effects:
  * Reads ``__version__`` from ``app/app.py``, computes the next version for the
    requested bump, and writes it back.
  * In ``CHANGELOG.md`` renames the top ``## Unreleased`` section to
    ``## vX.Y.Z - YYYY-MM-DD`` and inserts a fresh, empty ``## Unreleased`` above
    it. Creates ``CHANGELOG.md`` (and a stub ``Unreleased`` section) if missing.

Prints ONLY the new version (e.g. ``1.2.3``) to stdout; all logs go to stderr,
so callers can do ``NEW=$(python3 scripts/release_prep.py patch)``.
"""
import datetime
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "app" / "app.py"
CHANGELOG = ROOT / "CHANGELOG.md"
VERSION_RE = re.compile(r'^__version__ = "(\d+)\.(\d+)\.(\d+)"$', re.M)


def log(msg):
    print(msg, file=sys.stderr)


def die(msg):
    log(f"error: {msg}")
    raise SystemExit(1)


def read_version(text):
    m = VERSION_RE.search(text)
    if not m:
        die('could not find `__version__ = "X.Y.Z"` in app/app.py')
    return tuple(int(x) for x in m.groups())


def bump(ver, kind):
    major, minor, patch = ver
    if kind == "major":
        return (major + 1, 0, 0)
    if kind == "minor":
        return (major, minor + 1, 0)
    if kind == "patch":
        return (major, minor, patch + 1)
    die(f"unknown bump kind {kind!r} (expected patch|minor|major)")


def roll_changelog(new_version):
    date = datetime.date.today().isoformat()
    release_head = f"## v{new_version} - {date}"
    if CHANGELOG.exists():
        text = CHANGELOG.read_text(encoding="utf-8")
    else:
        text = "# Changelog\n\n## Unreleased\n"
    if "## Unreleased" not in text:
        # No Unreleased section: add a stub one just under the top title (or at
        # the very top when there is no title).
        if text.lstrip().startswith("#"):
            idx = text.find("\n")
            text = (text + "\n\n## Unreleased\n") if idx == -1 \
                else text[:idx + 1] + "\n## Unreleased\n" + text[idx + 1:]
        else:
            text = "# Changelog\n\n## Unreleased\n\n" + text
    # Keep the Unreleased heading (now empty) and move its former body under the
    # new dated version heading.
    text = text.replace("## Unreleased", f"## Unreleased\n\n{release_head}", 1)
    CHANGELOG.write_text(text, encoding="utf-8")
    log(f"rolled CHANGELOG.md: new section '{release_head}'")


def main(argv):
    if len(argv) != 2 or argv[1] not in ("patch", "minor", "major"):
        die("usage: release_prep.py {patch|minor|major}")
    kind = argv[1]
    text = APP.read_text(encoding="utf-8")
    cur = read_version(text)
    new = bump(cur, kind)
    new_str = ".".join(str(x) for x in new)
    APP.write_text(VERSION_RE.sub(f'__version__ = "{new_str}"', text, count=1),
                   encoding="utf-8")
    log(f"bumped version {'.'.join(map(str, cur))} -> {new_str} ({kind})")
    roll_changelog(new_str)
    print(new_str)  # stdout: just the version, for the caller to capture


if __name__ == "__main__":
    main(sys.argv)
