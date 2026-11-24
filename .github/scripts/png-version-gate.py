#!/usr/bin/env python3
"""PNG version gate: report/ipv6 screenshots must follow a VERSION bump.

D-1 root cause: the 12 report/ipv6 showcase PNGs kept a stale title version
while the text-only version gate stayed green (PNG bytes are skipped by it).
This gate closes that hole at the change-set level:

  If acheck.py's VERSION differs between the base commit and HEAD,
  then all 12 docs/showcase-report-*.png and docs/showcase-ipv6-*.png
  must be among the files changed in that range (git diff base...HEAD).
  Otherwise the run fails, naming the untouched PNGs.

Base resolution (first usable wins):
  1. $BASE_SHA            (pull_request: github.event.pull_request.base.sha)
  2. $BEFORE_SHA          (push: github.event.before; all-zero is unusable)
  3. HEAD~1               (workflow_dispatch / manual run fallback)
The workflow checks out with fetch-depth: 0 so the base commit is present
even for shallow-clone runners; without it `git show $BASE:...` fails and
this gate errors out instead of silently passing.

This gate checks that the PNGs were *touched* in the same change-set as the
bump; pixel-level title verification lives in the local fixture
fix_batch434_d1.py (renders the title strip and compares it with the PNG).

Usage (local):
  BASE_SHA=<base> python3 .github/scripts/png-version-gate.py
  BEFORE_SHA=<before> python3 .github/scripts/png-version-gate.py
Exit 0 = PASS, 1 = FAIL (bump without all 12 PNGs), 2 = ERROR (no usable base).
Prints a VERDICT line in all cases.
"""
import os
import re
import subprocess
import sys

PNGS = [f"docs/showcase-{kind}-{lang}.png"
        for kind in ("report", "ipv6")
        for lang in ("en", "zh", "zh-TW", "ja", "ru", "fa")]
VER_RE = re.compile(r'^VERSION\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"', re.M)
ZERO_SHA = "0" * 40


def git(*args):
    r = subprocess.run(["git"] + list(args), capture_output=True, text=True)
    return r


def version_at(ref):
    """VERSION string of acheck.py at ref ('HEAD' or a sha), or None."""
    r = git("show", f"{ref}:acheck.py")
    if r.returncode != 0:
        return None
    m = VER_RE.search(r.stdout)
    return m.group(1) if m else None


def resolve_base():
    base = os.environ.get("BASE_SHA", "").strip()
    if base and base != ZERO_SHA:
        if git("cat-file", "-e", f"{base}^{{commit}}").returncode == 0:
            return base, "BASE_SHA"
        print(f"WARNING: BASE_SHA {base} not present in this checkout")
    before = os.environ.get("BEFORE_SHA", "").strip()
    if before and before != ZERO_SHA:
        if git("cat-file", "-e", f"{before}^{{commit}}").returncode == 0:
            return before, "BEFORE_SHA"
        print(f"WARNING: BEFORE_SHA {before} not present in this checkout")
    head_parent = git("rev-parse", "HEAD~1")
    if head_parent.returncode == 0:
        return head_parent.stdout.strip(), "HEAD~1 (dispatch fallback)"
    return None, None


def main():
    base, how = resolve_base()
    if base is None:
        print("ERROR: no usable base commit (BASE_SHA/BEFORE_SHA unset or "
              "unresolvable, and no HEAD~1)")
        print("VERDICT: ERROR")
        return 2
    print(f"base: {base} (via {how})")
    head_ver = version_at("HEAD")
    base_ver = version_at(base)
    if head_ver is None:
        print("ERROR: VERSION not found in acheck.py at HEAD")
        print("VERDICT: ERROR")
        return 2
    if base_ver is None:
        print(f"ERROR: VERSION not found in acheck.py at base {base} "
              "(base predates VERSION or is not an A-Check tree)")
        print("VERDICT: ERROR")
        return 2
    print(f"VERSION: base={base_ver} HEAD={head_ver}")
    if base_ver == head_ver:
        print("no VERSION change in range; gate vacuous")
        print("VERDICT: PASS")
        return 0
    r = git("diff", "--name-only", f"{base}...HEAD")
    if r.returncode != 0:
        print(f"ERROR: git diff failed: {r.stderr.strip()[:200]}")
        print("VERDICT: ERROR")
        return 2
    changed = set(r.stdout.split())
    missing = [p for p in PNGS if p not in changed]
    if missing:
        print(f"ERROR: VERSION changed {base_ver} -> {head_ver} but "
              f"{len(missing)}/12 showcase PNGs were not changed:")
        for p in missing:
            print(f"  - {p}")
        print("VERDICT: FAIL")
        return 1
    print(f"VERSION changed {base_ver} -> {head_ver} and all 12 "
          "report/ipv6 PNGs changed in range")
    print("VERDICT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
