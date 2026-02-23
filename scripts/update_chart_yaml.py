#!/usr/bin/env python3
# We use a dedicated script because PSR's version_variables replacement is name-based and
# will update all matching keys. Chart.yaml has two "version:" keys (chart + dependency),
# so a config-only approach would also rewrite the dependency pin. This script updates only
# top-level "version" and "appVersion" using NEW_VERSION provided by PSR.
from __future__ import annotations

import os
import re
import sys
from pathlib import Path


CHART_PATH = Path(__file__).resolve().parents[1] / "helm" / "whispers" / "Chart.yaml"

def main() -> int:
    new_version = os.environ.get("NEW_VERSION", "").strip()
    if not new_version:
        print("NEW_VERSION is not set", file=sys.stderr)
        return 1

    if not re.fullmatch(r"\d+\.\d+\.\d+", new_version):
        print(f"NEW_VERSION is not valid SemVer X.Y.Z: {new_version}", file=sys.stderr)
        return 1

    if not CHART_PATH.exists():
        print(f"Chart.yaml not found at {CHART_PATH}", file=sys.stderr)
        return 1

    lines = CHART_PATH.read_text(encoding="utf-8").splitlines()
    updated_version = False
    updated_app_version = False
    new_lines: list[str] = []

    for line in lines:
        if re.match(r"^version:\s*", line):
            new_lines.append(f"version: {new_version}")
            updated_version = True
            continue
        if re.match(r"^appVersion:\s*", line):
            new_lines.append(f'appVersion: "{new_version}"')
            updated_app_version = True
            continue
        new_lines.append(line)

    if not updated_version or not updated_app_version:
        missing = []
        if not updated_version:
            missing.append("version")
        if not updated_app_version:
            missing.append("appVersion")
        print(f"Chart.yaml missing fields: {', '.join(missing)}", file=sys.stderr)
        return 1

    CHART_PATH.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
