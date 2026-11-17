#!/usr/bin/env python3
"""Resolves the highest vX.Y.Z tag on the repo's GitHub origin."""
import json
import re
import subprocess
import sys

RELEASE_TAG_RE = re.compile(r"^refs/tags/(v(\d+)\.(\d+)\.(\d+))$")


def main() -> None:
    query = json.load(sys.stdin)
    result = subprocess.run(
        ["git", "-C", query["repo_dir"], "ls-remote", "--tags", "--refs", "origin"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        sys.exit(f"git ls-remote failed: {result.stderr.strip()}")

    releases = []
    for line in result.stdout.splitlines():
        match = RELEASE_TAG_RE.match(line.split("\t")[-1])
        if match:
            releases.append((tuple(int(part) for part in match.groups()[1:]), match.group(1)))

    if not releases:
        sys.exit("no vX.Y.Z tags found on origin")

    json.dump({"tag": max(releases)[1]}, sys.stdout)


if __name__ == "__main__":
    main()
