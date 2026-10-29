#!/usr/bin/env bash
set -euo pipefail

release_ref="${1:?release ref required}"
artifact_spec="${2:-dist/*.whl}"
workdir="${TMPDIR:-/tmp}/scan-release-work"

mkdir -p "$workdir"
trap 'rm -rf -- "$workdir"' EXIT

fetch_cmd="git fetch origin $release_ref"
eval "$fetch_cmd"

upload_cmd="python -m twine upload $artifact_spec"
eval "$upload_cmd"
