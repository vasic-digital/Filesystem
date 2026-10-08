#!/bin/sh
# build_image.sh - builds the go-nfs fixture image rootless and prints its manifest-digest reference (the form the compose file pins).
# Usage: sh build_image.sh   -> prints  image_ref=localhost/catalogizer-test-nfs3@sha256:...
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
podman build -q -t localhost/catalogizer-test-nfs3:dev -f "$HERE/Containerfile" "$HERE" >/dev/null
d="$(podman image inspect localhost/catalogizer-test-nfs3:dev --format '{{.Digest}}')"
echo "image_ref=localhost/catalogizer-test-nfs3@${d}"
