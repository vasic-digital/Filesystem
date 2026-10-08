#!/bin/bash
# run_integration.sh - runs INSIDE the pinned IMG-GO container (see docs/scripts note in the evidence README). It needs BASH, not a POSIX sh: the
# readiness probe uses bash's /dev/tcp (the image's /bin/sh is dash, where the probe can never succeed and the script would always fail after 10 s):
#   bash scripts/containers/run_pinned.sh IMG-GO -- bash /src/submodules/filesystem/test/nfs3fixture/run_integration.sh
# Builds the go-nfs fixture, starts it on 127.0.0.1:12049 as a background process, writes the server-side manifest,
# then runs the pkg/nfs3 integration tests (tag nfs3fixture) against it. Rootless, no capability, nothing mounted.
# A second fixture process (port 12050, -authsys) verifies every call's AUTH_SYS credential with an independent XDR decoder;
# its log is NFS3_FIXTURE_AUTHLOG and its address NFS3_FIXTURE_AUTHSYS_ADDR (only started for the in-container fixture).
# Env: NFS3_FIXTURE_EXTERNAL=host:port uses an already running fixture container instead of the in-container process.
#      INTEGRATION_RUN (go test -run regexp, default GoNFS), INTEGRATION_COUNT (default 1).
set -eu
FX=/src/submodules/filesystem/test/nfs3fixture
export GOTOOLCHAIN=local
cd "$FX"
CGO_ENABLED=0 go build -trimpath -o /tmp/nfs3fixture .
/tmp/nfs3fixture -manifest /tmp/nfs3-manifest.json
ADDR="${NFS3_FIXTURE_EXTERNAL:-}"
if [ -z "$ADDR" ]; then
  ADDR=127.0.0.1:12049
  /tmp/nfs3fixture -listen "$ADDR" >/tmp/nfs3fixture.log 2>&1 &
  SRV=$!
  rm -f /tmp/nfs3-auth.log
  # DISTINCT uid, gid and gid values (not uid = gid): an encoder that swaps or shifts them must be seen by the oracle. The same identity is in
  # TestGoNFSAuthSysCredentialIsWellFormed.
  /tmp/nfs3fixture -listen 127.0.0.1:12050 -authsys -authlog /tmp/nfs3-auth.log -authuid 1234 -authgid 2345 -authgids 4,24,3456 >/tmp/nfs3fixture-authsys.log 2>&1 &
  SRV2=$!
  trap 'kill "$SRV" "$SRV2" 2>/dev/null || true' EXIT
  for port in 12049 12050; do
    i=0
    until (exec 3<>/dev/tcp/127.0.0.1/$port) 2>/dev/null; do
      i=$((i + 1)); [ "$i" -lt 100 ] || { echo "fixture on $port did not start"; cat /tmp/nfs3fixture.log /tmp/nfs3fixture-authsys.log; exit 1; }
      sleep 0.1
    done
  done
  export NFS3_FIXTURE_AUTHSYS_ADDR=127.0.0.1:12050 NFS3_FIXTURE_AUTHLOG=/tmp/nfs3-auth.log
fi
cd /src/submodules/filesystem
set +e
NFS3_FIXTURE_ADDR="$ADDR" NFS3_FIXTURE_MANIFEST=/tmp/nfs3-manifest.json \
  GOMAXPROCS=3 go test -tags nfs3fixture -race -count="${INTEGRATION_COUNT:-1}" -run "${INTEGRATION_RUN:-GoNFS}" -v ./pkg/nfs3/
rc=$?
set -e
if [ -f /tmp/nfs3-auth.log ]; then
  echo "--- AUTH_SYS tap log: $(grep -c '^OK ' /tmp/nfs3-auth.log) OK lines, $(grep -c '^VIOLATION' /tmp/nfs3-auth.log) VIOLATION lines (first 6 lines follow)"
  head -6 /tmp/nfs3-auth.log
fi
exit "$rc"
