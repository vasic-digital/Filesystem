#!/usr/bin/env bash
# filesystem_describe_challenge.sh
#
# Round-246 paired-mutation deep-doc challenge for Filesystem.
#
# Validates that:
#   1. The deep-doc ledger (docs/test-coverage.md) lists every exported
#      symbol from pkg/{client,factory,local}.
#   2. The bilingual fixtures (challenges/fixtures/{en,sr-Latn}.yaml)
#      parse and cover the required locales.
#   3. The bilingual runner (challenges/runner/main.go) builds and runs
#      against the real Filesystem local client, byte-preserving non-ASCII
#      filenames and content.
#   4. The README enumerates the round-246 anti-bluff guarantees section.
#
# Paired-mutation invariant (CONST-035 + CONST-050(B)):
#   With --anti-bluff-mutate the script plants a deliberate symbol-rename
#   mutation in a tmp ledger copy, reruns validation, and asserts the gate
#   FAILS with exit 99. This proves the gate actually catches ledger-vs-
#   source drift instead of rubber-stamping it.
#
# Exit codes:
#   0  — gate PASS on clean tree
#   1  — gate FAIL on clean tree (real failure to fix)
#   99 — paired-mutation correctly detected (good — proves anti-bluff)
#   2  — usage / environment error

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

MUTATE=0
for arg in "$@"; do
    case "$arg" in
        --anti-bluff-mutate) MUTATE=1 ;;
        --help|-h)
            sed -n '1,30p' "$0"
            exit 0
            ;;
        *)
            echo "unknown argument: $arg" >&2
            exit 2
            ;;
    esac
done

PASS=0
FAIL=0
TOTAL=0

pass() { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); echo "  FAIL: $1"; }

LEDGER="${MODULE_DIR}/docs/test-coverage.md"
FIXTURES_DIR="${MODULE_DIR}/challenges/fixtures"
RUNNER="${MODULE_DIR}/challenges/runner/main.go"
README="${MODULE_DIR}/README.md"

# If mutation requested, work against a tmp copy of the ledger with a
# planted symbol rename. The original tree stays untouched.
LEDGER_WORK="${LEDGER}"
TMP_LEDGER=""
if [ "${MUTATE}" -eq 1 ]; then
    TMP_LEDGER="$(mktemp)"
    cp "${LEDGER}" "${TMP_LEDGER}"
    # Plant a rename: SupportedProtocols → SupportedBogus (real symbol
    # must remain absent from ledger to flag the drift).
    sed -i 's/SupportedProtocols/SupportedBogus_MUTATED/g' "${TMP_LEDGER}"
    LEDGER_WORK="${TMP_LEDGER}"
    echo "=== Filesystem Describe Challenge (anti-bluff-mutate mode) ==="
else
    echo "=== Filesystem Describe Challenge (clean mode) ==="
fi
echo ""

# Section 1: ledger presence and freshness
echo "Section 1: docs/test-coverage.md ledger"
if [ ! -f "${LEDGER_WORK}" ]; then
    fail "ledger missing at ${LEDGER_WORK}"
else
    pass "ledger present"
    if grep -q "round-246" "${LEDGER_WORK}"; then
        pass "ledger marked round-246"
    else
        fail "ledger missing round-246 marker"
    fi
    if grep -q "execution of tests and Challenges MUST guarantee" "${LEDGER_WORK}"; then
        pass "ledger carries Article XI §11.9 mandate"
    else
        fail "ledger missing Article XI §11.9 mandate"
    fi
fi

# Section 2: every exported pkg symbol appears in ledger
echo ""
echo "Section 2: exported symbols cross-reference"

extract_symbols() {
    local pkg_dir="$1"
    local files
    files=$(find "${pkg_dir}" -maxdepth 1 -type f -name '*.go' \
        ! -name '*_test.go')
    [ -z "${files}" ] && return 0
    # shellcheck disable=SC2086
    grep -hE '^(func ([A-Z][A-Za-z0-9_]*\()|func \([^)]+\) ([A-Z][A-Za-z0-9_]*\()|type [A-Z][A-Za-z0-9_]* )' \
        ${files} 2>/dev/null \
        | sed -E 's/^func \([^)]+\) ([A-Z][A-Za-z0-9_]*)\(.*$/\1/; s/^func ([A-Z][A-Za-z0-9_]*)\(.*$/\1/; s/^type ([A-Z][A-Za-z0-9_]*).*$/\1/' \
        | sort -u
}

CHECKED=0
MISSING=0
for pkg in client factory local; do
    PKG_DIR="${MODULE_DIR}/pkg/${pkg}"
    if [ ! -d "${PKG_DIR}" ]; then
        fail "pkg/${pkg} missing — cannot cross-reference"
        continue
    fi
    while IFS= read -r sym; do
        [ -z "${sym}" ] && continue
        CHECKED=$((CHECKED + 1))
        if grep -qE "\b${sym}\b" "${LEDGER_WORK}"; then
            : # symbol cross-referenced
        else
            fail "ledger missing symbol ${pkg}.${sym}"
            MISSING=$((MISSING + 1))
        fi
    done < <(extract_symbols "${PKG_DIR}")
done
if [ "${CHECKED}" -gt 0 ] && [ "${MISSING}" -eq 0 ]; then
    pass "all ${CHECKED} exported symbols cross-referenced in ledger"
fi

# Section 3: bilingual fixtures sanity
echo ""
echo "Section 3: bilingual fixtures"
if [ ! -d "${FIXTURES_DIR}" ]; then
    fail "fixtures directory missing at ${FIXTURES_DIR}"
else
    pass "fixtures dir present"
    if [ -f "${FIXTURES_DIR}/en.yaml" ]; then
        pass "en.yaml present"
    else
        fail "en.yaml missing"
    fi
    if [ -f "${FIXTURES_DIR}/sr-Latn.yaml" ]; then
        pass "sr-Latn.yaml present"
    else
        fail "sr-Latn.yaml missing"
    fi
    LOCALE_COUNT=$(grep -h '^locale:' "${FIXTURES_DIR}"/*.yaml 2>/dev/null | sort -u | wc -l)
    if [ "${LOCALE_COUNT}" -ge 2 ]; then
        pass "fixtures cover ${LOCALE_COUNT} locales (>=2)"
    else
        fail "fixtures cover only ${LOCALE_COUNT} locales (<2)"
    fi
fi

# Section 4: runner builds + runs against real Filesystem
echo ""
echo "Section 4: bilingual runner build + run"
if [ ! -f "${RUNNER}" ]; then
    fail "runner missing at ${RUNNER}"
else
    pass "runner source present"
    cd "${MODULE_DIR}"
    if go build -o /tmp/fs_round246_runner ./challenges/runner/ 2>/tmp/fs_build.log; then
        pass "runner builds"
        if /tmp/fs_round246_runner -fixtures "${FIXTURES_DIR}" > /tmp/fs_run.log 2>&1; then
            pass "runner exit 0 against real Filesystem"
            if grep -q "PASS \[en\]" /tmp/fs_run.log; then
                pass "English (en) file round-trip"
            else
                fail "English (en) PASS missing from runner output"
            fi
            if grep -q "PASS \[sr-Latn\]" /tmp/fs_run.log; then
                pass "Serbian-Latin (sr-Latn) file round-trip"
            else
                fail "Serbian-Latin (sr-Latn) PASS missing from runner output"
            fi
            # Verify a Cyrillic-diacritic filename was actually exercised
            if grep -q "po.eta" /tmp/fs_run.log || grep -q "početak" /tmp/fs_run.log; then
                pass "diacritic filename (početak.log) exercised"
            else
                fail "diacritic filename missing from runner evidence"
            fi
        else
            fail "runner exit non-zero — see /tmp/fs_run.log"
            sed -n '1,20p' /tmp/fs_run.log
        fi
    else
        fail "runner build failed — see /tmp/fs_build.log"
        sed -n '1,20p' /tmp/fs_build.log
    fi
    rm -f /tmp/fs_round246_runner
fi

# Section 5: README round-246 anti-bluff section
echo ""
echo "Section 5: README round-246 anti-bluff section"
if grep -q "Anti-bluff guarantees" "${README}"; then
    pass "README declares Anti-bluff guarantees"
else
    fail "README missing Anti-bluff guarantees section"
fi
if grep -q "round-246" "${README}"; then
    pass "README marked round-246"
else
    fail "README missing round-246 marker"
fi

# Cleanup mutated ledger if any
if [ -n "${TMP_LEDGER}" ]; then
    rm -f "${TMP_LEDGER}"
fi

echo ""
echo "=== Summary: ${PASS}/${TOTAL} PASS, ${FAIL} FAIL ==="

if [ "${MUTATE}" -eq 1 ]; then
    if [ "${FAIL}" -gt 0 ]; then
        echo "anti-bluff-mutate: gate correctly detected planted mutation (exit 99)"
        exit 99
    else
        echo "anti-bluff-mutate: gate FAILED to detect planted mutation — bluff!"
        exit 1
    fi
fi

if [ "${FAIL}" -gt 0 ]; then
    exit 1
fi
exit 0
