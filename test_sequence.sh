#!/usr/bin/env bash
#
# test_sequence.sh — End-to-end integration test for PES-VCS
#
# Run from the repository root after compiling:
#   make
#   ./test_sequence.sh

set -euo pipefail

PES="$(cd "$(dirname "$0")" && pwd)/pes"
TEST_DIR="$(mktemp -d)"

cleanup() {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

cd "$TEST_DIR"

echo "=== PES-VCS Integration Test ==="
echo ""

# ── Init ───────────────────────────────────────────────────────────────────
echo "--- Repository Initialization ---"
$PES init
[ -d .pes/objects ] && echo "PASS: .pes/objects exists" || echo "FAIL: .pes/objects missing"
[ -d .pes/refs/heads ] && echo "PASS: .pes/refs/heads exists" || echo "FAIL: .pes/refs/heads missing"
[ -f .pes/HEAD ] && echo "PASS: .pes/HEAD exists" || echo "FAIL: .pes/HEAD missing"
echo ""

# ── Add and Status ─────────────────────────────────────────────────────────
echo "--- Staging Files ---"
echo "version 1" > file.txt
echo "hello world" > hello.txt
$PES add file.txt hello.txt
echo "Status after add:"
$PES status
echo ""

# ── First Commit ───────────────────────────────────────────────────────────
echo "--- First Commit ---"
$PES commit -m "Initial commit"
echo ""
echo "Log after first commit:"
$PES log
echo ""

# ── Modify and Recommit ───────────────────────────────────────────────────
echo "--- Second Commit ---"
echo "version 2" >> file.txt
$PES add file.txt
$PES commit -m "Update file.txt"
echo ""

# ── Third Commit ──────────────────────────────────────────────────────────
echo "--- Third Commit ---"
echo "goodbye" > bye.txt
$PES add bye.txt
$PES commit -m "Add farewell"
echo ""

echo "--- Full History ---"
$PES log
echo ""

echo "--- Reference Chain ---"
echo "HEAD:"
cat .pes/HEAD
echo "refs/heads/main:"
cat .pes/refs/heads/main
echo ""

echo "--- Object Store ---"
echo "Objects created:"
find .pes/objects -type f | wc -l
find .pes/objects -type f | sort
echo ""

echo "=== All integration tests completed ==="
