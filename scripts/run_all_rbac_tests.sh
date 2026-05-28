#!/usr/bin/env bash

set -u

# Wrapper to run both RBAC suites and print one summary.

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REGRESSION_SCRIPT="$ROOT_DIR/scripts/rbac_regression_flow.sh"
NEGATIVE_SCRIPT="$ROOT_DIR/scripts/rbac_negative_tests.sh"

overall_rc=0

echo "==> Running RBAC regression happy-path"
bash "$REGRESSION_SCRIPT"
regression_rc=$?
if [[ $regression_rc -ne 0 ]]; then
  echo "FAIL: rbac_regression_flow.sh exited with code $regression_rc"
  overall_rc=1
else
  echo "PASS: rbac_regression_flow.sh"
fi

echo
echo "==> Running RBAC negative tests"
bash "$NEGATIVE_SCRIPT"
negative_rc=$?
if [[ $negative_rc -ne 0 ]]; then
  echo "FAIL: rbac_negative_tests.sh exited with code $negative_rc"
  overall_rc=1
else
  echo "PASS: rbac_negative_tests.sh"
fi

echo
if [[ $overall_rc -eq 0 ]]; then
  echo "ALL PASS: RBAC suites completed successfully."
else
  echo "FAILED: One or more RBAC suites failed."
fi

exit $overall_rc
