#!/bin/bash

# Test script to run all auth endpoint tests
# Usage: ./test_all.sh [BASE_URL]
# Default BASE_URL: http://localhost:8080

BASE_URL="${1:-http://localhost:8080}"

echo "=========================================="
echo "Running all authentication endpoint tests"
echo "Base URL: ${BASE_URL}"
echo "=========================================="
echo ""

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Run register tests first (to create test user)
echo "Step 1: Running register tests..."
echo ""
bash "${SCRIPT_DIR}/test_register.sh" "${BASE_URL}"
echo ""
echo ""

# Run login tests (requires test user to exist)
echo "Step 2: Running login tests..."
echo ""
bash "${SCRIPT_DIR}/test_login.sh" "${BASE_URL}"
echo ""
echo ""

echo "=========================================="
echo "All tests completed"
echo "=========================================="

