#!/bin/bash

# Test script for /register and /login endpoints
# Usage: ./test_register_and_login.sh [BASE_URL]
# Default BASE_URL: http://localhost:8080
#
# This script registers a new user with a random name and then tests login.

BASE_URL="${1:-http://localhost:8080}"
REGISTER_URL="${BASE_URL}/register"
LOGIN_URL="${BASE_URL}/login"

echo "=========================================="
echo "Testing /register and /login endpoints"
echo "=========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Generate random username
RANDOM_USER="testuser_$(date +%s)_$RANDOM"
TEST_PASSWORD="testpass123"

echo -e "${YELLOW}Generated random username: ${RANDOM_USER}${NC}"
echo ""

# ============================================
# REGISTRATION TESTS
# ============================================

echo "=========================================="
echo "PART 1: Registration Tests"
echo "=========================================="
echo ""

# Test 1: Successful registration
echo -e "${YELLOW}Test 1: Successful registration${NC}"
echo "Request: POST ${REGISTER_URL}"
echo "Payload: {\"login\": \"${RANDOM_USER}\", \"password\": \"${TEST_PASSWORD}\"}"
echo ""
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "${REGISTER_URL}" \
  -H "Content-Type: application/json" \
  -d "{\"login\": \"${RANDOM_USER}\", \"password\": \"${TEST_PASSWORD}\"}")

HTTP_CODE=$(echo "$RESPONSE" | grep -o "HTTP_CODE:[0-9]*" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed 's/HTTP_CODE:[0-9]*$//')

if [ "$HTTP_CODE" = "201" ]; then
  echo -e "${GREEN}✓ PASS: Expected 201 Created, got ${HTTP_CODE}${NC}"
  REGISTRATION_SUCCESS=true
else
  echo -e "${RED}✗ FAIL: Expected 201 Created, got ${HTTP_CODE}${NC}"
  REGISTRATION_SUCCESS=false
fi
echo "Response body: $BODY"
echo ""
echo "----------------------------------------"
echo ""

# If registration failed, exit early
if [ "$REGISTRATION_SUCCESS" = "false" ]; then
  echo -e "${RED}Registration failed. Cannot proceed with login tests.${NC}"
  exit 1
fi

# Test 2: Attempt to register existing user (should fail with 409 Conflict)
echo -e "${YELLOW}Test 2: Register existing user (should return 409 Conflict)${NC}"
echo "Request: POST ${REGISTER_URL}"
echo "Payload: {\"login\": \"${RANDOM_USER}\", \"password\": \"${TEST_PASSWORD}\"}"
echo ""
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "${REGISTER_URL}" \
  -H "Content-Type: application/json" \
  -d "{\"login\": \"${RANDOM_USER}\", \"password\": \"${TEST_PASSWORD}\"}")

HTTP_CODE=$(echo "$RESPONSE" | grep -o "HTTP_CODE:[0-9]*" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed 's/HTTP_CODE:[0-9]*$//')

if [ "$HTTP_CODE" = "409" ]; then
  echo -e "${GREEN}✓ PASS: Expected 409 Conflict, got ${HTTP_CODE}${NC}"
else
  echo -e "${RED}✗ FAIL: Expected 409 Conflict, got ${HTTP_CODE}${NC}"
fi
echo "Response body: $BODY"
echo ""
echo "----------------------------------------"
echo ""

# Test 3: Missing password field (should fail with 400 Bad Request or 422)
echo -e "${YELLOW}Test 3: Missing password field${NC}"
echo "Request: POST ${REGISTER_URL}"
echo "Payload: {\"login\": \"testuser_missing_pass\"}"
echo ""
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "${REGISTER_URL}" \
  -H "Content-Type: application/json" \
  -d '{"login": "testuser_missing_pass"}')

HTTP_CODE=$(echo "$RESPONSE" | grep -o "HTTP_CODE:[0-9]*" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed 's/HTTP_CODE:[0-9]*$//')

if [ "$HTTP_CODE" = "400" ] || [ "$HTTP_CODE" = "422" ]; then
  echo -e "${GREEN}✓ PASS: Expected 400/422 for missing field, got ${HTTP_CODE}${NC}"
else
  echo -e "${RED}✗ FAIL: Expected 400/422, got ${HTTP_CODE}${NC}"
fi
echo "Response body: $BODY"
echo ""
echo "----------------------------------------"
echo ""

# Test 4: Invalid JSON
echo -e "${YELLOW}Test 4: Invalid JSON${NC}"
echo "Request: POST ${REGISTER_URL}"
echo "Payload: {invalid json}"
echo ""
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "${REGISTER_URL}" \
  -H "Content-Type: application/json" \
  -d '{invalid json}')

HTTP_CODE=$(echo "$RESPONSE" | grep -o "HTTP_CODE:[0-9]*" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed 's/HTTP_CODE:[0-9]*$//')

if [ "$HTTP_CODE" = "400" ]; then
  echo -e "${GREEN}✓ PASS: Expected 400 Bad Request for invalid JSON, got ${HTTP_CODE}${NC}"
else
  echo -e "${RED}✗ FAIL: Expected 400, got ${HTTP_CODE}${NC}"
fi
echo "Response body: $BODY"
echo ""
echo "----------------------------------------"
echo ""

# ============================================
# LOGIN TESTS
# ============================================

echo "=========================================="
echo "PART 2: Login Tests"
echo "=========================================="
echo ""

# Test 1: Successful login with newly registered user
echo -e "${YELLOW}Test 1: Successful login with registered user${NC}"
echo "Request: POST ${LOGIN_URL}"
echo "Payload: {\"username\": \"${RANDOM_USER}\", \"password\": \"${TEST_PASSWORD}\"}"
echo ""
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "${LOGIN_URL}" \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"${RANDOM_USER}\", \"password\": \"${TEST_PASSWORD}\"}")

HTTP_CODE=$(echo "$RESPONSE" | grep -o "HTTP_CODE:[0-9]*" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed 's/HTTP_CODE:[0-9]*$//')

if [ "$HTTP_CODE" = "200" ]; then
  echo -e "${GREEN}✓ PASS: Expected 200 OK, got ${HTTP_CODE}${NC}"
  if echo "$BODY" | grep -q "Login successful"; then
    echo -e "${GREEN}✓ PASS: Response contains 'Login successful'${NC}"
  else
    echo -e "${RED}✗ FAIL: Response should contain 'Login successful'${NC}"
  fi
else
  echo -e "${RED}✗ FAIL: Expected 200 OK, got ${HTTP_CODE}${NC}"
fi
echo "Response body: $BODY"
echo ""
echo "----------------------------------------"
echo ""

# Test 2: Wrong password (should fail with 401 Unauthorized)
echo -e "${YELLOW}Test 2: Wrong password (should return 401 Unauthorized)${NC}"
echo "Request: POST ${LOGIN_URL}"
echo "Payload: {\"username\": \"${RANDOM_USER}\", \"password\": \"wrongpass\"}"
echo ""
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "${LOGIN_URL}" \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"${RANDOM_USER}\", \"password\": \"wrongpass\"}")

HTTP_CODE=$(echo "$RESPONSE" | grep -o "HTTP_CODE:[0-9]*" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed 's/HTTP_CODE:[0-9]*$//')

if [ "$HTTP_CODE" = "401" ]; then
  echo -e "${GREEN}✓ PASS: Expected 401 Unauthorized, got ${HTTP_CODE}${NC}"
else
  echo -e "${RED}✗ FAIL: Expected 401 Unauthorized, got ${HTTP_CODE}${NC}"
fi
echo "Response body: $BODY"
echo ""
echo "----------------------------------------"
echo ""

# Test 3: Non-existent user (should fail with 401 Unauthorized)
echo -e "${YELLOW}Test 3: Non-existent user (should return 401 Unauthorized)${NC}"
echo "Request: POST ${LOGIN_URL}"
echo "Payload: {\"username\": \"nonexistent_user_12345\", \"password\": \"${TEST_PASSWORD}\"}"
echo ""
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "${LOGIN_URL}" \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"nonexistent_user_12345\", \"password\": \"${TEST_PASSWORD}\"}")

HTTP_CODE=$(echo "$RESPONSE" | grep -o "HTTP_CODE:[0-9]*" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed 's/HTTP_CODE:[0-9]*$//')

if [ "$HTTP_CODE" = "401" ]; then
  echo -e "${GREEN}✓ PASS: Expected 401 Unauthorized, got ${HTTP_CODE}${NC}"
else
  echo -e "${RED}✗ FAIL: Expected 401 Unauthorized, got ${HTTP_CODE}${NC}"
fi
echo "Response body: $BODY"
echo ""
echo "----------------------------------------"
echo ""

# Test 4: Missing password field (should fail with 400 Bad Request or 422)
echo -e "${YELLOW}Test 4: Missing password field${NC}"
echo "Request: POST ${LOGIN_URL}"
echo "Payload: {\"username\": \"${RANDOM_USER}\"}"
echo ""
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "${LOGIN_URL}" \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"${RANDOM_USER}\"}")

HTTP_CODE=$(echo "$RESPONSE" | grep -o "HTTP_CODE:[0-9]*" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed 's/HTTP_CODE:[0-9]*$//')

if [ "$HTTP_CODE" = "400" ] || [ "$HTTP_CODE" = "422" ]; then
  echo -e "${GREEN}✓ PASS: Expected 400/422 for missing field, got ${HTTP_CODE}${NC}"
else
  echo -e "${RED}✗ FAIL: Expected 400/422, got ${HTTP_CODE}${NC}"
fi
echo "Response body: $BODY"
echo ""
echo "----------------------------------------"
echo ""

# Test 5: Missing username field
echo -e "${YELLOW}Test 5: Missing username field${NC}"
echo "Request: POST ${LOGIN_URL}"
echo "Payload: {\"password\": \"${TEST_PASSWORD}\"}"
echo ""
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "${LOGIN_URL}" \
  -H "Content-Type: application/json" \
  -d "{\"password\": \"${TEST_PASSWORD}\"}")

HTTP_CODE=$(echo "$RESPONSE" | grep -o "HTTP_CODE:[0-9]*" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed 's/HTTP_CODE:[0-9]*$//')

if [ "$HTTP_CODE" = "400" ] || [ "$HTTP_CODE" = "422" ]; then
  echo -e "${GREEN}✓ PASS: Expected 400/422 for missing field, got ${HTTP_CODE}${NC}"
else
  echo -e "${RED}✗ FAIL: Expected 400/422, got ${HTTP_CODE}${NC}"
fi
echo "Response body: $BODY"
echo ""
echo "----------------------------------------"
echo ""

# Test 6: Invalid JSON
echo -e "${YELLOW}Test 6: Invalid JSON${NC}"
echo "Request: POST ${LOGIN_URL}"
echo "Payload: {invalid json}"
echo ""
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "${LOGIN_URL}" \
  -H "Content-Type: application/json" \
  -d '{invalid json}')

HTTP_CODE=$(echo "$RESPONSE" | grep -o "HTTP_CODE:[0-9]*" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed 's/HTTP_CODE:[0-9]*$//')

if [ "$HTTP_CODE" = "400" ]; then
  echo -e "${GREEN}✓ PASS: Expected 400 Bad Request for invalid JSON, got ${HTTP_CODE}${NC}"
else
  echo -e "${RED}✗ FAIL: Expected 400, got ${HTTP_CODE}${NC}"
fi
echo "Response body: $BODY"
echo ""
echo "----------------------------------------"
echo ""

# Test 7: Empty username
echo -e "${YELLOW}Test 7: Empty username${NC}"
echo "Request: POST ${LOGIN_URL}"
echo "Payload: {\"username\": \"\", \"password\": \"${TEST_PASSWORD}\"}"
echo ""
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "${LOGIN_URL}" \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"\", \"password\": \"${TEST_PASSWORD}\"}")

HTTP_CODE=$(echo "$RESPONSE" | grep -o "HTTP_CODE:[0-9]*" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed 's/HTTP_CODE:[0-9]*$//')

# Should return 401 (user not found) or 400 (validation error)
if [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "400" ]; then
  echo -e "${GREEN}✓ PASS: Expected 401/400 for empty username, got ${HTTP_CODE}${NC}"
else
  echo -e "${RED}✗ FAIL: Expected 401/400, got ${HTTP_CODE}${NC}"
fi
echo "Response body: $BODY"
echo ""
echo "----------------------------------------"
echo ""

# Test 8: Empty password
echo -e "${YELLOW}Test 8: Empty password${NC}"
echo "Request: POST ${LOGIN_URL}"
echo "Payload: {\"username\": \"${RANDOM_USER}\", \"password\": \"\"}"
echo ""
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "${LOGIN_URL}" \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"${RANDOM_USER}\", \"password\": \"\"}")

HTTP_CODE=$(echo "$RESPONSE" | grep -o "HTTP_CODE:[0-9]*" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed 's/HTTP_CODE:[0-9]*$//')

# Should return 401 (wrong password) or 400 (validation error)
if [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "400" ]; then
  echo -e "${GREEN}✓ PASS: Expected 401/400 for empty password, got ${HTTP_CODE}${NC}"
else
  echo -e "${RED}✗ FAIL: Expected 401/400, got ${HTTP_CODE}${NC}"
fi
echo "Response body: $BODY"
echo ""
echo "----------------------------------------"
echo ""

echo "=========================================="
echo "All tests completed"
echo "=========================================="
echo ""
echo -e "Test user created: ${YELLOW}${RANDOM_USER}${NC}"

