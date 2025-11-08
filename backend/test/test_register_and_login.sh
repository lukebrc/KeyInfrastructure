#!/bin/bash

# Test script for /register and /login endpoints
# Usage: ./test_register_and_login.sh [BASE_URL]
# Default BASE_URL: http://localhost:8080
#
# This script registers a new user with a random name and then tests login.

BASE_URL="${1:-http://localhost:8080}"
REGISTER_URL="${BASE_URL}/api/users"
LOGIN_URL="${BASE_URL}/api/login"

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
echo "Payload: {\"username\": \"${RANDOM_USER}\", \"password\": \"${TEST_PASSWORD}\", \"pin\": \"12345678\"}"
echo ""
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "${REGISTER_URL}" \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"${RANDOM_USER}\", \"password\": \"${TEST_PASSWORD}\", \"pin\": \"12345678\"}")

HTTP_CODE=$(echo "$RESPONSE" | grep -o "HTTP_CODE:[0-9]*" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed 's/HTTP_CODE:[0-9]*$//')

if [ "$HTTP_CODE" = "201" ]; then
  echo -e "${GREEN}✓ PASS: Expected 201 Created, got ${HTTP_CODE}${NC}"
  if echo "$BODY" | grep -q "User registered successfully"; then
    echo -e "${GREEN}✓ PASS: Response contains 'User registered successfully'${NC}"
  else
    echo -e "${RED}✗ FAIL: Response should contain 'User registered successfully'${NC}"
  fi
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
echo "Payload: {\"username\": \"${RANDOM_USER}\", \"password\": \"${TEST_PASSWORD}\", \"pin\": \"12345678\"}"
echo ""
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "${REGISTER_URL}" \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"${RANDOM_USER}\", \"password\": \"${TEST_PASSWORD}\", \"pin\": \"12345678\"}")

HTTP_CODE=$(echo "$RESPONSE" | grep -o "HTTP_CODE:[0-9]*" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed 's/HTTP_CODE:[0-9]*$//')

if [ "$HTTP_CODE" = "409" ]; then
  echo -e "${GREEN}✓ PASS: Expected 409 Conflict, got ${HTTP_CODE}${NC}"
  if echo "$BODY" | grep -q "Username already exists"; then
    echo -e "${GREEN}✓ PASS: Response contains 'Username already exists'${NC}"
  else
    echo -e "${RED}✗ FAIL: Response should contain 'Username already exists'${NC}"
  fi
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
echo "Payload: {\"username\": \"testuser_missing_pass\", \"pin\": \"12345678\"}"
echo ""
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "${REGISTER_URL}" \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser_missing_pass", "pin": "12345678"}')

HTTP_CODE=$(echo "$RESPONSE" | grep -o "HTTP_CODE:[0-9]*" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed 's/HTTP_CODE:[0-9]*$//')

if [ "$HTTP_CODE" = "400" ]; then
  echo -e "${GREEN}✓ PASS: Expected 400 Bad Request, got ${HTTP_CODE}${NC}"
else
  echo -e "${RED}✗ FAIL: Expected 400 Bad Request, got ${HTTP_CODE}${NC}"
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
  TOKEN=$(echo "$BODY" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
  if [ -n "$TOKEN" ]; then
    echo -e "${GREEN}✓ PASS: JWT token found in response.${NC}"
  else
    echo -e "${RED}✗ FAIL: JWT token not found in response.${NC}"
  fi
else
  echo -e "${RED}✗ FAIL: Expected 200 OK, got ${HTTP_CODE}${NC}"
fi
echo ""
echo "----------------------------------------"
echo ""

# Test 2: Wrong password (should fail with 401 Unauthorized)
echo -e "${YELLOW}Test 2: Wrong password (should return 401 Unauthorized)${NC}"
echo "Request: POST ${LOGIN_URL}"
echo "Payload: {\"username\": \"${RANDOM_USER}\", \"password\": \"wrongpass\"}"
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "${LOGIN_URL}" -H "Content-Type: application/json" -d "{\"username\": \"${RANDOM_USER}\", \"password\": \"wrongpass\"}")
echo ""
if [ "$HTTP_CODE" = "401" ]; then
  echo -e "${GREEN}✓ PASS: Expected 401 Unauthorized, got ${HTTP_CODE}${NC}"
  if echo "$BODY" | grep -q "Invalid credentials"; then
    echo -e "${GREEN}✓ PASS: Response contains 'Invalid credentials'${NC}"
  else
    echo -e "${RED}✗ FAIL: Response should contain 'Invalid credentials'${NC}"
    exit -1
  fi
else
  echo -e "${RED}✗ FAIL: Expected 401 Unauthorized, got ${HTTP_CODE}${NC}"
  exit -1
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
  if echo "$BODY" | grep -q "Invalid credentials"; then
    echo -e "${GREEN}✓ PASS: Response contains 'Invalid credentials'${NC}"
  else
    echo -e "${RED}✗ FAIL: Response should contain 'Invalid credentials'${NC}"
  fi
else
  echo -e "${RED}✗ FAIL: Expected 401 Unauthorized, got ${HTTP_CODE}${NC}"
fi
echo "Response body: $BODY"
echo ""
echo "----------------------------------------"
echo ""

# Test 4: Missing password field (should fail with 400 Bad Request or 422)
if [ "$HTTP_CODE" = "400" ]; then
  echo -e "${GREEN}✓ PASS: Expected 400 Bad Request, got ${HTTP_CODE}${NC}"
else
  echo -e "${RED}✗ FAIL: Expected 400 Bad Request, got ${HTTP_CODE}${NC}"
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

if [ "$HTTP_CODE" = "400" ]; then
  echo -e "${GREEN}✓ PASS: Expected 400 Bad Request, got ${HTTP_CODE}${NC}"
else
  echo -e "${RED}✗ FAIL: Expected 400 Bad Request, got ${HTTP_CODE}${NC}"
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

if [ -n "$TOKEN" ]; then
  # ============================================
  # PROTECTED ENDPOINT TEST
  # ============================================
  echo "=========================================="
  echo "PART 3: Protected Endpoint Test"
  echo "=========================================="
  echo ""

  echo -e "${YELLOW}Test 1: Access protected /api/certificates endpoint with JWT${NC}"
  CERT_URL="${BASE_URL}/api/certificates"
  RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X GET "${CERT_URL}" \
    -H "Authorization: Bearer ${TOKEN}")

  HTTP_CODE=$(echo "$RESPONSE" | grep -o "HTTP_CODE:[0-9]*" | cut -d: -f2)

  if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}✓ PASS: Expected 200 OK, got ${HTTP_CODE}${NC}"
  else
    echo -e "${RED}✗ FAIL: Expected 200 OK, got ${HTTP_CODE}${NC}"
  fi
  echo ""
  echo "----------------------------------------"
fi

echo "=========================================="
echo "All tests completed"
echo "=========================================="
echo ""
echo -e "Test user created: ${YELLOW}${RANDOM_USER}${NC}"
