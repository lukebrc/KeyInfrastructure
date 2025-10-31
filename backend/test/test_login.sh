#!/bin/bash

# Test script for /login endpoint
# Usage: ./test_login.sh [BASE_URL]
# Default BASE_URL: http://localhost:8080
#
# Note: This script assumes a user "testuser" exists with password "testpass123"
# Run test_register.sh first to create the test user.

BASE_URL="${1:-http://localhost:8080}"
LOGIN_URL="${BASE_URL}/login"

echo "=========================================="
echo "Testing /login endpoint"
echo "=========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test 1: Successful login
echo -e "${YELLOW}Test 1: Successful login${NC}"
echo "Request: POST ${LOGIN_URL}"
echo "Payload: {\"username\": \"testuser\", \"password\": \"testpass123\"}"
echo ""
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "${LOGIN_URL}" \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "testpass123"}')

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
echo "Payload: {\"username\": \"testuser\", \"password\": \"wrongpass\"}"
echo ""
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "${LOGIN_URL}" \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "wrongpass"}')

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
echo "Payload: {\"username\": \"nonexistent\", \"password\": \"testpass123\"}"
echo ""
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "${LOGIN_URL}" \
  -H "Content-Type: application/json" \
  -d '{"username": "nonexistent", "password": "testpass123"}')

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
echo "Payload: {\"username\": \"testuser\"}"
echo ""
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "${LOGIN_URL}" \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser"}')

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
echo "Payload: {\"password\": \"testpass123\"}"
echo ""
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "${LOGIN_URL}" \
  -H "Content-Type: application/json" \
  -d '{"password": "testpass123"}')

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
echo "Payload: {\"username\": \"\", \"password\": \"testpass123\"}"
echo ""
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "${LOGIN_URL}" \
  -H "Content-Type: application/json" \
  -d '{"username": "", "password": "testpass123"}')

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
echo "Payload: {\"username\": \"testuser\", \"password\": \"\"}"
echo ""
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "${LOGIN_URL}" \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": ""}')

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
echo "Login tests completed"
echo "=========================================="

