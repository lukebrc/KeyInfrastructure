#!/bin/bash

# Test script for /register endpoint
# Usage: ./test_register.sh [BASE_URL]
# Default BASE_URL: http://localhost:8080

BASE_URL="${1:-http://localhost:8080}"
REGISTER_URL="${BASE_URL}/register"

echo "=========================================="
echo "Testing /register endpoint"
echo "=========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test 1: Successful registration
echo -e "${YELLOW}Test 1: Successful registration${NC}"
echo "Request: POST ${REGISTER_URL}"
echo "Payload: {\"login\": \"testuser\", \"password\": \"testpass123\"}"
echo ""
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "${REGISTER_URL}" \
  -H "Content-Type: application/json" \
  -d '{"login": "testuser", "password": "testpass123"}')

HTTP_CODE=$(echo "$RESPONSE" | grep -o "HTTP_CODE:[0-9]*" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed 's/HTTP_CODE:[0-9]*$//')

if [ "$HTTP_CODE" = "201" ]; then
  echo -e "${GREEN}✓ PASS: Expected 201 Created, got ${HTTP_CODE}${NC}"
else
  echo -e "${RED}✗ FAIL: Expected 201 Created, got ${HTTP_CODE}${NC}"
fi
echo "Response body: $BODY"
echo ""
echo "----------------------------------------"
echo ""

# Test 2: Attempt to register existing user (should fail with 409 Conflict)
echo -e "${YELLOW}Test 2: Register existing user (should return 409 Conflict)${NC}"
echo "Request: POST ${REGISTER_URL}"
echo "Payload: {\"login\": \"testuser\", \"password\": \"testpass123\"}"
echo ""
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "${REGISTER_URL}" \
  -H "Content-Type: application/json" \
  -d '{"login": "testuser", "password": "testpass123"}')

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

# Test 3: Missing required fields (should fail with 400 Bad Request or 422)
echo -e "${YELLOW}Test 3: Missing password field${NC}"
echo "Request: POST ${REGISTER_URL}"
echo "Payload: {\"login\": \"testuser2\"}"
echo ""
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "${REGISTER_URL}" \
  -H "Content-Type: application/json" \
  -d '{"login": "testuser2"}')

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

# Test 4: Missing login field
echo -e "${YELLOW}Test 4: Missing login field${NC}"
echo "Request: POST ${REGISTER_URL}"
echo "Payload: {\"password\": \"testpass123\"}"
echo ""
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "${REGISTER_URL}" \
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

# Test 5: Invalid JSON
echo -e "${YELLOW}Test 5: Invalid JSON${NC}"
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

# Test 6: Empty fields
echo -e "${YELLOW}Test 6: Empty login field${NC}"
echo "Request: POST ${REGISTER_URL}"
echo "Payload: {\"login\": \"\", \"password\": \"testpass123\"}"
echo ""
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "${REGISTER_URL}" \
  -H "Content-Type: application/json" \
  -d '{"login": "", "password": "testpass123"}')

HTTP_CODE=$(echo "$RESPONSE" | grep -o "HTTP_CODE:[0-9]*" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed 's/HTTP_CODE:[0-9]*$//')

# This might succeed or fail depending on validation - both are acceptable
echo "Response code: ${HTTP_CODE}"
echo "Response body: $BODY"
echo ""
echo "----------------------------------------"
echo ""

echo "=========================================="
echo "Register tests completed"
echo "=========================================="

