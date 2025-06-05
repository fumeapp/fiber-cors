#!/bin/bash

# Set default host if not specified
HOST=${1:-"https://d245hvitoez60u.cloudfront.net"}
echo "Testing CORS middleware on $HOST"

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Function to check if a header exists in the response
check_header() {
  local response=$1
  local header=$2
  local expected_value=$3
  
  # Extract the header value more carefully
  actual_value=$(echo "$response" | grep -i "^$header:" | sed "s/^$header: //i" | tr -d '\r\n')
  
  if [ -z "$actual_value" ]; then
    echo -e "${RED}✗ $header is not present${NC}"
  elif [ "$actual_value" = "$expected_value" ]; then
    echo -e "${GREEN}✓ $header is set to '$expected_value'${NC}"
  else
    echo -e "${RED}✗ $header is '$actual_value', expected '$expected_value'${NC}"
  fi
}

# Function to check if a header does not exist in the response
check_header_not_exists() {
  local response=$1
  local header=$2
  
  if echo "$response" | grep -qi "^$header:"; then
    actual_value=$(echo "$response" | grep -i "^$header:" | sed "s/^$header: //i" | tr -d '\r\n')
    echo -e "${RED}✗ $header should not be present but is: '$actual_value'${NC}"
  else
    echo -e "${GREEN}✓ $header is not present as expected${NC}"
  fi
}

# Function to print a separator
print_separator() {
  echo -e "\n${YELLOW}----------------------------------------${NC}"
}

echo -e "\n${YELLOW}Test 1: Regular request with allowed origin${NC}"
response=$(curl -s -i -H "Origin: https://console.domain.com" $HOST)
echo "$response" | head -20
print_separator
check_header "$response" "Access-Control-Allow-Origin" "https://console.domain.com"
check_header "$response" "Access-Control-Allow-Credentials" "true"

echo -e "\n${YELLOW}Test 2: Request with disallowed origin${NC}"
response=$(curl -s -i -H "Origin: https://evil.com" $HOST)
echo "$response" | head -20
print_separator
check_header_not_exists "$response" "Access-Control-Allow-Origin"

echo -e "\n${YELLOW}Test 3: Preflight request with allowed origin${NC}"
response=$(curl -s -i -X OPTIONS -H "Origin: https://console.domain.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type" $HOST)
echo "$response" | head -20
print_separator
check_header "$response" "Access-Control-Allow-Origin" "https://console.domain.com"
check_header "$response" "Access-Control-Allow-Methods" "GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD"
check_header "$response" "Access-Control-Allow-Headers" "Origin, Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, User-Agent"
check_header "$response" "Access-Control-Allow-Credentials" "true"
echo -e "${YELLOW}⚠️ Note: Access-Control-Max-Age header might be stripped by CloudFront/API Gateway${NC}"
if echo "$response" | grep -qi "^Access-Control-Max-Age:"; then
  check_header "$response" "Access-Control-Max-Age" "86400"
else
  echo -e "${YELLOW}⚠️ Access-Control-Max-Age header not present (likely stripped by proxy)${NC}"
fi

echo -e "\n${YELLOW}Test 4: Preflight request with disallowed origin${NC}"
response=$(curl -s -i -X OPTIONS -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type" $HOST)
echo "$response" | head -20
print_separator
check_header_not_exists "$response" "Access-Control-Allow-Origin"

echo -e "\n${YELLOW}Test 5: Case-insensitive origin matching${NC}"
response=$(curl -s -i -H "Origin: https://CONSOLE.domain.com" $HOST)
echo "$response" | head -20
print_separator
check_header "$response" "Access-Control-Allow-Origin" "https://CONSOLE.domain.com"

echo -e "\n${YELLOW}Test 6: Header validation for preflight${NC}"
response=$(curl -s -i -X OPTIONS -H "Origin: https://console.domain.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type, Authorization, X-CSRF-Token, Host" $HOST)
echo "$response" | head -20
print_separator
check_header "$response" "Access-Control-Allow-Origin" "https://console.domain.com"
# Check if 'Host' is not in the allowed headers
allowed_headers=$(echo "$response" | grep -i "^Access-Control-Allow-Headers:" | sed "s/^Access-Control-Allow-Headers: //i" | tr -d '\r\n')
if echo "$allowed_headers" | grep -qi "host"; then
  echo -e "${RED}✗ Unsafe header 'Host' is included in Access-Control-Allow-Headers${NC}"
else
  echo -e "${GREEN}✓ Unsafe header 'Host' is not included in Access-Control-Allow-Headers${NC}"
fi

echo -e "\n${YELLOW}Test 7: Empty origin header${NC}"
response=$(curl -s -i $HOST)
echo "$response" | head -20
print_separator
check_header_not_exists "$response" "Access-Control-Allow-Origin"

echo -e "\n${YELLOW}Test 8: Simple OPTIONS request (not preflight)${NC}"
response=$(curl -s -i -X OPTIONS $HOST)
echo "$response" | head -20
print_separator
# Check status code
status_code=$(echo "$response" | grep -i "^HTTP" | awk '{print $2}')
if [ "$status_code" = "204" ]; then
  echo -e "${GREEN}✓ Status code is 204 as expected${NC}"
else
  echo -e "${RED}✗ Status code is $status_code, expected 204${NC}"
fi

echo -e "\n${YELLOW}Test 9: Request from localhost${NC}"
response=$(curl -s -i -H "Origin: http://localhost:3000" $HOST)
echo "$response" | head -20
print_separator
check_header "$response" "Access-Control-Allow-Origin" "http://localhost:3000"

echo -e "\n${YELLOW}Test 10: Request with custom headers${NC}"
response=$(curl -s -i -H "Origin: https://console.domain.com" \
  -H "X-Custom-Header: test" $HOST)
echo "$response" | head -20
print_separator
check_header "$response" "Access-Control-Allow-Origin" "https://console.domain.com"
check_header "$response" "Access-Control-Expose-Headers" "Origin, User-Agent"

echo -e "\n${GREEN}All tests completed!${NC}"