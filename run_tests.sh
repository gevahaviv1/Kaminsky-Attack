#!/bin/bash

# Test runner script for DNS implementation

set -e

COLOR_GREEN='\033[0;32m'
COLOR_RED='\033[0;31m'
COLOR_YELLOW='\033[1;33m'
COLOR_BLUE='\033[0;34m'
COLOR_RESET='\033[0m'

echo -e "${COLOR_BLUE}========================================${COLOR_RESET}"
echo -e "${COLOR_BLUE}   DNS Test Runner${COLOR_RESET}"
echo -e "${COLOR_BLUE}========================================${COLOR_RESET}"
echo ""

# Check if we should run network tests
NETWORK_TESTS=0
if [ "$1" == "--network" ] || [ "$1" == "-n" ]; then
    NETWORK_TESTS=1
fi

# Build everything
echo -e "${COLOR_YELLOW}Building test suite...${COLOR_RESET}"
make clean > /dev/null 2>&1
if make all; then
    echo -e "${COLOR_GREEN}✓ Build successful${COLOR_RESET}"
else
    echo -e "${COLOR_RED}✗ Build failed${COLOR_RESET}"
    exit 1
fi
echo ""

# Run unit tests
echo -e "${COLOR_YELLOW}Running unit tests...${COLOR_RESET}"
if ./test_dns; then
    echo -e "${COLOR_GREEN}✓ Unit tests passed${COLOR_RESET}"
    UNIT_RESULT=0
else
    echo -e "${COLOR_RED}✗ Unit tests failed${COLOR_RESET}"
    UNIT_RESULT=1
fi
echo ""

# Run network tests if requested
if [ $NETWORK_TESTS -eq 1 ]; then
    echo -e "${COLOR_YELLOW}Running network tests...${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}NOTE: Server must be running on 192.168.1.201${COLOR_RESET}"
    echo ""
    
    if ./test_dns --network; then
        echo -e "${COLOR_GREEN}✓ Network tests passed${COLOR_RESET}"
        NETWORK_RESULT=0
    else
        echo -e "${COLOR_RED}✗ Network tests failed${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}Make sure the server is running: sudo ./ex2_server${COLOR_RESET}"
        NETWORK_RESULT=1
    fi
    echo ""
fi

# Summary
echo -e "${COLOR_BLUE}========================================${COLOR_RESET}"
echo -e "${COLOR_BLUE}   Test Summary${COLOR_RESET}"
echo -e "${COLOR_BLUE}========================================${COLOR_RESET}"

if [ $UNIT_RESULT -eq 0 ]; then
    echo -e "Unit Tests:    ${COLOR_GREEN}PASSED${COLOR_RESET}"
else
    echo -e "Unit Tests:    ${COLOR_RED}FAILED${COLOR_RESET}"
fi

if [ $NETWORK_TESTS -eq 1 ]; then
    if [ $NETWORK_RESULT -eq 0 ]; then
        echo -e "Network Tests: ${COLOR_GREEN}PASSED${COLOR_RESET}"
    else
        echo -e "Network Tests: ${COLOR_RED}FAILED${COLOR_RESET}"
    fi
fi

echo ""

# Exit with error if any tests failed
if [ $UNIT_RESULT -ne 0 ] || [ $NETWORK_RESULT -ne 0 ]; then
    exit 1
fi

exit 0
