#!/usr/bin/env bash
# OpenClaw Security Audit - Bash Test Suite
# Tests for claw-hunter.sh

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
AUDIT_SCRIPT="$PROJECT_ROOT/claw-hunter.sh"

echo "=================================="
echo "Claw-Hunter - Bash Test Suite"
echo "=================================="
echo ""

# Helper functions
pass() {
    echo -e "${GREEN}✓${NC} $1"
    ((TESTS_PASSED++))
    ((TESTS_RUN++))
}

fail() {
    echo -e "${RED}✗${NC} $1"
    echo "  Expected: $2"
    echo "  Got: $3"
    ((TESTS_FAILED++))
    ((TESTS_RUN++))
}

skip() {
    echo -e "${YELLOW}⊘${NC} $1 (skipped)"
}

# Test 1: Script exists and is executable
test_script_exists() {
    echo "Test: Script exists and is executable"
    if [[ -f "$AUDIT_SCRIPT" && -x "$AUDIT_SCRIPT" ]]; then
        pass "Script exists and is executable"
    else
        fail "Script exists and is executable" "executable file" "missing or not executable"
    fi
}

# Test 2: Help flag works
test_help_flag() {
    echo "Test: --help flag displays usage"
    if bash "$AUDIT_SCRIPT" --help 2>/dev/null | grep -q "Usage:"; then
        pass "Help flag works"
    else
        fail "Help flag works" "usage message" "no output"
    fi
}

# Test 3: Invalid flag returns error
test_invalid_flag() {
    echo "Test: Invalid flag returns error"
    if ! bash "$AUDIT_SCRIPT" --invalid-flag 2>&1 | grep -q "Unknown argument"; then
        fail "Invalid flag returns error" "error message" "no error"
    else
        pass "Invalid flag returns error"
    fi
}

# Test 4: JSON output flag creates valid JSON
test_json_output() {
    echo "Test: --json flag creates valid JSON"
    local output
    output=$(bash "$AUDIT_SCRIPT" --json 2>/dev/null | tail -n +4)
    
    if echo "$output" | grep -q '"platform"'; then
        if command -v jq &>/dev/null; then
            if echo "$output" | jq . >/dev/null 2>&1; then
                pass "JSON output is valid"
            else
                fail "JSON output is valid" "valid JSON" "invalid JSON"
            fi
        else
            pass "JSON output contains expected keys (jq not available for full validation)"
        fi
    else
        fail "JSON output is valid" "JSON with platform key" "no JSON output"
    fi
}

# Test 5: JSON file output works
test_json_file_output() {
    echo "Test: --json-path creates output file"
    local test_file="/tmp/openclaw-test-$$.json"
    
    bash "$AUDIT_SCRIPT" --json-path "$test_file" >/dev/null 2>&1
    
    if [[ -f "$test_file" ]]; then
        if grep -q '"platform"' "$test_file"; then
            pass "JSON file output works"
        else
            fail "JSON file output works" "valid JSON file" "invalid content"
        fi
        rm -f "$test_file"
    else
        fail "JSON file output works" "JSON file created" "no file"
    fi
}

# Test 6: Exit code is proper (0, 1, or 2)
test_exit_codes() {
    echo "Test: Script returns valid exit code"
    bash "$AUDIT_SCRIPT" --json-path /tmp/test-exit-$$.json >/dev/null 2>&1
    local exit_code=$?
    rm -f /tmp/test-exit-$$.json
    
    if [[ $exit_code -eq 0 || $exit_code -eq 1 || $exit_code -eq 2 ]]; then
        pass "Exit code is valid ($exit_code)"
    else
        fail "Exit code is valid" "0, 1, or 2" "$exit_code"
    fi
}

# Test 7: MDM mode suppresses output
test_mdm_mode_silent() {
    echo "Test: --mdm mode suppresses terminal output"
    local output
    local test_file="/tmp/openclaw-mdm-test-$$.json"
    output=$(bash "$AUDIT_SCRIPT" --mdm --json-path "$test_file" 2>&1 | wc -l)
    rm -f "$test_file"
    
    if [[ $output -lt 3 ]]; then
        pass "MDM mode is silent"
    else
        fail "MDM mode is silent" "minimal output" "$output lines"
    fi
}

# Test 8: MDM mode includes metadata
test_mdm_metadata() {
    echo "Test: MDM mode includes machine metadata"
    local test_file="/tmp/openclaw-mdm-meta-$$.json"
    bash "$AUDIT_SCRIPT" --mdm --json-path "$test_file" >/dev/null 2>&1
    
    if [[ -f "$test_file" ]]; then
        if grep -q '"mdm_metadata"' "$test_file" && grep -q '"hostname"' "$test_file"; then
            pass "MDM metadata present"
        else
            fail "MDM metadata present" "mdm_metadata with hostname" "missing metadata"
        fi
        rm -f "$test_file"
    else
        fail "MDM metadata present" "JSON file with metadata" "no file"
    fi
}

# Test 9: Security summary is calculated
test_security_summary() {
    echo "Test: Security summary is calculated"
    local output
    output=$(bash "$AUDIT_SCRIPT" --json 2>/dev/null)
    
    if echo "$output" | grep -q '"security_summary"' && echo "$output" | grep -q '"risk_level"'; then
        pass "Security summary is calculated"
    else
        fail "Security summary is calculated" "security_summary with risk_level" "missing summary"
    fi
}

# Test 10: Script works with bash 3.2 (macOS compatibility)
test_bash_32_compatibility() {
    echo "Test: Bash 3.2 compatibility (no associative arrays)"
    if grep -q "declare -A" "$AUDIT_SCRIPT"; then
        fail "Bash 3.2 compatibility" "no associative arrays" "found declare -A"
    else
        pass "No associative arrays used (Bash 3.2 compatible)"
    fi
}

# Run all tests
echo "Running tests..."
echo ""

test_script_exists
test_help_flag
test_invalid_flag
test_json_output
test_json_file_output
test_exit_codes
test_mdm_mode_silent
test_mdm_metadata
test_security_summary
test_bash_32_compatibility

# Summary
echo ""
echo "=================================="
echo "Test Results"
echo "=================================="
echo "Tests run: $TESTS_RUN"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
if [[ $TESTS_FAILED -gt 0 ]]; then
    echo -e "${RED}Failed: $TESTS_FAILED${NC}"
fi
echo ""

if [[ $TESTS_FAILED -eq 0 ]]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed${NC}"
    exit 1
fi
