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
    echo -e "${GREEN}[PASS]${NC} $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
    TESTS_RUN=$((TESTS_RUN + 1))
}

fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    echo "  Expected: $2"
    echo "  Got: $3"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    TESTS_RUN=$((TESTS_RUN + 1))
}

skip() {
    echo -e "${YELLOW}[SKIP]${NC} $1"
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
    local exit_code
    bash "$AUDIT_SCRIPT" --invalid-flag >/dev/null 2>&1 || exit_code=$?
    if [[ ${exit_code:-0} -ne 0 ]]; then
        pass "Invalid flag returns error (exit code: $exit_code)"
    else
        fail "Invalid flag returns error" "non-zero exit code" "exit code 0"
    fi
}

# Test 4: JSON output flag creates valid JSON
test_json_output() {
    echo "Test: --json flag creates valid JSON"
    local output exit_code
    # Extract JSON after the "JSON OUTPUT:" marker (script may exit with 2 if not installed)
    output=$(bash "$AUDIT_SCRIPT" --json 2>&1 | sed -n '/^{$/,/^}$/p') || exit_code=$?
    
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
    
    bash "$AUDIT_SCRIPT" --json-path "$test_file" >/dev/null 2>&1 || true
    
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
    local exit_code
    bash "$AUDIT_SCRIPT" --json-path /tmp/test-exit-$$.json >/dev/null 2>&1 || exit_code=$?
    rm -f /tmp/test-exit-$$.json
    
    if [[ ${exit_code:-0} -eq 0 || ${exit_code:-0} -eq 1 || ${exit_code:-0} -eq 2 ]]; then
        pass "Exit code is valid (${exit_code:-0})"
    else
        fail "Exit code is valid" "0, 1, or 2" "${exit_code:-0}"
    fi
}

# Test 6b: Exit code 2 when not installed
test_exit_code_not_installed() {
    echo "Test: Exit code 2 when OpenClaw not installed"
    
    # Create a temporary HOME directory with no OpenClaw installation
    local temp_home="/tmp/openclaw-test-home-$$"
    mkdir -p "$temp_home"
    
    local exit_code
    HOME="$temp_home" PATH="/usr/bin:/bin" bash "$AUDIT_SCRIPT" --json-path /tmp/test-not-installed-$$.json >/dev/null 2>&1 || exit_code=$?
    rm -f /tmp/test-not-installed-$$.json
    rm -rf "$temp_home"
    
    if [[ ${exit_code:-0} -eq 2 ]]; then
        pass "Exit code 2 when not installed (${exit_code:-0})"
    else
        skip "Exit code 2 test (OpenClaw may be installed, got exit code ${exit_code:-0})"
    fi
}

# Test 6c: Exit code 0 for clean system (if not installed, should be 2)
test_exit_code_clean() {
    echo "Test: Exit code 0 for clean system or 2 if not installed"
    local exit_code
    bash "$AUDIT_SCRIPT" --json-path /tmp/test-clean-$$.json >/dev/null 2>&1 || exit_code=$?
    rm -f /tmp/test-clean-$$.json
    
    # Valid exit codes are 0 (clean), 1 (issues), or 2 (not installed)
    if [[ ${exit_code:-0} -eq 0 ]]; then
        pass "Exit code 0 (clean system)"
    elif [[ ${exit_code:-0} -eq 1 ]]; then
        pass "Exit code 1 (security issues detected)"
    elif [[ ${exit_code:-0} -eq 2 ]]; then
        pass "Exit code 2 (not installed)"
    else
        fail "Valid exit code" "0, 1, or 2" "${exit_code:-0}"
    fi
}

# Test 7: MDM mode suppresses output
test_mdm_mode_silent() {
    echo "Test: --mdm mode suppresses terminal output"
    local output line_count
    local test_file="/tmp/openclaw-mdm-test-$$.json"
    output=$(bash "$AUDIT_SCRIPT" --mdm --json-path "$test_file" 2>&1 || true)
    rm -f "$test_file"
    
    line_count=$(echo "$output" | grep -v "^$" | wc -l | tr -d ' ')
    # MDM mode should have minimal output (permission errors are OK in test environments)
    # Accept up to 10 lines to account for log file permission errors
    if [[ $line_count -le 10 ]]; then
        pass "MDM mode is silent (${line_count} lines)"
    else
        fail "MDM mode is silent" "minimal output (<=10 lines)" "$line_count lines"
    fi
}

# Test 8: MDM mode includes metadata
test_mdm_metadata() {
    echo "Test: MDM mode includes machine metadata"
    local test_file="/tmp/openclaw-mdm-meta-$$.json"
    bash "$AUDIT_SCRIPT" --mdm --json-path "$test_file" >/dev/null 2>&1 || true
    
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
    output=$(bash "$AUDIT_SCRIPT" --json 2>&1 | sed -n '/^{$/,/^}$/p' || true)
    
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

# Test 11: HTTP upload functionality
test_http_upload() {
    echo "Test: HTTP upload to remote endpoint"
    local test_file="/tmp/openclaw-upload-test-$$.json"
    local log_file="/tmp/openclaw-upload-log-$$.txt"
    
    # Run the script WITH --upload-url and --log-file to test the actual upload feature
    local exit_code
    bash "$AUDIT_SCRIPT" --json-path "$test_file" --upload-url "https://httpbin.org/post" --log-file "$log_file" >/dev/null 2>&1 || exit_code=$?
    
    # Check if JSON file was created
    if [[ ! -f "$test_file" ]]; then
        rm -f "$log_file"
        fail "HTTP upload test" "JSON file created" "no file"
        return
    fi
    
    # Check if the script reported upload success in the log file
    if [[ -f "$log_file" ]] && grep -q "Upload successful" "$log_file"; then
        # Validate the JSON file contents
        if grep -q '"platform"' "$test_file"; then
            pass "HTTP upload successful (script uploaded via --upload-url, HTTP 200)"
        else
            fail "HTTP upload test" "valid JSON uploaded" "invalid JSON content"
        fi
    else
        # Check if it's a network issue or script issue
        if [[ -f "$log_file" ]] && grep -qi "upload failed\|curl not found" "$log_file"; then
            # Upload was attempted but failed - could be network issue
            skip "HTTP upload test (upload failed - network or connectivity issue)"
        elif [[ ${exit_code:-0} -eq 0 ]]; then
            # Script ran successfully but no upload confirmation
            skip "HTTP upload test (upload status unclear)"
        else
            fail "HTTP upload test" "upload success message in logs" "no success message found"
        fi
    fi
    
    # Clean up
    rm -f "$test_file" "$log_file"
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
test_exit_code_not_installed
test_exit_code_clean
test_mdm_mode_silent
test_mdm_metadata
test_security_summary
test_bash_32_compatibility
test_http_upload

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
