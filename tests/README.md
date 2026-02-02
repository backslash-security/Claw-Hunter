# Claw-Hunter - Test Suite

This directory contains test suites for both the Bash and PowerShell versions of the Claw-Hunter tool.

## Overview

The test suites verify:
- ✅ Script execution and exit codes
- ✅ Command-line argument parsing
- ✅ JSON output generation and validity
- ✅ MDM mode functionality
- ✅ Cross-version compatibility (Bash 3.2, PowerShell 5.1)
- ✅ Security summary calculation
- ✅ Machine metadata collection

## Running Tests

### Bash Tests (macOS/Linux)

```bash
cd tests/bash
./run-tests.sh
```

**Requirements:**
- Bash 3.2 or higher
- Optional: `jq` for JSON validation

### PowerShell Tests (Windows)

```powershell
cd tests/powershell
.\run-tests.ps1
```

**Requirements:**
- PowerShell 5.1 or higher

## Test Coverage

### Bash Test Suite (`tests/bash/run-tests.sh`)

1. **Script Existence**: Verifies script file exists and is executable
2. **Help Flag**: Tests `--help` flag displays usage information
3. **Invalid Flags**: Ensures unknown flags return appropriate errors
4. **JSON Output**: Validates `--json` flag produces valid JSON
5. **JSON File Output**: Tests `--json-path` creates output file
6. **Exit Codes**: Verifies proper exit codes (0, 1, 2, 3)
7. **MDM Silent Mode**: Confirms `--mdm` suppresses terminal output
8. **MDM Metadata**: Validates machine identification data
9. **Security Summary**: Tests risk scoring calculation
10. **Bash 3.2 Compatibility**: Ensures no associative arrays used
11. **HTTP Upload**: Tests `--upload-url` flag, validates script uploads JSON to open endpoint (httpbin.org) and logs success

### PowerShell Test Suite (`tests/powershell/run-tests.ps1`)

1. **Script Existence**: Verifies script file exists
2. **Help Flag**: Tests `--help` flag displays usage information
3. **Invalid Flags**: Ensures unknown flags return appropriate errors
4. **JSON Output**: Validates `--json` flag produces valid JSON
5. **JSON File Output**: Tests `--json-path` creates output file
6. **Exit Codes**: Verifies proper exit codes (0, 1, 2, 3)
7. **MDM Silent Mode**: Confirms `--mdm` suppresses terminal output
8. **MDM Metadata**: Validates machine identification data
9. **Security Summary**: Tests risk scoring calculation
10. **PowerShell 5.1 Compatibility**: Checks for version-specific features
11. **HTTP Upload**: Tests `--upload-url` flag, validates script uploads JSON to open endpoint (httpbin.org) and logs success

## Continuous Integration

Tests run automatically on:
- Pull requests
- Pushes to main branch
- Release tags

See [../.github/workflows/](.github/workflows/) for CI configuration.

## Adding New Tests

### Bash Test Template

```bash
test_new_feature() {
    echo "Test: Description of test"
    if [[ condition ]]; then
        pass "Test description"
    else
        fail "Test description" "expected value" "actual value"
    fi
}
```

Add the function call to the "Run all tests" section.

### PowerShell Test Template

```powershell
function Test-NewFeature {
    Write-Host "Test: Description of test"
    if (condition) {
        Pass "Test description"
    } else {
        Fail "Test description" "expected value" "actual value"
    }
}
```

Add the function call to the "Run all tests" section.

## Test Output

### Success
```
==================================
OpenClaw Audit - Bash Test Suite
==================================

Running tests...

✓ Script exists and is executable
✓ Help flag works
✓ Invalid flag returns error
✓ JSON output is valid
✓ JSON file output works
✓ Exit code is valid (2)
✓ MDM mode is silent
✓ MDM metadata present
✓ Security summary is calculated
✓ No associative arrays used (Bash 3.2 compatible)
✓ HTTP upload successful (script uploaded via --upload-url, HTTP 200)

==================================
Test Results
==================================
Tests run: 11
Passed: 11

All tests passed!
```

### Failure
```
✗ JSON output is valid
  Expected: valid JSON
  Got: invalid JSON

==================================
Test Results
==================================
Tests run: 11
Passed: 10
Failed: 1

Some tests failed
```

## Manual Testing

For manual testing scenarios:

```bash
# Test normal execution
./claw-hunter.sh

# Test JSON output
./claw-hunter.sh --json > /tmp/test-output.json
jq . /tmp/test-output.json

# Test MDM mode
sudo ./claw-hunter.sh --mdm --json-path /tmp/mdm-test.json
cat /tmp/mdm-test.json

# Test exit codes
./claw-hunter.sh; echo "Exit code: $?"
```

## Troubleshooting

**Test fails with "command not found":**
- Ensure scripts are executable: `chmod +x *.sh`
- Verify you're in the correct directory

**JSON validation fails:**
- Install `jq`: `brew install jq` (macOS) or `apt install jq` (Linux)
- Tests will skip full JSON validation without `jq`

**PowerShell tests fail to run:**
- Check execution policy: `Get-ExecutionPolicy`
- If restricted: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`

## Contributing

When adding new features:
1. Add corresponding tests
2. Run full test suite before committing
3. Update this README if adding new test categories
4. Ensure tests work on minimum supported versions (Bash 3.2, PowerShell 5.1)
