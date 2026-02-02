# OpenClaw Security Audit - PowerShell Test Suite
# Tests for claw-hunter.ps1

$ErrorActionPreference = "Stop"

# Counters
$script:TestsRun = 0
$script:TestsPassed = 0
$script:TestsFailed = 0

# Get script paths
$TestDir = Split-Path -Parent $PSCommandPath
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $TestDir)
$AuditScript = Join-Path -Path $ProjectRoot -ChildPath "claw-hunter.ps1"

Write-Host "==================================" -ForegroundColor Cyan
Write-Host "Claw-Hunter - PowerShell Test Suite" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host ""

# Helper functions
function Pass {
    param([string]$Message)
    Write-Host "✓ $Message" -ForegroundColor Green
    $script:TestsPassed++
    $script:TestsRun++
}

function Fail {
    param(
        [string]$Message,
        [string]$Expected,
        [string]$Got
    )
    Write-Host "✗ $Message" -ForegroundColor Red
    Write-Host "  Expected: $Expected" -ForegroundColor DarkRed
    Write-Host "  Got: $Got" -ForegroundColor DarkRed
    $script:TestsFailed++
    $script:TestsRun++
}

# Test 1: Script exists
function Test-ScriptExists {
    Write-Host "Test: Script exists"
    if (Test-Path $AuditScript) {
        Pass "Script exists"
    } else {
        Fail "Script exists" "file exists" "missing"
    }
}

# Test 2: Help flag works
function Test-HelpFlag {
    Write-Host "Test: --help flag displays usage"
    try {
        $output = & powershell -NoProfile -File $AuditScript --help 2>&1 | Out-String
        if ($output -match "Usage:") {
            Pass "Help flag works"
        } else {
            Fail "Help flag works" "usage message" "no output"
        }
    } catch {
        Fail "Help flag works" "usage message" "error: $_"
    }
}

# Test 3: Invalid flag returns error
function Test-InvalidFlag {
    Write-Host "Test: Invalid flag returns error"
    try {
        $output = & powershell -NoProfile -File $AuditScript --invalid-flag 2>&1 | Out-String
        if ($output -match "Unknown argument") {
            Pass "Invalid flag returns error"
        } else {
            Fail "Invalid flag returns error" "error message" "no error"
        }
    } catch {
        Pass "Invalid flag returns error (caught exception)"
    }
}

# Test 4: JSON output flag creates valid JSON
function Test-JsonOutput {
    Write-Host "Test: --json flag creates valid JSON"
    try {
        $output = & powershell -NoProfile -File $AuditScript --json 2>&1 | Out-String
        if ($output -match '"platform"') {
            try {
                $jsonPart = $output -split "JSON OUTPUT:" | Select-Object -Last 1
                $jsonPart = $jsonPart -split "==========" | Select-Object -Skip 1 -First 1
                $parsed = $jsonPart | ConvertFrom-Json
                Pass "JSON output is valid"
            } catch {
                Fail "JSON output is valid" "valid JSON" "parse error"
            }
        } else {
            Fail "JSON output is valid" "JSON with platform key" "no JSON output"
        }
    } catch {
        Fail "JSON output is valid" "valid JSON" "error: $_"
    }
}

# Test 5: JSON file output works
function Test-JsonFileOutput {
    Write-Host "Test: --json-path creates output file"
    $testFile = Join-Path -Path $env:TEMP -ChildPath "openclaw-test-$PID.json"
    
    try {
        & powershell -NoProfile -File $AuditScript --json-path $testFile 2>&1 | Out-Null
        
        if (Test-Path $testFile) {
            $content = Get-Content -Path $testFile -Raw
            if ($content -match '"platform"') {
                Pass "JSON file output works"
            } else {
                Fail "JSON file output works" "valid JSON file" "invalid content"
            }
            Remove-Item -Path $testFile -ErrorAction SilentlyContinue
        } else {
            Fail "JSON file output works" "JSON file created" "no file"
        }
    } catch {
        Fail "JSON file output works" "success" "error: $_"
    }
}

# Test 6: Exit code is proper
function Test-ExitCodes {
    Write-Host "Test: Script returns valid exit code"
    $testFile = Join-Path -Path $env:TEMP -ChildPath "test-exit-$PID.json"
    
    try {
        & powershell -NoProfile -File $AuditScript --json-path $testFile 2>&1 | Out-Null
        $exitCode = $LASTEXITCODE
        Remove-Item -Path $testFile -ErrorAction SilentlyContinue
        
        if ($exitCode -in @(0, 1, 2)) {
            Pass "Exit code is valid ($exitCode)"
        } else {
            Fail "Exit code is valid" "0, 1, or 2" "$exitCode"
        }
    } catch {
        Fail "Exit code is valid" "0, 1, or 2" "error: $_"
    }
}

# Test 7: MDM mode suppresses output
function Test-MdmModeSilent {
    Write-Host "Test: --mdm mode suppresses terminal output"
    $testFile = Join-Path -Path $env:TEMP -ChildPath "openclaw-mdm-test-$PID.json"
    
    try {
        $output = & powershell -NoProfile -File $AuditScript --mdm --json-path $testFile 2>&1 | Out-String
        Remove-Item -Path $testFile -ErrorAction SilentlyContinue
        
        $lineCount = ($output -split "`n").Count
        if ($lineCount -lt 5) {
            Pass "MDM mode is silent"
        } else {
            Fail "MDM mode is silent" "minimal output" "$lineCount lines"
        }
    } catch {
        Fail "MDM mode is silent" "minimal output" "error: $_"
    }
}

# Test 8: MDM mode includes metadata
function Test-MdmMetadata {
    Write-Host "Test: MDM mode includes machine metadata"
    $testFile = Join-Path -Path $env:TEMP -ChildPath "openclaw-mdm-meta-$PID.json"
    
    try {
        & powershell -NoProfile -File $AuditScript --mdm --json-path $testFile 2>&1 | Out-Null
        
        if (Test-Path $testFile) {
            $content = Get-Content -Path $testFile -Raw
            if ($content -match '"mdm_metadata"' -and $content -match '"hostname"') {
                Pass "MDM metadata present"
            } else {
                Fail "MDM metadata present" "mdm_metadata with hostname" "missing metadata"
            }
            Remove-Item -Path $testFile -ErrorAction SilentlyContinue
        } else {
            Fail "MDM metadata present" "JSON file with metadata" "no file"
        }
    } catch {
        Fail "MDM metadata present" "success" "error: $_"
    }
}

# Test 9: Security summary is calculated
function Test-SecuritySummary {
    Write-Host "Test: Security summary is calculated"
    try {
        $output = & powershell -NoProfile -File $AuditScript --json 2>&1 | Out-String
        if ($output -match '"security_summary"' -and $output -match '"risk_level"') {
            Pass "Security summary is calculated"
        } else {
            Fail "Security summary is calculated" "security_summary with risk_level" "missing summary"
        }
    } catch {
        Fail "Security summary is calculated" "success" "error: $_"
    }
}

# Test 10: PowerShell 5.1 compatibility
function Test-PowerShell51Compatibility {
    Write-Host "Test: PowerShell 5.1 compatibility"
    $content = Get-Content -Path $AuditScript -Raw
    
    # Check for PowerShell 7+ specific features
    if ($content -match '\?\?' -and $content -notmatch '# PowerShell 7') {
        Fail "PowerShell 5.1 compatibility" "no null coalescing operator" "found ??"
    } else {
        Pass "No PowerShell 7+ specific features detected"
    }
}

# Run all tests
Write-Host "Running tests..." -ForegroundColor Cyan
Write-Host ""

Test-ScriptExists
Test-HelpFlag
Test-InvalidFlag
Test-JsonOutput
Test-JsonFileOutput
Test-ExitCodes
Test-MdmModeSilent
Test-MdmMetadata
Test-SecuritySummary
Test-PowerShell51Compatibility

# Summary
Write-Host ""
Write-Host "==================================" -ForegroundColor Cyan
Write-Host "Test Results" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host "Tests run: $TestsRun"
Write-Host "Passed: $TestsPassed" -ForegroundColor Green
if ($TestsFailed -gt 0) {
    Write-Host "Failed: $TestsFailed" -ForegroundColor Red
}
Write-Host ""

if ($TestsFailed -eq 0) {
    Write-Host "All tests passed!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "Some tests failed" -ForegroundColor Red
    exit 1
}
