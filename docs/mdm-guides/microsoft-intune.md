# Microsoft Intune Deployment Guide

This guide covers deploying Claw-Hunter via Microsoft Intune for Windows devices.

## Overview

Deploy the audit script to run automatically on Windows devices and report results back to your central monitoring system or Azure Log Analytics.

## Prerequisites

- Microsoft Intune subscription
- Windows 10/11 devices enrolled in Intune
- (Optional) Azure Log Analytics workspace
- (Optional) Central API endpoint for result collection
- PowerShell 5.1 or higher on target devices

## Deployment Methods

### Method 1: PowerShell Script Deployment (Recommended)

#### Step 1: Prepare the Script Package

1. Download `claw-hunter.ps1`
2. Create a wrapper script for Intune deployment:

`deploy-claw-hunter.ps1`:
```powershell
#Requires -Version 5.1
<#
.SYNOPSIS
    Intune deployment wrapper for Claw-Hunter
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

# Configuration - Update these
$UploadUrl = "https://your-api.com/audits"
$UseUpload = $false  # Set to $true if using upload

# Intune-specific paths
$InstallDir = "C:\Program Files\OpenClaw Audit"
$ScriptPath = Join-Path -Path $InstallDir -ChildPath "claw-hunter.ps1"
$OutputPath = "C:\ProgramData\claw-hunter.json"
$LogPath = "C:\ProgramData\claw-hunter.log"

# Ensure directory exists
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# Copy script to install location
$scriptContent = @'
# INSERT OPENCLAW-AUDIT.PS1 CONTENT HERE
'@

$scriptContent | Set-Content -Path $ScriptPath -Encoding UTF8

# Run audit
try {
    $arguments = @(
        '--mdm'
        '--json-path', $OutputPath
        '--log-file', $LogPath
    )
    
    if ($UseUpload) {
        $arguments += '--upload-url', $UploadUrl
    }
    
    & powershell.exe -ExecutionPolicy Bypass -File $ScriptPath @arguments
    
    $exitCode = $LASTEXITCODE
    Write-Output "Audit completed with exit code: $exitCode"
    
    # Upload to Azure Log Analytics (optional)
    if (Test-Path $OutputPath) {
        # Send-AzureLogAnalytics -JsonPath $OutputPath
    }
    
    exit $exitCode
    
} catch {
    Write-Error "Audit failed: $_"
    exit 3
}
```

#### Step 2: Deploy via Intune

1. Sign in to [Microsoft Endpoint Manager admin center](https://endpoint.microsoft.com)
2. Navigate to **Devices** → **Scripts** → **Add** → **Windows 10 and later**
3. Configure:
   - **Name**: `Claw-Hunter`
   - **Description**: `Weekly security audit for OpenClaw installations`
   - **Script location**: Upload `deploy-claw-hunter.ps1`
   - **Run this script using the logged on credentials**: No
   - **Enforce script signature check**: No (unless you sign scripts)
   - **Run script in 64 bit PowerShell Host**: Yes

4. **Assignments**:
   - Add groups: All devices or specific Azure AD groups
   
5. Click **Review + add**

#### Step 3: Schedule Execution

Scripts in Intune run:
- At device check-in (every 8 hours by default)
- Can be triggered manually via Intune portal

For more frequent execution, use Proactive Remediations or Scheduled Tasks.

### Method 2: Proactive Remediations

Proactive Remediations run on a schedule and provide better reporting.

#### Detection Script

`detect-openclaw-issues.ps1`:
```powershell
#Requires -Version 5.1
<#
.SYNOPSIS
    Detection script for OpenClaw security audit
.DESCRIPTION
    Returns non-compliant (exit 1) if critical issues found
#>

$OutputPath = "C:\ProgramData\claw-hunter.json"

# Check if audit has run recently
if (Test-Path $OutputPath) {
    try {
        $audit = Get-Content $OutputPath -Raw | ConvertFrom-Json
        
        # Check timestamp (should be within last 24 hours)
        $timestamp = [DateTime]::Parse($audit.mdm_metadata.timestamp)
        $age = (Get-Date).ToUniversalTime() - $timestamp
        
        if ($age.TotalHours -gt 24) {
            Write-Output "Audit data is stale ($($ age.TotalHours) hours old)"
            exit 1
        }
        
        # Check risk level
        if ($audit.security_summary.risk_level -eq "critical") {
            Write-Output "Critical security issues detected"
            exit 1  # Non-compliant
        }
        
        Write-Output "Audit clean, risk level: $($audit.security_summary.risk_level)"
        exit 0  # Compliant
        
    } catch {
        Write-Output "Failed to parse audit data: $_"
        exit 1
    }
} else {
    Write-Output "No audit data found"
    exit 1
}
```

#### Remediation Script

`remediate-claw-hunter.ps1`:
```powershell
#Requires -Version 5.1
<#
.SYNOPSIS
    Remediation script - runs the audit
#>

$ScriptPath = "C:\Program Files\OpenClaw Audit\claw-hunter.ps1"
$OutputPath = "C:\ProgramData\claw-hunter.json"
$LogPath = "C:\ProgramData\claw-hunter.log"

if (-not (Test-Path $ScriptPath)) {
    Write-Output "Audit script not installed"
    exit 1
}

try {
    & powershell.exe -ExecutionPolicy Bypass -File $ScriptPath `
        --mdm `
        --json-path $OutputPath `
        --log-file $LogPath
    
    Write-Output "Audit completed"
    exit 0
    
} catch {
    Write-Output "Audit failed: $_"
    exit 1
}
```

#### Deploy Proactive Remediation

1. Navigate to **Reports** → **Endpoint Analytics** → **Proactive remediations**
2. Click **Create script package**
3. Configure:
   - **Name**: `Claw-Hunter`
   - **Description**: `Daily audit for OpenClaw security`
   - **Detection script**: Upload `detect-openclaw-issues.ps1`
   - **Remediation script**: Upload `remediate-claw-hunter.ps1`
   - **Run this script using logged-on credentials**: No
   - **Enforce script signature check**: No
   - **Run script in 64-bit PowerShell**: Yes

4. **Schedule**:
   - Daily at specific time (e.g., 2 AM)
   
5. **Assignments**: Select target groups

### Method 3: Win32 App Deployment

For more control, package as a Win32 app.

#### Step 1: Create Package

```powershell
# Create package structure
mkdir C:\Temp\OpenClawAudit
mkdir C:\Temp\OpenClawAudit\Scripts

# Copy scripts
Copy-Item claw-hunter.ps1 C:\Temp\OpenClawAudit\Scripts\

# Create install script
@'
$InstallDir = "C:\Program Files\OpenClaw Audit"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force
}
Copy-Item -Path "Scripts\*" -Destination $InstallDir -Force

# Create scheduled task
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$InstallDir\claw-hunter.ps1`" --mdm"
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 2am
$principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

Register-ScheduledTask -TaskName "Claw-Hunter" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force
'@ | Set-Content C:\Temp\OpenClawAudit\install.ps1

# Create uninstall script
@'
Unregister-ScheduledTask -TaskName "Claw-Hunter" -Confirm:$false
Remove-Item -Path "C:\Program Files\OpenClaw Audit" -Recurse -Force
'@ | Set-Content C:\Temp\OpenClawAudit\uninstall.ps1

# Download IntuneWinAppUtil
# https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool

# Create .intunewin package
.\IntuneWinAppUtil.exe -c C:\Temp\OpenClawAudit -s install.ps1 -o C:\Temp\Output
```

#### Step 2: Deploy Win32 App

1. Navigate to **Apps** → **Windows** → **Add**
2. Select **Windows app (Win32)**
3. Upload `.intunewin` file
4. Configure:
   - **Name**: `Claw-Hunter`
   - **Install command**: `powershell.exe -ExecutionPolicy Bypass -File install.ps1`
   - **Uninstall command**: `powershell.exe -ExecutionPolicy Bypass -File uninstall.ps1`
   - **Install behavior**: System
   - **Detection rules**: File exists: `C:\Program Files\OpenClaw Audit\claw-hunter.ps1`

5. Assign to device groups

## Collecting Results

### Option 1: Azure Log Analytics

Upload audit results to Log Analytics for centralized monitoring.

#### Setup Custom Table

```powershell
# PowerShell module
Install-Module -Name Az.OperationalInsights

# Create custom table
$tableParams = @{
    ResourceGroupName = "YourResourceGroup"
    WorkspaceName = "YourWorkspace"
    TableName = "OpenClawAudit_CL"
    Schema = @{
        columns = @(
            @{ name = "TimeGenerated"; type = "datetime" }
            @{ name = "Computer"; type = "string" }
            @{ name = "RiskLevel"; type = "string" }
            @{ name = "CriticalIssues"; type = "int" }
            @{ name = "AuditData"; type = "dynamic" }
        )
    }
}
```

#### Send Data Function

Add to audit script:
```powershell
function Send-ToLogAnalytics {
    param(
        [string]$WorkspaceId,
        [string]$SharedKey,
        [string]$JsonData
    )
    
    $body = ([System.Text.Encoding]::UTF8.GetBytes($JsonData))
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    
    $xHeaders = "x-ms-date:" + $rfc1123date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
    
    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($SharedKey)
    
    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $WorkspaceId, $encodedHash
    
    $uri = "https://$WorkspaceId.ods.opinsights.azure.com$resource?api-version=2016-04-01"
    
    $headers = @{
        "Authorization" = $authorization
        "Log-Type" = "OpenClawAudit"
        "x-ms-date" = $rfc1123date
    }
    
    Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
}
```

### Option 2: Compliance Policies

Create custom compliance settings based on audit results.

#### Custom Compliance Script

`openclaw-compliance-check.ps1`:
```powershell
$OutputPath = "C:\ProgramData\claw-hunter.json"

if (Test-Path $OutputPath) {
    $audit = Get-Content $OutputPath -Raw | ConvertFrom-Json
    
    $compliance = @{
        RiskLevel = $audit.security_summary.risk_level
        CriticalIssues = $audit.security_summary.critical_issues
        OpenClawInstalled = $audit.cli_installed
        GatewaySecure = -not $audit.gateway_bind_to_all
    }
    
    return $compliance | ConvertTo-Json -Compress
}

return @{ Error = "No audit data" } | ConvertTo-Json -Compress
```

Deploy via **Devices** → **Compliance policies** → **Scripts**.

### Option 3: Device Reporting

Query devices directly:

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Device.Read.All", "DeviceManagementManagedDevices.Read.All"

# Get devices
$devices = Get-MgDeviceManagementManagedDevice -Filter "operatingSystem eq 'Windows'"

# Collect audit data (requires remote execution capability)
foreach ($device in $devices) {
    # Retrieve audit results via remote PowerShell or script output
}
```

## Monitoring and Alerts

### Azure Monitor Alerts

Create alerts based on audit results:

1. Navigate to Azure Portal → Monitor → Alerts
2. Create alert rule:
   - Resource: Log Analytics workspace
   - Condition: Custom log search
   - Query:
     ```kusto
     OpenClawAudit_CL
     | where RiskLevel_s == "critical"
     | summarize count() by Computer_s
     ```
   - Threshold: Greater than 0
   - Action: Email/Teams/ServiceNow

### Power BI Dashboard

Create a Power BI dashboard for executive reporting:

1. Connect Power BI to Log Analytics
2. Create visualizations:
   - Risk level distribution
   - Trend over time
   - Critical issues by device
   - Compliance rate

## Troubleshooting

### Script Not Executing

**Check Intune Sync:**
```powershell
# On device
Get-ScheduledTask | Where-Object {$_.TaskName -like "*Intune*"}
Start-ScheduledTask -TaskName "Microsoft\Windows\EnterpriseMgmt\*\Schedule*"
```

**Check Script Logs:**
```powershell
# Intune Management Extension logs
Get-Content "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension.log" -Tail 100
```

### No Results Generated

**Run Manually:**
```powershell
& "C:\Program Files\OpenClaw Audit\claw-hunter.ps1" --mdm --json-path C:\Temp\test-audit.json
Get-Content C:\Temp\test-audit.json
```

**Check Permissions:**
```powershell
# Script should run as SYSTEM
whoami  # When run in SYSTEM context
```

### Upload Failures

**Test Connectivity:**
```powershell
Test-NetConnection -ComputerName your-api.com -Port 443
Invoke-WebRequest -Uri https://your-api.com/audits -Method POST -UseBasicParsing
```

## Best Practices

1. **Test in Pilot Group**: Deploy to test devices first
2. **Monitor Performance**: Track script execution time
3. **Use System Context**: Run as SYSTEM for full access
4. **Secure API Keys**: Store in Azure Key Vault
5. **Version Control**: Tag scripts with version numbers
6. **Log Rotation**: Implement log cleanup policy
7. **Compliance Integration**: Link to device compliance

## Security Considerations

- Use Azure Key Vault for API keys
- Limit script execution to managed devices only
- Review audit logs in Azure AD
- Implement conditional access based on compliance
- Use managed identities where possible

## Support

For Intune-specific issues:
- Microsoft Learn: https://learn.microsoft.com/intune
- Microsoft Support: Via Azure portal

For script issues:
- GitHub Issues: https://github.com/backslash-security/claw-hunter/issues
