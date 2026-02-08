# Claw-Hunter - By Backslash Security
# https://backslash.security
#
# A comprehensive security audit tool for OpenClaw installations
# Supports: Windows (PowerShell 5.1+)
#
# Copyright (c) 2024 Backslash Security
#
# Usage:
#   .\claw-hunter.ps1 [--json] [--json-path <file>] [--mdm] [--upload-url <url>]
#
# Notes:
# - Use --json to print JSON to terminal or --json-path to save to a file.
# - Use --mdm for silent MDM execution with JSON output to standard location.
# Notes:
# - Use --json to print JSON to terminal or --json-path to save to a file.
# - Use --mdm for silent MDM execution with JSON output to standard location.

# We intentionally do our own argument parsing so Windows users can use the same
# flags as the .sh script: --json-path/--json/--mdm.

$JsonToStdout = $false
$JsonPath = ""
$JsonPathSet = $false
$MdmMode = $false
$UploadUrl = ""
$LogFile = ""
$Help = $false

function Show-Usage {
    @"
Claw-Hunter - Windows

Usage:
  .\discover.ps1 [--json] [--json-path <file>] [--mdm] [--upload-url <url>]

Options:
  --json                   Print JSON output to terminal (stdout)
  --json-path <file>       Save JSON results to this file path
  --mdm                    MDM mode: silent execution, JSON to standard location, proper exit codes
  --upload-url <url>       Upload JSON results to this URL (requires --mdm or --json-path)
  --log-file <file>        Write logs to this file (default: C:\ProgramData\claw-hunter.log in MDM mode)
  -h, --help               Show help

MDM Mode:
  - Suppresses terminal output (errors go to stderr and log file)
  - Writes JSON to C:\ProgramData\claw-hunter.json
  - Includes machine identification and security summary
  - Exit codes: 0=clean, 1=issues found, 2=not installed, 3=error

Notes:
  - Without --json or --json-path flags, only the formatted terminal output is shown.
"@ | Write-Host
}

# Parse args (supports --opt value, --opt=value, and PowerShell-style -Opt/-Opt=value)
for ($i = 0; $i -lt $args.Count; $i++) {
    $a = [string]$args[$i]

    if ($a -match '^(--help|-h|/h|-\?|/\?)$') {
        $Help = $true
        continue
    }

    if ($a -match '^(--json-path=|-json-path=|-JsonPath=)(.+)$') {
        $JsonPath = $Matches[2]
        $JsonPathSet = $true
        continue
    }

    if ($a -match '^(--json-path|-json-path|-JsonPath)$') {
        if (($i + 1) -ge $args.Count) { throw "Missing value for $a" }
        $JsonPath = [string]$args[$i + 1]
        $JsonPathSet = $true
        $i++
        continue
    }

    if ($a -match '^(--json|-json)$') {
        $JsonToStdout = $true
        continue
    }

    if ($a -match '^(--mdm|-mdm)$') {
        $MdmMode = $true
        continue
    }

    if ($a -match '^(--upload-url=|-upload-url=)(.+)$') {
        $UploadUrl = $Matches[2]
        continue
    }

    if ($a -match '^(--upload-url|-upload-url)$') {
        if (($i + 1) -ge $args.Count) { throw "Missing value for $a" }
        $UploadUrl = [string]$args[$i + 1]
        $i++
        continue
    }

    if ($a -match '^(--log-file=|-log-file=)(.+)$') {
        $LogFile = $Matches[2]
        continue
    }

    if ($a -match '^(--log-file|-log-file)$') {
        if (($i + 1) -ge $args.Count) { throw "Missing value for $a" }
        $LogFile = [string]$args[$i + 1]
        $i++
        continue
    }

    throw "Unknown argument: $a"
}

# MDM mode setup
if ($MdmMode) {
    if ([string]::IsNullOrWhiteSpace($LogFile)) {
        $LogFile = "C:\ProgramData\claw-hunter.log"
    }
    
    if (-not $JsonPathSet) {
        $JsonPath = "C:\ProgramData\claw-hunter.json"
        $JsonPathSet = $true
    }
}

if ($Help) {
    Show-Usage
    exit 0
}

function Get-AbsolutePath {
    param([string]$PathValue)
    if ([string]::IsNullOrWhiteSpace($PathValue)) {
        return ""
    }
    try {
        if ([System.IO.Path]::IsPathRooted($PathValue)) {
            $rp = Resolve-Path -Path $PathValue -ErrorAction SilentlyContinue
            if ($rp) { return $rp.Path }
            return $PathValue
        }
        return (Join-Path -Path (Get-Location).Path -ChildPath $PathValue)
    } catch {
        return $PathValue
    }
}

function Write-Banner {
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "[SECURITY]  CLAW-HUNTER: WINDOWS" -ForegroundColor Cyan
    Write-Host "    By Backslash Security" -ForegroundColor Gray
    Write-Host "    https://backslash.security" -ForegroundColor Gray
    Write-Host "==========================================" -ForegroundColor Cyan
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "--- [ $Title ] ---" -ForegroundColor Yellow
}

function Write-Line {
    param(
        [string]$Text,
        [string]$Color = "White"
    )
    Write-Host $Text -ForegroundColor $Color
}

# Determine output path (default: results.json in current directory)
if ($JsonPathSet -and -not [System.IO.Path]::IsPathRooted($JsonPath)) {
    $JsonPath = Get-AbsolutePath -PathValue $JsonPath
}

# Logging function
function Write-Log {
    param(
        [string]$Level,
        [string]$Message
    )
    
    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    
    if (-not [string]::IsNullOrWhiteSpace($LogFile)) {
        try {
            "[$timestamp] [$Level] $Message" | Out-File -FilePath $LogFile -Append -ErrorAction SilentlyContinue
        } catch { }
    }
    
    # In MDM mode, only output errors to stderr
    if ($MdmMode -and $Level -eq "ERROR") {
        Write-Error "[$Level] $Message"
    }
}

# Get machine identification
function Get-Hostname {
    try {
        return $env:COMPUTERNAME
    } catch {
        return "unknown"
    }
}

function Get-SerialNumber {
    try {
        $serial = (Get-WmiObject -Class Win32_BIOS -ErrorAction SilentlyContinue).SerialNumber
        if ([string]::IsNullOrWhiteSpace($serial)) {
            $serial = (Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue).SerialNumber
        }
        return $serial
    } catch {
        return ""
    }
}

function Get-Timestamp {
    return (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

# Results object
$results = [ordered]@{
    platform = "windows"
    os = "windows"
    cli_installed = $false
    cli_path = ""
    cli_version = ""
    cli_install_method = ""
    config_exists = $false
    config_path = ""
    state_dir = ""
    workspace_exists = $false
    workspace_path = ""
    gateway_running = $false
    gateway_pid = ""
    gateway_process_cmd = ""
    gateway_port = ""
    gateway_token_set = $false
    gateway_bind_mode = ""
    gateway_listening_on = ""
    gateway_bind_to_all = $false
    scheduled_task_exists = $false
    scheduled_task_name = ""
    scheduled_task_status = ""
    agents_configured = 0
    agents_list = ""
    default_agent_id = ""
    integrations_enabled = @()
    integrations_count = 0
    registry_integrations = @()
    registry_integrations_count = 0
    credentials_dir = ""
    credential_files_count = 0
    risk_shell_access_enabled = $false
    risk_filesystem_write_enabled = $false
    secrets_found = $false
    secrets_count = 0
    secrets_files = @()
    plugins = @{
        global_count = 0
        workspace_count = 0
        total_count = 0
        list = @()
    }
    skills = @{
        global_count = 0
        workspace_count = 0
        total_count = 0
        list = @()
    }
    json_output_path = $JsonPath
}


# Detect state directory (v1 compatibility: .clawdbot fallback)
$stateDir = Join-Path -Path $HOME -ChildPath ".openclaw"
if (-not (Test-Path $stateDir)) {
    $fallback = Join-Path -Path $HOME -ChildPath ".clawdbot"
    if (Test-Path $fallback) { $stateDir = $fallback }
}
if ($env:OPENCLAW_STATE_DIR) { $stateDir = $env:OPENCLAW_STATE_DIR }
$results.state_dir = $stateDir

# Config path override
$configPath = if ($env:OPENCLAW_CONFIG_PATH) {
    $env:OPENCLAW_CONFIG_PATH
} else {
    Join-Path -Path $stateDir -ChildPath "openclaw.json"
}
$results.config_path = $configPath
if (Test-Path $configPath) {
    $results.config_exists = $true
}


# Detect CLI installation (v2)
$cliSearchPaths = @(
    "$env:APPDATA\npm",
    "$env:LOCALAPPDATA\pnpm",
    "$env:USERPROFILE\.local\bin",
    "$env:USERPROFILE\.bun\bin",
    "$env:USERPROFILE\.openclaw\bin",
    "$env:ProgramFiles\nodejs",
    "C:\Program Files\nodejs"
)

foreach ($searchPath in $cliSearchPaths) {
    $cmdPath = Join-Path $searchPath "openclaw.cmd"
    if (Test-Path $cmdPath) { $results.cli_installed = $true; $results.cli_path = $cmdPath; break }
    $exePath = Join-Path $searchPath "openclaw.exe"
    if (Test-Path $exePath) { $results.cli_installed = $true; $results.cli_path = $exePath; break }
}

if (-not $results.cli_installed) {
    $cliInPath = Get-Command openclaw -ErrorAction SilentlyContinue
    if ($cliInPath) {
        $results.cli_installed = $true
        $results.cli_path = $cliInPath.Source
    }
}

if ($results.cli_installed) {
    try {
        $results.cli_version = (& $results.cli_path --version 2>$null) -join " "
        if ([string]::IsNullOrWhiteSpace($results.cli_version)) { $results.cli_version = "unknown" }
    } catch {
        $results.cli_version = "unknown"
    }
    if ($results.cli_path -like "*\node_modules\*" -or $results.cli_path -like "*\npm\*") {
        $results.cli_install_method = "npm (global)"
    } elseif (Test-Path (Join-Path (Split-Path $results.cli_path) "..\.git")) {
        $results.cli_install_method = "git (source)"
    } else {
        $results.cli_install_method = "unknown"
    }
}


# Workspace
$results.workspace_path = Join-Path -Path $stateDir -ChildPath "workspace"
if (Test-Path $results.workspace_path) { $results.workspace_exists = $true }

# Parse config if present
$config = $null
if ($results.config_exists) {
    try {
        $config = Get-Content $configPath -Raw | ConvertFrom-Json
    } catch {
        $config = $null
    }
}

# Gateway port
if ($env:OPENCLAW_GATEWAY_PORT) {
    $results.gateway_port = $env:OPENCLAW_GATEWAY_PORT
} elseif ($config -and $config.gateway -and $config.gateway.port) {
    $results.gateway_port = [string]$config.gateway.port
} else {
    $results.gateway_port = "18789"
}

# Gateway token
if ($env:OPENCLAW_GATEWAY_TOKEN) {
    $results.gateway_token_set = $true
} elseif ($config -and $config.gateway -and $config.gateway.auth -and $config.gateway.auth.token) {
    $results.gateway_token_set = $true
}

# Gateway process detection (combined: port-based + process-based)
# Prefer port-based detection (more reliable than process name matching).
$tcpCmd = Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue
if ($tcpCmd) {
    try {
        $conn = Get-NetTCPConnection -LocalPort ([int]$results.gateway_port) -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($conn) {
            $results.gateway_running = $true
            $results.gateway_pid = [string]$conn.OwningProcess
            if ($conn.LocalAddress) { $results.gateway_listening_on = [string]$conn.LocalAddress }
            if ($conn.LocalAddress -eq "0.0.0.0") { $results.gateway_bind_to_all = $true }
        }
    } catch { }
}

# Fallback: process-name detection
if (-not $results.gateway_running) {
    try {
        $p = Get-Process -Name "openclaw" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($p) {
            $results.gateway_running = $true
            $results.gateway_pid = [string]$p.Id
        }
    } catch { }
}

# Get process command line (best-effort; may require permissions)
if (-not [string]::IsNullOrWhiteSpace($results.gateway_pid)) {
    try {
        $wmi = Get-WmiObject Win32_Process -Filter "ProcessId = $($results.gateway_pid)" -ErrorAction SilentlyContinue
        if ($wmi -and $wmi.CommandLine) { $results.gateway_process_cmd = $wmi.CommandLine }
    } catch { }
}

# Bind mode / listening (from config + netstat verification)
if ($config -and $config.gateway -and $config.gateway.bind) {
    $results.gateway_bind_mode = [string]$config.gateway.bind
} else {
    $results.gateway_bind_mode = "loopback"
}

# Only apply config-derived listening info if we didn't already detect a live listener.
if ([string]::IsNullOrWhiteSpace($results.gateway_listening_on)) {
    if ($results.gateway_bind_mode -eq "lan") {
        $results.gateway_bind_to_all = $true
        $results.gateway_listening_on = "0.0.0.0"
    } elseif ($results.gateway_bind_mode -eq "custom") {
        $customBind = ""
        if ($config -and $config.gateway -and $config.gateway.customBindHost) { $customBind = [string]$config.gateway.customBindHost }
        if ($customBind -eq "0.0.0.0") {
            $results.gateway_bind_to_all = $true
            $results.gateway_listening_on = "0.0.0.0"
        } elseif (-not [string]::IsNullOrWhiteSpace($customBind)) {
            $results.gateway_listening_on = $customBind
        } else {
            $results.gateway_listening_on = "127.0.0.1"
        }
    } else {
        $results.gateway_listening_on = "127.0.0.1"
    }
}

# If port-based detection didn't populate bind-to-all, fall back to netstat parsing.
if ($results.gateway_running -and -not $results.gateway_bind_to_all) {
    try {
        $netstat = netstat -an | Select-String ":$($results.gateway_port)\s+LISTENING"
        if ($netstat -match "0\.0\.0\.0:$($results.gateway_port)") {
            $results.gateway_bind_to_all = $true
            if ([string]::IsNullOrWhiteSpace($results.gateway_listening_on)) { $results.gateway_listening_on = "0.0.0.0" }
        } elseif ($netstat -match "127\.0\.0\.1:$($results.gateway_port)") {
            if ([string]::IsNullOrWhiteSpace($results.gateway_listening_on)) { $results.gateway_listening_on = "127.0.0.1" }
        }
    } catch { }
}


# Agents & integrations (v2)
if ($config) {
    try {
        $agentCount = if ($config.agents -and $config.agents.list) { $config.agents.list.Count } else { 0 }
        $results.agents_configured = [int]$agentCount
        if ($agentCount -gt 0) {
            $agentList = @()
            foreach ($a in $config.agents.list) {
                $id = if ($a.id) { [string]$a.id } else { "unknown" }
                $name = if ($a.name) { [string]$a.name } else { "unnamed" }
                $agentList += "$id ($name)"
            }
            $results.agents_list = ($agentList -join ",")

            try {
                $def = $config.agents.list | Where-Object { $_.default -eq $true } | Select-Object -First 1
                if ($def -and $def.id) { $results.default_agent_id = [string]$def.id }
            } catch { }
        }
    } catch { }

    try {
        $channels = @("whatsapp","telegram","discord","slack","signal","imessage","googlechat","msteams")
        $enabled = New-Object System.Collections.Generic.List[string]
        foreach ($ch in $channels) {
            if ($config.channels.$ch -and $config.channels.$ch.enabled -eq $true) { $enabled.Add($ch) }
        }
        $results.integrations_enabled = $enabled.ToArray()
        $results.integrations_count = $results.integrations_enabled.Count
    } catch { }

    # Risk flags (v1): capabilities.shell_access, capabilities.filesystem_write
    try {
        if ($config.capabilities) {
            if ($config.capabilities.shell_access -eq $true -or $config.capabilities.shellAccess -eq $true) { $results.risk_shell_access_enabled = $true }
            if ($config.capabilities.filesystem_write -eq $true -or $config.capabilities.filesystemWrite -eq $true) { $results.risk_filesystem_write_enabled = $true }
        }
    } catch { }
}


# Credentials directory count (v2)
try {
    $results.credentials_dir = (Join-Path -Path $stateDir -ChildPath "credentials")
    if (Test-Path $results.credentials_dir) {
        $results.credential_files_count = (Get-ChildItem -Path $results.credentials_dir -File -ErrorAction SilentlyContinue).Count
    } else {
        $results.credential_files_count = 0
    }
} catch { }


# Secret scan (v1-ish)
try {
    if (Test-Path $stateDir) {
        $patterns = @("sk-","AI_","TOKEN","KEY")
        # Match bash behavior more closely: recurse within state dir.
        $hits = Select-String -Path (Join-Path $stateDir "*") -Pattern $patterns -Exclude "*.log" -Recurse -ErrorAction SilentlyContinue
        if ($hits) {
            $files = $hits | Select-Object -ExpandProperty Path | Sort-Object -Unique
            $results.secrets_files = @($files)
            $results.secrets_count = $results.secrets_files.Count
            $results.secrets_found = ($results.secrets_count -gt 0)
        }
    }
} catch { }

# Plugins detection
try {
    $pluginsGlobalDir = Join-Path -Path $stateDir -ChildPath "extensions"
    $pluginsWorkspaceDir = Join-Path -Path $results.workspace_path -ChildPath ".openclaw\extensions"
    
    if (Test-Path $pluginsGlobalDir) {
        $globalPlugins = Get-ChildItem -Path $pluginsGlobalDir -Directory -ErrorAction SilentlyContinue
        $results.plugins.global_count = $globalPlugins.Count
        if ($globalPlugins) {
            $results.plugins.list += $globalPlugins | ForEach-Object { $_.Name }
        }
    }
    
    if (Test-Path $pluginsWorkspaceDir) {
        $workspacePlugins = Get-ChildItem -Path $pluginsWorkspaceDir -Directory -ErrorAction SilentlyContinue
        $results.plugins.workspace_count = $workspacePlugins.Count
        if ($workspacePlugins) {
            $results.plugins.list += $workspacePlugins | ForEach-Object { $_.Name }
        }
    }
    
    $results.plugins.total_count = $results.plugins.global_count + $results.plugins.workspace_count
} catch { }

# Skills detection
try {
    $skillsGlobalDir = Join-Path -Path $stateDir -ChildPath "skills"
    $skillsWorkspaceDir = Join-Path -Path $results.workspace_path -ChildPath "skills"
    
    if (Test-Path $skillsGlobalDir) {
        $globalSkills = Get-ChildItem -Path $skillsGlobalDir -Directory -ErrorAction SilentlyContinue
        $results.skills.global_count = $globalSkills.Count
        if ($globalSkills) {
            $results.skills.list += $globalSkills | ForEach-Object { $_.Name }
        }
    }
    
    if (Test-Path $skillsWorkspaceDir) {
        $workspaceSkills = Get-ChildItem -Path $skillsWorkspaceDir -Directory -ErrorAction SilentlyContinue
        $results.skills.workspace_count = $workspaceSkills.Count
        if ($workspaceSkills) {
            $results.skills.list += $workspaceSkills | ForEach-Object { $_.Name }
        }
    }
    
    $results.skills.total_count = $results.skills.global_count + $results.skills.workspace_count
} catch { }

# Registry integrations (v1-style): registry.json "name" entries
try {
    $registryPath = Join-Path -Path $stateDir -ChildPath "registry.json"
    if (Test-Path $registryPath) {
        $content = Get-Content -Path $registryPath -Raw -ErrorAction SilentlyContinue
        if (-not [string]::IsNullOrWhiteSpace($content)) {
            $m = [regex]::Matches($content, '"name"\s*:\s*"([^"]+)"')
            if ($m -and $m.Count -gt 0) {
                $names = @()
                foreach ($match in $m) {
                    $names += $match.Groups[1].Value
                }
                $names = $names | Sort-Object -Unique
                $results.registry_integrations = @($names)
                $results.registry_integrations_count = $results.registry_integrations.Count
            }
        }
    }
} catch { }


# Scheduled Task detection (v2)
$profile = $env:OPENCLAW_PROFILE
if ($profile -and $profile -ne "default") {
    $taskName = "OpenClaw Gateway ($profile)"
} else {
    $taskName = "OpenClaw Gateway"
}
$results.scheduled_task_name = $taskName
try {
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($task) {
        $results.scheduled_task_exists = $true
        $results.scheduled_task_status = [string]$task.State
    }
} catch { }


# Write JSON file or to stdout (if enabled)
$jsonString = ""
if ($JsonPathSet -or $JsonToStdout) {
    $jsonString = $results | ConvertTo-Json -Depth 6
    
    # Write to file if --json-path was provided
    if ($JsonPathSet) {
        try {
            $dir = Split-Path -Parent $JsonPath
            if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path $dir)) {
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
            }
            $jsonString | Set-Content -Path $JsonPath -Encoding UTF8
        } catch {
            Write-Host "[X] Failed to write JSON output: $JsonPath" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor DarkRed
            exit 1
        }
    }
}

Write-Log -Level "INFO" -Message "Starting OpenClaw security audit"

# Terminal output (script 1 style) - suppress in MDM mode
if (-not $MdmMode) {
    Write-Banner
    if ($JsonPathSet) {
        Write-Line "[NOTE] JSON output: $JsonPath" "Gray"
    }

    Write-Section "Detection"
    if ($results.cli_installed -or $results.config_exists -or (Test-Path $stateDir)) {
        Write-Line "[OK] State Dir: $($results.state_dir)" "Green"
        $cfgStatus = if ($results.config_exists) { "found" } else { "missing" }
        Write-Line "[OK] Config: $($results.config_path) ($cfgStatus)" "Green"
        if ($results.cli_installed) {
            Write-Line "[OK] CLI: $($results.cli_path) (v$($results.cli_version))" "Green"
        } else {
            Write-Line "[!]  CLI: not found in PATH/common locations" "Yellow"
        }
    } else {
        Write-Line "[X] OpenClaw not detected on this system." "Gray"
    }

    Write-Section "Network and Gateway"
    if ($results.gateway_running) {
        Write-Line "[ACTIVE] Gateway: ACTIVE (Port $($results.gateway_port) | PID: $($results.gateway_pid))" "Green"
    } else {
        Write-Line "[INACTIVE] Gateway: INACTIVE (Expected Port $($results.gateway_port))" "Gray"
    }
    if ($results.gateway_bind_to_all) {
        Write-Line "[!!] RISK: Gateway bound to ALL interfaces (0.0.0.0) - network reachable" "Red"
    } elseif (-not [string]::IsNullOrWhiteSpace($results.gateway_listening_on)) {
        Write-Line "[OK] Gateway binding: $($results.gateway_listening_on)" "Green"
    }
    if ($results.gateway_token_set) {
        Write-Line "[OK] Gateway auth token: CONFIGURED" "Green"
    } else {
        Write-Line "[!]  Gateway auth token: NOT SET" "Yellow"
    }

    Write-Section "Privileges and Tools"
    if ($results.risk_shell_access_enabled) {
        Write-Line "[!!] RISK: Shell Access ENABLED" "Red"
    } else {
        Write-Line "[OK] Shell Access: not flagged" "Green"
    }
    if ($results.risk_filesystem_write_enabled) {
        Write-Line "[!!] RISK: Filesystem Write ENABLED" "Red"
    } else {
        Write-Line "[OK] Filesystem Write: not flagged" "Green"
    }

    Write-Section "Agents and Integrations"
    Write-Line "[AGENT] Agents configured: $($results.agents_configured)" "Cyan"
    if (-not [string]::IsNullOrWhiteSpace($results.agents_list)) {
        Write-Line "  - $($results.agents_list)" "Gray"
    }
    if (-not [string]::IsNullOrWhiteSpace($results.default_agent_id)) {
        Write-Line "[*] Default agent: $($results.default_agent_id)" "Cyan"
    }
    Write-Line "[INTEGRATION] Integrations enabled: $($results.integrations_count)" "Cyan"
    if ($results.integrations_count -gt 0) {
        Write-Line ("  - " + ($results.integrations_enabled -join ", ")) "Gray"
    }
    if ($results.registry_integrations_count -gt 0) {
        Write-Line "[REGISTRY]  Registry integrations: $($results.registry_integrations_count)" "Cyan"
        Write-Line ("  - " + ($results.registry_integrations -join ", ")) "Gray"
    }
    if ($results.credential_files_count -gt 0) {
        Write-Line "[CREDENTIAL] Credential files: $($results.credential_files_count) found in credentials/" "Cyan"
    }

    Write-Section "Plugins and Skills"
    Write-Line "[PLUGIN] Plugins installed: $($results.plugins.total_count) (Global: $($results.plugins.global_count), Workspace: $($results.plugins.workspace_count))" "Cyan"
    if ($results.plugins.list.Count -gt 0) {
        Write-Line ("  - " + ($results.plugins.list -join ", ")) "Gray"
    }
    Write-Line "[SKILL] Skills installed: $($results.skills.total_count) (Global: $($results.skills.global_count), Workspace: $($results.skills.workspace_count))" "Cyan"
    if ($results.skills.list.Count -gt 0) {
        Write-Line ("  - " + ($results.skills.list -join ", ")) "Gray"
    }

    Write-Section "Secret/Credential Scan"
    if ($results.secrets_found -and $results.secrets_count -gt 0) {
        Write-Line "[!!] RISK: Potential secrets found in $($results.secrets_count) file(s)" "Red"
        foreach ($f in $results.secrets_files) {
            Write-Line "  [!] Secret found in: $f" "Magenta"
        }
    } else {
        Write-Line "[OK] No obvious secret patterns found (best-effort scan)" "Green"
    }

    Write-Section "Windows Service"
    if ($results.scheduled_task_exists) {
        Write-Line "[OK] Scheduled Task: configured ($($results.scheduled_task_name) | $($results.scheduled_task_status))" "Green"
    } else {
        Write-Line "[!]  Scheduled Task: not configured ($($results.scheduled_task_name))" "Yellow"
    }
}  # End MDM mode check

# Calculate security summary
$criticalIssues = 0
$warnings = 0
$infoItems = 0

# Critical issues
if ($results.risk_shell_access_enabled) { $criticalIssues++ }
if ($results.risk_filesystem_write_enabled) { $criticalIssues++ }
if ($results.secrets_found) { $criticalIssues++ }
if ($results.gateway_bind_to_all) { $criticalIssues++ }

# Warnings
if (-not $results.gateway_token_set -and $results.gateway_running) { $warnings++ }
if (-not $results.cli_installed -and $results.config_exists) { $warnings++ }
if ($results.credential_files_count -gt 0) { $warnings++ }

# Info items
$infoItems = $results.agents_configured + $results.integrations_count + $results.registry_integrations_count

# Determine risk level
$riskLevel = "clean"
if ($criticalIssues -gt 0) {
    $riskLevel = "critical"
} elseif ($warnings -gt 0) {
    $riskLevel = "warning"
}

Write-Log -Level "INFO" -Message "Audit complete: risk_level=$riskLevel critical=$criticalIssues warnings=$warnings"

# Gather MDM metadata
$mdmHostname = Get-Hostname
$mdmSerial = Get-SerialNumber
$mdmTimestamp = Get-Timestamp

# Add MDM metadata and security summary to results
$results = [ordered]@{
    mdm_mode = $MdmMode
    mdm_metadata = @{
        hostname = $mdmHostname
        serial_number = $mdmSerial
        timestamp = $mdmTimestamp
        script_version = "1.0"
    }
    security_summary = @{
        risk_level = $riskLevel
        critical_issues = $criticalIssues
        warnings = $warnings
        info_items = $infoItems
    }
} + $results

# Re-generate JSON with MDM data
if ($JsonPathSet -or $JsonToStdout) {
    $jsonString = $results | ConvertTo-Json -Depth 6
    
    # Write to file if --json-path was provided
    if ($JsonPathSet) {
        try {
            $dir = Split-Path -Parent $JsonPath
            if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path $dir)) {
                New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null
            }
            $jsonString | Set-Content -Path $JsonPath -Encoding UTF8 -ErrorAction Stop
            Write-Log -Level "INFO" -Message "JSON written to: $JsonPath"
        } catch {
            Write-Log -Level "ERROR" -Message "Failed to write JSON to: $JsonPath"
            if ($MdmMode) {
                Write-Error "Failed to write JSON output: $JsonPath"
            } else {
                Write-Host "[X] Failed to write JSON output: $JsonPath" -ForegroundColor Red
                Write-Host $_.Exception.Message -ForegroundColor DarkRed
            }
            exit 1
        }
    }
}

# Print JSON to stdout if --json was provided (not in MDM mode)
if ($JsonToStdout -and -not $MdmMode) {
    Write-Host ""
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "JSON OUTPUT:" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host $jsonString
}

# Upload to remote URL if requested
if (-not [string]::IsNullOrWhiteSpace($UploadUrl)) {
    if ([string]::IsNullOrWhiteSpace($jsonString)) {
        Write-Log -Level "ERROR" -Message "Cannot upload: no JSON data generated"
        exit 1
    }
    
    Write-Log -Level "INFO" -Message "Uploading results to: $UploadUrl"
    
    try {
        $headers = @{
            "Content-Type" = "application/json"
        }
        
        $response = Invoke-WebRequest -Uri $UploadUrl -Method Post -Body $jsonString -Headers $headers -UseBasicParsing -ErrorAction Stop
        
        if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
            Write-Log -Level "INFO" -Message "Upload successful (HTTP $($response.StatusCode))"
        } else {
            Write-Log -Level "ERROR" -Message "Upload failed (HTTP $($response.StatusCode))"
            if ($MdmMode) {
                Write-Error "Upload failed: HTTP $($response.StatusCode)"
            }
        }
    } catch {
        Write-Log -Level "ERROR" -Message "Upload failed: $($_.Exception.Message)"
        if ($MdmMode) {
            Write-Error "Upload failed: $($_.Exception.Message)"
        }
    }
}

# Determine exit code based on findings
$exitCode = 0

# Check if OpenClaw is installed (CLI, config, or state dir exists)
if (-not $results.cli_installed -and -not $results.config_exists -and -not (Test-Path $stateDir)) {
    $exitCode = 2  # Not installed
    Write-Log -Level "INFO" -Message "OpenClaw not installed (exit code 2)"
} elseif ($riskLevel -eq "critical") {
    $exitCode = 1  # Critical issues found
    Write-Log -Level "INFO" -Message "Critical security issues found (exit code 1)"
} elseif ($riskLevel -eq "warning") {
    $exitCode = 1  # Warnings found
    Write-Log -Level "INFO" -Message "Security warnings found (exit code 1)"
} else {
    $exitCode = 0  # Clean
    Write-Log -Level "INFO" -Message "No issues detected (exit code 0)"
}

# Script completed successfully
Write-Log -Level "INFO" -Message "Audit completed successfully"

# Final output based on mode
if (-not $MdmMode) {
    if ($JsonPathSet) {
        Write-Host ""
        Write-Host "✅ Results written to: $JsonPath" -ForegroundColor Green
    }
}

exit $exitCode

