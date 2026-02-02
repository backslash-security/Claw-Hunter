#!/usr/bin/env bash
# Claw-Hunter - By Backslash Security
# https://backslash.security
#
# Usage:
#   ./claw-hunter.sh [--json] [--json-path <file>] [--mdm] [--upload-url <url>]
#
# Notes:
# - Use --json to print JSON to terminal or --json-path to save to a file.
# - Use --mdm for silent MDM execution with JSON output to standard location.

set -euo pipefail

JSON_TO_STDOUT=false
JSON_PATH=""
JSON_PATH_SET=false
MDM_MODE=false
UPLOAD_URL=""
LOG_FILE=""

usage() {
  cat <<'EOF'
Claw-Hunter

Usage:
  ./claw-hunter.sh [--json] [--json-path <file>] [--mdm] [--upload-url <url>]

Options:
  --json                   Print JSON output to terminal (stdout)
  --json-path <file>       Save JSON results to this file path
  --mdm                    MDM mode: silent execution, JSON to standard location, proper exit codes
  --upload-url <url>       Upload JSON results to this URL (requires --mdm or --json-path)
  --log-file <file>        Write logs to this file (default: /var/log/claw-hunter.log in MDM mode)
  -h, --help               Show help

MDM Mode:
  - Suppresses terminal output (errors go to stderr and log file)
  - Writes JSON to /var/log/claw-hunter.json (macOS/Linux)
  - Includes machine identification and security summary
  - Exit codes: 0=clean, 1=issues found, 2=not installed, 3=error

Notes:
  - Without --json or --json-path flags, only the formatted terminal output is shown.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --json-path)
      JSON_PATH="${2:-}"
      JSON_PATH_SET=true
      shift 2
      ;;
    --json-path=*)
      JSON_PATH="${1#*=}"
      JSON_PATH_SET=true
      shift 1
      ;;
    --json)
      JSON_TO_STDOUT=true
      shift 1
      ;;
    --mdm)
      MDM_MODE=true
      shift 1
      ;;
    --upload-url)
      UPLOAD_URL="${2:-}"
      shift 2
      ;;
    --upload-url=*)
      UPLOAD_URL="${1#*=}"
      shift 1
      ;;
    --log-file)
      LOG_FILE="${2:-}"
      shift 2
      ;;
    --log-file=*)
      LOG_FILE="${1#*=}"
      shift 1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 3
      ;;
  esac
done

PWD_P="$(pwd -P)"

# MDM mode setup
if [[ "$MDM_MODE" == "true" ]]; then
  # Set default paths for MDM mode
  if [[ -z "$LOG_FILE" ]]; then
    LOG_FILE="/var/log/claw-hunter.log"
  fi
  
  # Set default JSON output location for MDM mode
  if [[ "$JSON_PATH_SET" == "false" ]]; then
    JSON_PATH="/var/log/claw-hunter.json"
    JSON_PATH_SET=true
  fi
fi

# Set default log file if not in MDM mode but log-file was specified
if [[ -n "$LOG_FILE" && "$LOG_FILE" != /* ]]; then
  LOG_FILE="${PWD_P}/${LOG_FILE}"
fi

# Make JSON_PATH absolute if relative
if [[ "$JSON_PATH_SET" == "true" && "$JSON_PATH" != /* ]]; then
  JSON_PATH="${PWD_P}/${JSON_PATH}"
fi

# Logging function
log_msg() {
  local level="$1"
  shift
  local msg="$*"
  local timestamp
  timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  
  if [[ -n "$LOG_FILE" ]]; then
    echo "[$timestamp] [$level] $msg" >> "$LOG_FILE" 2>/dev/null || true
  fi
  
  # In MDM mode, only output errors to stderr
  if [[ "$MDM_MODE" == "true" && "$level" == "ERROR" ]]; then
    echo "[$level] $msg" >&2
  fi
}

# Get machine identification
get_hostname() {
  hostname -s 2>/dev/null || hostname 2>/dev/null || echo "unknown"
}

get_serial_number() {
  if [[ "$(uname)" == "Darwin" ]]; then
    system_profiler SPHardwareDataType 2>/dev/null | awk '/Serial Number/ {print $NF}' || echo ""
  else
    # Linux: try dmidecode (requires root) or fallback
    if command -v dmidecode &>/dev/null && [[ $EUID -eq 0 ]]; then
      dmidecode -s system-serial-number 2>/dev/null | head -1 || echo ""
    else
      cat /sys/class/dmi/id/product_serial 2>/dev/null || echo ""
    fi
  fi
}

get_timestamp() {
  date -u '+%Y-%m-%dT%H:%M:%SZ'
}

json_escape() {
  # Minimal JSON string escaping for bash (handles backslash, quote, control chars)
  local s="${1:-}"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

json_array_from_csv() {
  local csv="${1:-}"
  if [[ -z "$csv" ]]; then
    printf '[]'
    return 0
  fi

  local IFS=','
  # bash arrays are available in bash 3.2 (macOS default)
  read -r -a items <<<"$csv"

  printf '['
  local first=true
  local item
  for item in "${items[@]}"; do
    # Skip empty items (can happen if trailing commas)
    [[ -z "$item" ]] && continue
    if [[ "$first" == "true" ]]; then
      first=false
    else
      printf ','
    fi
    printf '"%s"' "$(json_escape "$item")"
  done
  printf ']'
}

run_audit() {
  # All variables default to empty/false/0. Keep bash 3.2 compatibility (no associative arrays).
  local platform="unix"
  local os=""

  local cli_installed="false"
  local cli_path=""
  local cli_version=""
  local cli_install_method=""

  local config_exists="false"
  local config_path=""
  local state_dir=""

  local workspace_exists="false"
  local workspace_path=""

  local gateway_running="false"
  local gateway_pid=""
  local gateway_process_cmd=""
  local gateway_port=""
  local gateway_token_set="false"
  local gateway_bind_mode=""
  local gateway_listening_on=""
  local gateway_bind_to_all="false"

  local launchagent_installed="false"
  local launchagent_label=""
  local launchagent_loaded="false"
  local launchagent_path=""

  local macos_app_installed="false"
  local macos_app_path=""
  local macos_app_version=""

  local agents_configured="0"
  local agents_list=""
  local default_agent_id=""

  local integrations_enabled_csv=""
  local integrations_count="0"
  local registry_integrations_csv=""
  local registry_integrations_count="0"
  local credentials_dir=""
  local credential_files_count="0"

  local risk_shell_access_enabled="false"
  local risk_filesystem_write_enabled="false"

  local secrets_found="false"
  local secrets_count="0"
  local secrets_files_csv=""

  local plugins_global_count="0"
  local plugins_workspace_count="0"
  local plugins_total_count="0"
  local plugins_list_csv=""

  local skills_global_count="0"
  local skills_workspace_count="0"
  local skills_total_count="0"
  local skills_list_csv=""

  local json_output_path="$JSON_PATH"

  if command -v sw_vers &>/dev/null; then
    os="macos"
  else
    os="linux"
  fi

  # Detect state dir (v1 compatibility)
  if [[ -n "${OPENCLAW_STATE_DIR:-}" ]]; then
    state_dir="$OPENCLAW_STATE_DIR"
  else
    state_dir="$HOME/.openclaw"
    [[ ! -d "$state_dir" && -d "$HOME/.clawdbot" ]] && state_dir="$HOME/.clawdbot"
  fi

  # Config path override support
  if [[ -n "${OPENCLAW_CONFIG_PATH:-}" ]]; then
    config_path="$OPENCLAW_CONFIG_PATH"
  else
    config_path="$state_dir/openclaw.json"
  fi
  if [[ -f "$config_path" ]]; then
    config_exists="true"
  fi

  # Detect CLI
  local -a CLI_SEARCH_PATHS=(
    "$HOME/Library/pnpm"
    "$HOME/.local/bin"
    "$HOME/.local/share/pnpm"
    "$HOME/.bun/bin"
    "$HOME/.openclaw/bin"
    "/opt/homebrew/bin"
    "/usr/local/bin"
    "/usr/bin"
  )
  local p
  for p in "${CLI_SEARCH_PATHS[@]}"; do
    if [[ -x "$p/openclaw" ]]; then
      cli_path="$p/openclaw"
      break
    fi
  done
  if [[ -z "$cli_path" ]] && command -v openclaw &>/dev/null; then
    cli_path="$(command -v openclaw)"
  fi
  if [[ -n "$cli_path" ]]; then
    cli_installed="true"
    cli_version="$("$cli_path" --version 2>/dev/null || echo "unknown")"
    if [[ "$cli_path" == *"/node_modules/"* ]] || [[ "$cli_path" == *"/.npm-global/"* ]]; then
      cli_install_method="npm (global)"
    elif [[ -d "$(dirname "$cli_path")/../.git" ]]; then
      cli_install_method="git (source)"
    else
      cli_install_method="unknown"
    fi
  fi

  # Workspace
  workspace_path="$state_dir/workspace"
  if [[ -d "$workspace_path" ]]; then
    workspace_exists="true"
  fi

  # Gateway port
  if [[ -n "${OPENCLAW_GATEWAY_PORT:-}" ]]; then
    gateway_port="$OPENCLAW_GATEWAY_PORT"
  elif [[ "$config_exists" == "true" ]] && command -v jq &>/dev/null; then
    gateway_port="$(jq -r '.gateway.port // "18789"' "$config_path" 2>/dev/null || echo "18789")"
  else
    gateway_port="18789"
  fi

  # Gateway process (both styles: pgrep + lsof on port)
  local -a pids=()
  local pid
  while IFS= read -r pid; do
    [[ -n "$pid" ]] && pids+=("$pid")
  done < <(pgrep -f "openclaw.*gateway" 2>/dev/null || true)
  if [[ ${#pids[@]} -gt 0 ]]; then
    gateway_running="true"
    gateway_pid="${pids[0]}"
  fi

  if command -v lsof &>/dev/null; then
    local lpid
    lpid="$(lsof -iTCP:"$gateway_port" -sTCP:LISTEN -t 2>/dev/null | head -n 1 || true)"
    if [[ -n "$lpid" ]]; then
      gateway_running="true"
      [[ -z "$gateway_pid" ]] && gateway_pid="$lpid"
    fi
  fi

  if [[ -n "$gateway_pid" ]]; then
    gateway_process_cmd="$(ps -p "$gateway_pid" -o command= 2>/dev/null || true)"
  fi

  # Gateway token
  if [[ -n "${OPENCLAW_GATEWAY_TOKEN:-}" ]]; then
    gateway_token_set="true"
  elif [[ "$config_exists" == "true" ]] && command -v jq &>/dev/null; then
    local tok
    tok="$(jq -r '.gateway.auth.token // ""' "$config_path" 2>/dev/null || echo "")"
    [[ -n "$tok" ]] && gateway_token_set="true"
  fi

  # Bind mode (from config when possible)
  if [[ "$config_exists" == "true" ]] && command -v jq &>/dev/null; then
    gateway_bind_mode="$(jq -r '.gateway.bind // "loopback"' "$config_path" 2>/dev/null || echo "loopback")"
    if [[ "$gateway_bind_mode" == "lan" ]]; then
      gateway_bind_to_all="true"
      gateway_listening_on="0.0.0.0"
    elif [[ "$gateway_bind_mode" == "custom" ]]; then
      local custom
      custom="$(jq -r '.gateway.customBindHost // ""' "$config_path" 2>/dev/null || echo "")"
      if [[ "$custom" == "0.0.0.0" ]]; then
        gateway_bind_to_all="true"
        gateway_listening_on="0.0.0.0"
      else
        gateway_listening_on="${custom:-127.0.0.1}"
      fi
    else
      gateway_listening_on="127.0.0.1"
    fi
  fi

  # Active listening verification (works even without jq)
  if [[ "$gateway_running" == "true" ]] && command -v lsof &>/dev/null; then
    local listen
    listen="$(lsof -nP -iTCP:"$gateway_port" -sTCP:LISTEN 2>/dev/null || true)"
    if echo "$listen" | grep -qE "TCP[[:space:]]+(\*|0\.0\.0\.0):${gateway_port}[[:space:]]*\(LISTEN\)"; then
      gateway_bind_to_all="true"
      [[ -z "$gateway_listening_on" ]] && gateway_listening_on="0.0.0.0"
    elif echo "$listen" | grep -qE "TCP[[:space:]]+127\.0\.0\.1:${gateway_port}[[:space:]]*\(LISTEN\)"; then
      [[ -z "$gateway_listening_on" ]] && gateway_listening_on="127.0.0.1"
    fi
  fi

  # LaunchAgent (macOS)
  if [[ "$os" == "macos" ]]; then
    local profile="${OPENCLAW_PROFILE:-}"
    if [[ -n "$profile" && "$profile" != "default" ]]; then
      launchagent_label="ai.openclaw.${profile}"
    else
      launchagent_label="ai.openclaw.gateway"
    fi
    launchagent_path="$HOME/Library/LaunchAgents/${launchagent_label}.plist"
    if [[ -f "$launchagent_path" ]]; then
      launchagent_installed="true"
      if launchctl print "gui/$(id -u)/${launchagent_label}" &>/dev/null; then
        launchagent_loaded="true"
      fi
    fi
  fi

  # macOS app detection
  if [[ "$os" == "macos" ]]; then
    local -a app_paths=(
      "/Applications/OpenClaw.app"
      "$HOME/Applications/OpenClaw.app"
    )
    local ap
    for ap in "${app_paths[@]}"; do
      if [[ -d "$ap" ]]; then
        macos_app_installed="true"
        macos_app_path="$ap"
        macos_app_version="$(defaults read "${macos_app_path}/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")"
        break
      fi
    done
  fi

  # Agents + Integrations (from config, v2 - requires jq)
  if [[ "$config_exists" == "true" ]] && command -v jq &>/dev/null; then
    agents_configured="$(jq -r '.agents.list // [] | length' "$config_path" 2>/dev/null || echo "0")"
    if [[ "$agents_configured" =~ ^[0-9]+$ ]] && [[ "$agents_configured" -gt 0 ]]; then
      agents_list="$(jq -r '.agents.list // [] | .[] | "\(.id // "unknown") (\(.name // "unnamed"))"' "$config_path" 2>/dev/null | tr '\n' ',' | sed 's/,$//')"
      default_agent_id="$(jq -r '.agents.list // [] | .[] | select(.default == true) | .id // empty' "$config_path" 2>/dev/null | head -n 1 || true)"
    fi

    local -a enabled=()
    local ch en
    for ch in whatsapp telegram discord slack signal imessage googlechat msteams; do
      en="$(jq -r ".channels.$ch.enabled // false" "$config_path" 2>/dev/null || echo "false")"
      [[ "$en" == "true" ]] && enabled+=("$ch")
    done
    integrations_count="${#enabled[@]}"
    # Safe array expansion for set -u
    if [[ ${#enabled[@]} -gt 0 ]]; then
      integrations_enabled_csv="$(IFS=,; echo "${enabled[*]}")"
    else
      integrations_enabled_csv=""
    fi
  fi

  # Credentials directory count (v2)
  credentials_dir="$state_dir/credentials"
  if [[ -d "$credentials_dir" ]]; then
    credential_files_count="$(find "$credentials_dir" -type f 2>/dev/null | wc -l | tr -d ' ')"
  fi

  # Integrations registry (v1 style): registry.json "name" entries
  local registry_path="$state_dir/registry.json"
  if [[ -f "$registry_path" ]]; then
    registry_integrations_csv="$(sed -nE 's/.*"name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' "$registry_path" 2>/dev/null | sort -u | tr '\n' ',' | sed 's/,$//')"
    if [[ -n "$registry_integrations_csv" ]]; then
      registry_integrations_count="$(awk -F',' '{print NF}' <<<"$registry_integrations_csv" 2>/dev/null || echo "1")"
    fi
  fi

  # v1 risk flags: shell_access / filesystem_write
  if [[ "$config_exists" == "true" ]]; then
    if command -v jq &>/dev/null; then
      local shell_write fs_write
      shell_write="$(jq -r '.capabilities.shell_access // .capabilities.shellAccess // false' "$config_path" 2>/dev/null || echo "false")"
      fs_write="$(jq -r '.capabilities.filesystem_write // .capabilities.filesystemWrite // false' "$config_path" 2>/dev/null || echo "false")"
      [[ "$shell_write" == "true" ]] && risk_shell_access_enabled="true"
      [[ "$fs_write" == "true" ]] && risk_filesystem_write_enabled="true"
    else
      grep -q '"shell_access"[[:space:]]*:[[:space:]]*true' "$config_path" 2>/dev/null && risk_shell_access_enabled="true"
      grep -q '"filesystem_write"[[:space:]]*:[[:space:]]*true' "$config_path" 2>/dev/null && risk_filesystem_write_enabled="true"
    fi
  fi

  # Secret scan (v1)
  if [[ -d "$state_dir" ]]; then
    secrets_files_csv="$(grep -rInE "sk-|AI_|TOKEN|KEY" "$state_dir" 2>/dev/null | cut -d: -f1 | sort -u | tr '\n' ',' | sed 's/,$//')"
    if [[ -n "$secrets_files_csv" ]]; then
      secrets_found="true"
      secrets_count="$(awk -F',' '{print NF}' <<<"$secrets_files_csv" 2>/dev/null || echo "1")"
    fi
  fi

  # Plugins detection
  local plugins_global_dir="$state_dir/extensions"
  local plugins_workspace_dir="$workspace_path/.openclaw/extensions"
  
  if [[ -d "$plugins_global_dir" ]]; then
    plugins_global_count="$(find "$plugins_global_dir" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')"
    local plugin_names="$(find "$plugins_global_dir" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; 2>/dev/null | sort | tr '\n' ',' | sed 's/,$//')"
    [[ -n "$plugin_names" ]] && plugins_list_csv="$plugin_names"
  fi
  
  if [[ -d "$plugins_workspace_dir" ]]; then
    plugins_workspace_count="$(find "$plugins_workspace_dir" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')"
    local workspace_plugin_names="$(find "$plugins_workspace_dir" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; 2>/dev/null | sort | tr '\n' ',' | sed 's/,$//')"
    if [[ -n "$workspace_plugin_names" ]]; then
      [[ -n "$plugins_list_csv" ]] && plugins_list_csv="$plugins_list_csv,$workspace_plugin_names" || plugins_list_csv="$workspace_plugin_names"
    fi
  fi
  
  plugins_total_count=$((plugins_global_count + plugins_workspace_count))

  # Skills detection
  local skills_global_dir="$state_dir/skills"
  local skills_workspace_dir="$workspace_path/skills"
  
  if [[ -d "$skills_global_dir" ]]; then
    skills_global_count="$(find "$skills_global_dir" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')"
    local skill_names="$(find "$skills_global_dir" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; 2>/dev/null | sort | tr '\n' ',' | sed 's/,$//')"
    [[ -n "$skill_names" ]] && skills_list_csv="$skill_names"
  fi
  
  if [[ -d "$skills_workspace_dir" ]]; then
    skills_workspace_count="$(find "$skills_workspace_dir" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')"
    local workspace_skill_names="$(find "$skills_workspace_dir" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; 2>/dev/null | sort | tr '\n' ',' | sed 's/,$//')"
    if [[ -n "$workspace_skill_names" ]]; then
      [[ -n "$skills_list_csv" ]] && skills_list_csv="$skills_list_csv,$workspace_skill_names" || skills_list_csv="$workspace_skill_names"
    fi
  fi
  
  skills_total_count=$((skills_global_count + skills_workspace_count))

  # Terminal output (script 1 style) - suppress in MDM mode
  if [[ "$MDM_MODE" != "true" ]]; then
    echo "=========================================="
    echo "🛡️  CLAW-HUNTER: UNIX/MAC"
    echo "    By Backslash Security"
    echo "    https://backslash.security"
    echo "=========================================="
    if [[ "$JSON_PATH_SET" == "true" ]]; then
      echo "📝 JSON output: $JSON_PATH"
    fi

    echo ""
    echo "--- [ Detection ] ---"
  fi
  
  log_msg "INFO" "Starting OpenClaw security audit"
  
  if [[ "$MDM_MODE" != "true" ]]; then
    if [[ "$cli_installed" == "true" || "$config_exists" == "true" || -d "$state_dir" ]]; then
      echo "✅ State Dir: $state_dir"
      echo "✅ Config: $config_path ($( [[ "$config_exists" == "true" ]] && echo "found" || echo "missing" ))"
      if [[ "$cli_installed" == "true" ]]; then
        echo "✅ CLI: $cli_path (v$cli_version)"
      else
        echo "⚠️  CLI: not found in PATH/common locations"
      fi
    else
      echo "❌ OpenClaw not detected on this system."
    fi

    echo ""
    echo "--- [ Network and Gateway ] ---"
    if [[ "$gateway_running" == "true" ]]; then
      echo "⚡ Gateway: ACTIVE (Port $gateway_port | PID: $gateway_pid)"
    else
      echo "💤 Gateway: INACTIVE (Expected Port $gateway_port)"
    fi
    if [[ "$gateway_bind_to_all" == "true" ]]; then
      echo "❗ RISK: Gateway bound to ALL interfaces (0.0.0.0) - network reachable"
    elif [[ -n "$gateway_listening_on" ]]; then
      echo "✅ Gateway binding: $gateway_listening_on"
    fi
    if [[ "$gateway_token_set" == "true" ]]; then
      echo "✅ Gateway auth token: CONFIGURED"
    else
      echo "⚠️  Gateway auth token: NOT SET"
    fi

    echo ""
    echo "--- [ Privileges and Tools ] ---"
    if [[ "$risk_shell_access_enabled" == "true" ]]; then
      echo "❗ RISK: Shell Access ENABLED"
    else
      echo "✅ Shell Access: not flagged"
    fi
    if [[ "$risk_filesystem_write_enabled" == "true" ]]; then
      echo "❗ RISK: Filesystem Write ENABLED"
    else
      echo "✅ Filesystem Write: not flagged"
    fi

    echo ""
    echo "--- [ Agents and Integrations ] ---"
    echo "🤖 Agents configured: $agents_configured"
    [[ -n "$agents_list" ]] && echo "  - $agents_list"
    [[ -n "$default_agent_id" ]] && echo "⭐ Default agent: $default_agent_id"
    echo "🔌 Integrations enabled: $integrations_count"
    [[ -n "$integrations_enabled_csv" ]] && echo "  - $integrations_enabled_csv"
    if [[ "$registry_integrations_count" != "0" ]]; then
      echo "🛠️  Registry integrations: $registry_integrations_count"
      echo "  - $registry_integrations_csv"
    fi
    if [[ "$credential_files_count" != "0" ]]; then
      echo "🔐 Credential files: $credential_files_count found in credentials/"
    fi

    echo ""
    echo "--- [ Plugins and Skills ] ---"
    echo "🧩 Plugins installed: $plugins_total_count (Global: $plugins_global_count, Workspace: $plugins_workspace_count)"
    [[ -n "$plugins_list_csv" ]] && echo "  - $plugins_list_csv"
    echo "🎯 Skills installed: $skills_total_count (Global: $skills_global_count, Workspace: $skills_workspace_count)"
    [[ -n "$skills_list_csv" ]] && echo "  - $skills_list_csv"

    echo ""
    echo "--- [ Secret/Credential Scan ] ---"
    if [[ "$secrets_found" == "true" ]]; then
      echo "❗ RISK: Potential secrets found in $secrets_count file(s)"
      IFS=',' read -r -a sfiles <<<"$secrets_files_csv"
      local f
      for f in "${sfiles[@]}"; do
        [[ -n "$f" ]] && echo "  [!] Secret found in: $f"
      done
    else
      echo "✅ No obvious secret patterns found (best-effort scan)"
    fi

    if [[ "$os" == "macos" ]]; then
      echo ""
      echo "--- [ macOS Service/App ] ---"
      if [[ "$launchagent_installed" == "true" ]]; then
        if [[ "$launchagent_loaded" == "true" ]]; then
          echo "✅ LaunchAgent: installed & loaded ($launchagent_label)"
        else
          echo "⚠️  LaunchAgent: installed but not loaded ($launchagent_label)"
        fi
      else
        echo "⚠️  LaunchAgent: not installed"
      fi
      if [[ "$macos_app_installed" == "true" ]]; then
        echo "✅ OpenClaw.app: installed ($macos_app_path)"
        [[ -n "$macos_app_version" ]] && echo "  - Version: $macos_app_version"
      else
        echo "⚠️  OpenClaw.app: not installed"
      fi
    fi
  fi  # End MDM mode check
  
  # Calculate security summary for MDM and JSON output
  local critical_issues=0
  local warnings=0
  local info_items=0
  
  # Critical issues
  [[ "$risk_shell_access_enabled" == "true" ]] && ((critical_issues++))
  [[ "$risk_filesystem_write_enabled" == "true" ]] && ((critical_issues++))
  [[ "$secrets_found" == "true" ]] && ((critical_issues++))
  [[ "$gateway_bind_to_all" == "true" ]] && ((critical_issues++))
  
  # Warnings
  [[ "$gateway_token_set" != "true" && "$gateway_running" == "true" ]] && ((warnings++))
  [[ "$cli_installed" != "true" && "$config_exists" == "true" ]] && ((warnings++))
  [[ "$os" == "macos" && "$launchagent_installed" == "true" && "$launchagent_loaded" != "true" ]] && ((warnings++))
  [[ "$credential_files_count" -gt 0 ]] && ((warnings++))
  
  # Info items
  info_items=$((agents_configured + integrations_count + registry_integrations_count))
  
  # Determine risk level
  local risk_level="clean"
  if [[ $critical_issues -gt 0 ]]; then
    risk_level="critical"
  elif [[ $warnings -gt 0 ]]; then
    risk_level="warning"
  fi
  
  log_msg "INFO" "Audit complete: risk_level=$risk_level critical=$critical_issues warnings=$warnings"

  # Gather MDM metadata
  local mdm_hostname=""
  local mdm_serial=""
  local mdm_timestamp=""
  if [[ "$MDM_MODE" == "true" || "$JSON_PATH_SET" == "true" || "$JSON_TO_STDOUT" == "true" ]]; then
    mdm_hostname="$(get_hostname)"
    mdm_serial="$(get_serial_number)"
    mdm_timestamp="$(get_timestamp)"
  fi

  # Write JSON to file or stdout (if enabled)
  if [[ "$JSON_PATH_SET" == "true" || "$JSON_TO_STDOUT" == "true" ]]; then
    local json=""
    if command -v jq &>/dev/null; then
    json="$(jq -n \
      --arg mdm_mode "$MDM_MODE" \
      --arg mdm_hostname "$mdm_hostname" \
      --arg mdm_serial "$mdm_serial" \
      --arg mdm_timestamp "$mdm_timestamp" \
      --arg risk_level "$risk_level" \
      --argjson critical_issues "$critical_issues" \
      --argjson warnings "$warnings" \
      --argjson info_items "$info_items" \
      --arg platform "$platform" \
      --arg os "$os" \
      --arg cli_installed "$cli_installed" \
      --arg cli_path "$cli_path" \
      --arg cli_version "$cli_version" \
      --arg cli_install_method "$cli_install_method" \
      --arg config_exists "$config_exists" \
      --arg config_path "$config_path" \
      --arg state_dir "$state_dir" \
      --arg workspace_exists "$workspace_exists" \
      --arg workspace_path "$workspace_path" \
      --arg gateway_running "$gateway_running" \
      --arg gateway_pid "$gateway_pid" \
      --arg gateway_process_cmd "$gateway_process_cmd" \
      --arg gateway_port "$gateway_port" \
      --arg gateway_token_set "$gateway_token_set" \
      --arg gateway_bind_mode "$gateway_bind_mode" \
      --arg gateway_listening_on "$gateway_listening_on" \
      --arg gateway_bind_to_all "$gateway_bind_to_all" \
      --arg launchagent_installed "$launchagent_installed" \
      --arg launchagent_label "$launchagent_label" \
      --arg launchagent_loaded "$launchagent_loaded" \
      --arg launchagent_path "$launchagent_path" \
      --arg macos_app_installed "$macos_app_installed" \
      --arg macos_app_path "$macos_app_path" \
      --arg macos_app_version "$macos_app_version" \
      --arg agents_configured "$agents_configured" \
      --arg agents_list "$agents_list" \
      --arg default_agent_id "$default_agent_id" \
      --arg integrations_enabled_csv "$integrations_enabled_csv" \
      --arg integrations_count "$integrations_count" \
      --arg registry_integrations_csv "$registry_integrations_csv" \
      --arg registry_integrations_count "$registry_integrations_count" \
      --arg credentials_dir "$credentials_dir" \
      --arg credential_files_count "$credential_files_count" \
      --arg plugins_global_count "$plugins_global_count" \
      --arg plugins_workspace_count "$plugins_workspace_count" \
      --arg plugins_total_count "$plugins_total_count" \
      --arg plugins_list_csv "$plugins_list_csv" \
      --arg skills_global_count "$skills_global_count" \
      --arg skills_workspace_count "$skills_workspace_count" \
      --arg skills_total_count "$skills_total_count" \
      --arg skills_list_csv "$skills_list_csv" \
      --arg risk_shell_access_enabled "$risk_shell_access_enabled" \
      --arg risk_filesystem_write_enabled "$risk_filesystem_write_enabled" \
      --arg secrets_found "$secrets_found" \
      --arg secrets_count "$secrets_count" \
      --arg secrets_files_csv "$secrets_files_csv" \
      --arg json_output_path "$json_output_path" \
      '{
        mdm_mode: ($mdm_mode == "true"),
        mdm_metadata: {
          hostname: $mdm_hostname,
          serial_number: $mdm_serial,
          timestamp: $mdm_timestamp,
          script_version: "1.0"
        },
        security_summary: {
          risk_level: $risk_level,
          critical_issues: $critical_issues,
          warnings: $warnings,
          info_items: $info_items
        },
        platform: $platform,
        os: $os,
        cli_installed: ($cli_installed == "true"),
        cli_path: $cli_path,
        cli_version: $cli_version,
        cli_install_method: $cli_install_method,
        config_exists: ($config_exists == "true"),
        config_path: $config_path,
        state_dir: $state_dir,
        workspace_exists: ($workspace_exists == "true"),
        workspace_path: $workspace_path,
        gateway_running: ($gateway_running == "true"),
        gateway_pid: $gateway_pid,
        gateway_process_cmd: $gateway_process_cmd,
        gateway_port: $gateway_port,
        gateway_token_set: ($gateway_token_set == "true"),
        gateway_bind_mode: $gateway_bind_mode,
        gateway_listening_on: $gateway_listening_on,
        gateway_bind_to_all: ($gateway_bind_to_all == "true"),
        launchagent_installed: ($launchagent_installed == "true"),
        launchagent_label: $launchagent_label,
        launchagent_loaded: ($launchagent_loaded == "true"),
        launchagent_path: $launchagent_path,
        macos_app_installed: ($macos_app_installed == "true"),
        macos_app_path: $macos_app_path,
        macos_app_version: $macos_app_version,
        agents_configured: ($agents_configured | tonumber),
        agents_list: $agents_list,
        default_agent_id: $default_agent_id,
        integrations_enabled: (if $integrations_enabled_csv == "" then [] else ($integrations_enabled_csv | split(",")) end),
        integrations_count: ($integrations_count | tonumber),
        registry_integrations: (if $registry_integrations_csv == "" then [] else ($registry_integrations_csv | split(",")) end),
        registry_integrations_count: ($registry_integrations_count | tonumber),
        credentials_dir: $credentials_dir,
        credential_files_count: ($credential_files_count | tonumber),
        plugins: {
          global_count: ($plugins_global_count | tonumber),
          workspace_count: ($plugins_workspace_count | tonumber),
          total_count: ($plugins_total_count | tonumber),
          list: (if $plugins_list_csv == "" then [] else ($plugins_list_csv | split(",")) end)
        },
        skills: {
          global_count: ($skills_global_count | tonumber),
          workspace_count: ($skills_workspace_count | tonumber),
          total_count: ($skills_total_count | tonumber),
          list: (if $skills_list_csv == "" then [] else ($skills_list_csv | split(",")) end)
        },
        risk_shell_access_enabled: ($risk_shell_access_enabled == "true"),
        risk_filesystem_write_enabled: ($risk_filesystem_write_enabled == "true"),
        secrets_found: ($secrets_found == "true"),
        secrets_count: ($secrets_count | tonumber),
        secrets_files: (if $secrets_files_csv == "" then [] else ($secrets_files_csv | split(",")) end),
        json_output_path: $json_output_path
      }')"
  else
    json="{"
    json+="\"mdm_mode\":$MDM_MODE,"
    json+="\"mdm_metadata\":{"
    json+="\"hostname\":\"$(json_escape "$mdm_hostname")\","
    json+="\"serial_number\":\"$(json_escape "$mdm_serial")\","
    json+="\"timestamp\":\"$(json_escape "$mdm_timestamp")\","
    json+="\"script_version\":\"1.0\""
    json+="},"
    json+="\"security_summary\":{"
    json+="\"risk_level\":\"$(json_escape "$risk_level")\","
    json+="\"critical_issues\":$critical_issues,"
    json+="\"warnings\":$warnings,"
    json+="\"info_items\":$info_items"
    json+="},"
    json+="\"platform\":\"$(json_escape "$platform")\","
    json+="\"os\":\"$(json_escape "$os")\","
    json+="\"cli_installed\":$cli_installed,"
    json+="\"cli_path\":\"$(json_escape "$cli_path")\","
    json+="\"cli_version\":\"$(json_escape "$cli_version")\","
    json+="\"cli_install_method\":\"$(json_escape "$cli_install_method")\","
    json+="\"config_exists\":$config_exists,"
    json+="\"config_path\":\"$(json_escape "$config_path")\","
    json+="\"state_dir\":\"$(json_escape "$state_dir")\","
    json+="\"workspace_exists\":$workspace_exists,"
    json+="\"workspace_path\":\"$(json_escape "$workspace_path")\","
    json+="\"gateway_running\":$gateway_running,"
    json+="\"gateway_pid\":\"$(json_escape "$gateway_pid")\","
    json+="\"gateway_process_cmd\":\"$(json_escape "$gateway_process_cmd")\","
    json+="\"gateway_port\":\"$(json_escape "$gateway_port")\","
    json+="\"gateway_token_set\":$gateway_token_set,"
    json+="\"gateway_bind_mode\":\"$(json_escape "$gateway_bind_mode")\","
    json+="\"gateway_listening_on\":\"$(json_escape "$gateway_listening_on")\","
    json+="\"gateway_bind_to_all\":$gateway_bind_to_all,"
    json+="\"launchagent_installed\":$launchagent_installed,"
    json+="\"launchagent_label\":\"$(json_escape "$launchagent_label")\","
    json+="\"launchagent_loaded\":$launchagent_loaded,"
    json+="\"launchagent_path\":\"$(json_escape "$launchagent_path")\","
    json+="\"macos_app_installed\":$macos_app_installed,"
    json+="\"macos_app_path\":\"$(json_escape "$macos_app_path")\","
    json+="\"macos_app_version\":\"$(json_escape "$macos_app_version")\","
    json+="\"agents_configured\":$agents_configured,"
    json+="\"agents_list\":\"$(json_escape "$agents_list")\","
    json+="\"default_agent_id\":\"$(json_escape "$default_agent_id")\","
    json+="\"integrations_enabled\":$(json_array_from_csv "$integrations_enabled_csv"),"
    json+="\"integrations_count\":$integrations_count,"
    json+="\"registry_integrations\":$(json_array_from_csv "$registry_integrations_csv"),"
    json+="\"registry_integrations_count\":$registry_integrations_count,"
    json+="\"credentials_dir\":\"$(json_escape "$credentials_dir")\","
    json+="\"credential_files_count\":$credential_files_count,"
    json+="\"plugins\":{\"global_count\":$plugins_global_count,\"workspace_count\":$plugins_workspace_count,\"total_count\":$plugins_total_count,\"list\":$(json_array_from_csv "$plugins_list_csv")},"
    json+="\"skills\":{\"global_count\":$skills_global_count,\"workspace_count\":$skills_workspace_count,\"total_count\":$skills_total_count,\"list\":$(json_array_from_csv "$skills_list_csv")},"
    json+="\"risk_shell_access_enabled\":$risk_shell_access_enabled,"
    json+="\"risk_filesystem_write_enabled\":$risk_filesystem_write_enabled,"
    json+="\"secrets_found\":$secrets_found,"
    json+="\"secrets_count\":$secrets_count,"
    json+="\"secrets_files\":$(json_array_from_csv "$secrets_files_csv"),"
    json+="\"json_output_path\":\"$(json_escape "$json_output_path")\""
    json+="}"
    fi

    # Write to file if --json-path was provided or in MDM mode
    if [[ "$JSON_PATH_SET" == "true" ]]; then
      mkdir -p "$(dirname "$JSON_PATH")" 2>/dev/null || {
        log_msg "ERROR" "Failed to create directory for JSON output: $(dirname "$JSON_PATH")"
        return 3
      }
      if printf '%s\n' "$json" >"$JSON_PATH" 2>/dev/null; then
        log_msg "INFO" "JSON written to: $JSON_PATH"
      else
        log_msg "ERROR" "Failed to write JSON to: $JSON_PATH"
        return 3
      fi
    fi

    # Print to stdout if --json was provided (not in MDM mode)
    if [[ "$JSON_TO_STDOUT" == "true" && "$MDM_MODE" != "true" ]]; then
      echo ""
      echo "=========================================="
      echo "JSON OUTPUT:"
      echo "=========================================="
      printf '%s\n' "$json"
    fi
  fi
  
  # Upload to remote URL if requested
  if [[ -n "$UPLOAD_URL" ]]; then
    if [[ -z "$json" ]]; then
      log_msg "ERROR" "Cannot upload: no JSON data generated"
      return 3
    fi
    
    log_msg "INFO" "Uploading results to: $UPLOAD_URL"
    
    local curl_opts=(-X POST -H "Content-Type: application/json" -d "$json")
    
    if command -v curl &>/dev/null; then
      local upload_response
      local upload_code
      upload_response="$(curl -s -w "\n%{http_code}" "${curl_opts[@]}" "$UPLOAD_URL" 2>&1)"
      upload_code="$(echo "$upload_response" | tail -n1)"
      
      if [[ "$upload_code" =~ ^2[0-9]{2}$ ]]; then
        log_msg "INFO" "Upload successful (HTTP $upload_code)"
      else
        log_msg "ERROR" "Upload failed (HTTP $upload_code)"
        [[ "$MDM_MODE" == "true" ]] && echo "Upload failed: HTTP $upload_code" >&2
      fi
    else
      log_msg "ERROR" "curl not found, cannot upload results"
      [[ "$MDM_MODE" == "true" ]] && echo "ERROR: curl not found" >&2
    fi
  fi
  
  # Determine exit code based on findings
  local exit_code=0
  if [[ "$cli_installed" != "true" && "$config_exists" != "true" && ! -d "$state_dir" ]]; then
    exit_code=2  # OpenClaw not installed
    log_msg "INFO" "Exit code: 2 (OpenClaw not detected)"
  elif [[ $critical_issues -gt 0 ]]; then
    exit_code=1  # Security issues found
    log_msg "INFO" "Exit code: 1 (Security issues detected: $critical_issues critical)"
  elif [[ $warnings -gt 0 ]]; then
    exit_code=1  # Warnings found
    log_msg "INFO" "Exit code: 1 (Warnings detected: $warnings warnings)"
  else
    exit_code=0  # Clean
    log_msg "INFO" "Exit code: 0 (No issues detected)"
  fi
  
  return $exit_code
}

# Run audit and capture exit code
run_audit
EXIT_CODE=$?

# Final output based on mode
if [[ "$MDM_MODE" != "true" ]]; then
  if [[ "$JSON_PATH_SET" == "true" ]]; then
    echo ""
    echo "✅ Results written to: $JSON_PATH"
  fi
fi

exit $EXIT_CODE

