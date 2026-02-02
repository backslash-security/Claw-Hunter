# Jamf Pro Deployment Guide

This guide covers deploying Claw-Hunter via Jamf Pro for macOS devices.

## Overview

Deploy the audit script to run automatically on a schedule and report results back to your central monitoring system.

## Prerequisites

- Jamf Pro 10.x or higher
- macOS devices enrolled in Jamf
- (Optional) Central API endpoint for result collection
- (Optional) API key for authentication

## Deployment Methods

### Method 1: Policy with Script (Recommended)

This method runs the audit on-demand or on a schedule via a Jamf Policy.

#### Step 1: Upload Script to Jamf

1. Log into Jamf Pro
2. Navigate to **Settings** → **Computer Management** → **Scripts**
3. Click **+ New**
4. Configure:
   - **Display Name**: `Claw-Hunter`
   - **Script Contents**: Paste contents of `claw-hunter.sh`
   - **Parameter Labels**:
     - Parameter 4: `Upload URL` (optional)
     - Parameter 5: `API Key` (optional)

5. Click **Save**

#### Step 2: Create Policy

1. Navigate to **Computers** → **Policies**
2. Click **+ New**
3. Configure **General**:
   - **Display Name**: `Claw-Hunter - Weekly`
   - **Enabled**: ✓
   - **Trigger**: Recurring Check-in
   - **Execution Frequency**: Once per week
   
4. Configure **Scripts**:
   - Add script: `Claw-Hunter`
   - Priority: After
   - Parameters:
     - Parameter 4: `https://your-api.com/audits`
     - Parameter 5: Leave empty (will use API key file)

5. Configure **Scope**:
   - Target: All computers or specific Smart Group

6. Click **Save**

#### Step 3: (Optional) Deploy API Key

If using upload functionality:

1. Create a package containing your API key:
   ```bash
   mkdir /tmp/openclaw-key
   echo "your-api-key-here" > /tmp/openclaw-key/claw-hunter-key.txt
   pkgbuild --root /tmp/openclaw-key \
     --identifier com.yourorg.openclaw.apikey \
     --version 1.0 \
     --install-location /etc \
     openclaw-api-key.pkg
   ```

2. Upload package to Jamf
3. Deploy via Policy before audit policy runs

#### Modify Script for Parameters

Update the script to use Jamf parameters:

```bash
# At top of claw-hunter.sh, after argument parsing
if [[ -n "$4" ]]; then
    UPLOAD_URL="$4"
fi

if [[ -n "$5" ]]; then
    API_KEY_FILE="$5"
fi
```

### Method 2: LaunchDaemon (Advanced)

For continuous monitoring, deploy as a LaunchDaemon.

#### Step 1: Create LaunchDaemon plist

`com.yourorg.claw-hunter.plist`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.yourorg.claw-hunter</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/claw-hunter.sh</string>
        <string>--mdm</string>
        <string>--upload-url</string>
        <string>https://your-api.com/audits</string>
        <string>--api-key-file</string>
        <string>/etc/claw-hunter-key.txt</string>
    </array>
    <key>StartInterval</key>
    <integer>86400</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/claw-hunter-daemon.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/claw-hunter-daemon-error.log</string>
</dict>
</plist>
```

#### Step 2: Package and Deploy

```bash
# Create package structure
mkdir -p /tmp/claw-hunter-pkg/usr/local/bin
mkdir -p /tmp/claw-hunter-pkg/Library/LaunchDaemons

# Copy files
cp claw-hunter.sh /tmp/claw-hunter-pkg/usr/local/bin/
chmod +x /tmp/claw-hunter-pkg/usr/local/bin/claw-hunter.sh
cp com.yourorg.claw-hunter.plist /tmp/claw-hunter-pkg/Library/LaunchDaemons/

# Create package
pkgbuild --root /tmp/claw-hunter-pkg \
  --identifier com.yourorg.openclaw.audit \
  --version 1.0 \
  --install-location / \
  claw-hunter-1.0.pkg
```

Deploy via Jamf Policies.

## Collecting Results

### Option 1: Extension Attributes

Create an Extension Attribute to surface audit results in Jamf inventory:

1. Navigate to **Settings** → **Computer Management** → **Extension Attributes**
2. Click **+ New**
3. Configure:
   - **Display Name**: `OpenClaw Risk Level`
   - **Data Type**: String
   - **Input Type**: Script
   
4. Script:
   ```bash
   #!/bin/bash
   if [ -f /var/log/claw-hunter.json ]; then
       risk_level=$(grep -o '"risk_level":"[^"]*"' /var/log/claw-hunter.json | cut -d'"' -f4)
       echo "<result>$risk_level</result>"
   else
       echo "<result>Not Run</result>"
   fi
   ```

5. Save and run inventory update

Create additional Extension Attributes for:
- Critical issues count
- Last audit timestamp
- OpenClaw version

### Option 2: Smart Groups

Create Smart Groups based on audit results:

**High Risk Devices:**
- Criteria: OpenClaw Risk Level | is | critical
- Use for: Immediate remediation policies

**Medium Risk Devices:**
- Criteria: OpenClaw Risk Level | is | warning
- Use for: Scheduled review

### Option 3: Jamf API Integration

Upload results to Jamf API for custom reporting:

```bash
# In script or as post-flight
if [ -f /var/log/claw-hunter.json ]; then
    curl -X POST \
      -H "Authorization: Bearer $JAMF_API_TOKEN" \
      -H "Content-Type: application/json" \
      -d @/var/log/claw-hunter.json \
      "https://yourinstance.jamfcloud.com/api/v1/computer-inventory-collection-settings"
fi
```

## Monitoring and Alerts

### Jamf Pro Notifications

1. **Settings** → **Global Management** → **Re-enrollment**
2. Create notification for failed policies
3. Set recipients for audit policy failures

### Splunk Integration (if available)

Forward logs to Splunk:

```bash
# Add to audit script
if [ -f /var/log/claw-hunter.json ]; then
    /opt/splunkforwarder/bin/splunk add oneshot /var/log/claw-hunter.json \
      -index security_audits
fi
```

## Troubleshooting

### Script Not Running

**Check Policy Logs:**
1. Computers → Search for device
2. History tab → Policy Logs
3. Find audit policy execution

**Check Script Permissions:**
```bash
sudo ls -la /usr/local/bin/claw-hunter.sh
# Should be: -rwxr-xr-x root wheel
```

### No Results in Extension Attributes

**Verify JSON File Exists:**
```bash
sudo ls -la /var/log/claw-hunter.json
sudo cat /var/log/claw-hunter.json | jq .
```

**Force Inventory Update:**
```bash
sudo jamf recon
```

### Upload Failures

**Check Logs:**
```bash
sudo tail -50 /var/log/claw-hunter.log
```

**Test Manually:**
```bash
sudo /usr/local/bin/claw-hunter.sh --mdm \
  --upload-url https://your-api.com/audits \
  --api-key-file /etc/claw-hunter-key.txt
echo "Exit code: $?"
```

## Best Practices

1. **Test First**: Deploy to a test group before production
2. **Schedule Wisely**: Run during off-peak hours (e.g., 2 AM local)
3. **Monitor Performance**: Watch for script execution time
4. **Version Control**: Tag scripts in Jamf with version numbers
5. **API Key Security**: Store API keys securely, rotate regularly
6. **Log Rotation**: Set up log rotation for `/var/log/claw-hunter.log`

## Example Smart Groups

### Critical Security Issues
```
OpenClaw Risk Level | is | critical
OR
OpenClaw Critical Issues | greater than | 0
```

### Needs Audit
```
Last Check-in | more than x days ago | 7
AND
OpenClaw Risk Level | is not | (any value)
```

### Compliant Devices
```
OpenClaw Risk Level | is | clean
AND
Last Check-in | less than x days ago | 7
```

## Security Considerations

- API keys should have read-only access when possible
- Use Jamf's encrypted script parameters for sensitive data
- Limit audit script scope to specific Computer Groups
- Review audit logs regularly
- Implement change management for script updates

## Support

For Jamf-specific issues:
- Jamf Nation: https://community.jamf.com
- Jamf Support: Via your support portal

For script issues:
- GitHub Issues: https://github.com/backslash-security/claw-hunter/issues
