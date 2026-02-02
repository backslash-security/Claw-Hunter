# Example Outputs

This directory contains example JSON outputs from the Claw-Hunter tool demonstrating different scenarios.

## Files

### `output-clean.json`
Example of a **clean** security audit with no issues detected.

**Characteristics:**
- All security best practices followed
- Gateway token configured
- No shell access or filesystem write enabled
- No secrets found
- Gateway bound to localhost only
- Exit code: `0`

**Risk Level:** `clean`

### `output-critical.json`
Example of a **critical** security audit with multiple serious issues.

**Characteristics:**
- Gateway exposed to all interfaces (0.0.0.0)
- No gateway authentication token
- Shell access enabled
- Filesystem write enabled
- Secrets found in configuration files
- Multiple credential files present
- Exit code: `1`

**Risk Level:** `critical`

**Critical Issues Detected:**
1. Gateway bound to all interfaces without authentication
2. Shell access capability enabled
3. Filesystem write capability enabled
4. Potential secrets exposed in files

### `output-warning.json` (Coming Soon)
Example of a **warning** level audit with moderate concerns.

## Understanding Risk Levels

### Clean (risk_level: "clean")
- No critical issues or warnings
- All security best practices followed
- Safe for production use
- **Exit code:** `0`

### Warning (risk_level: "warning")
- Minor security concerns present
- No critical vulnerabilities
- Should be reviewed and addressed
- **Exit code:** `1`

**Common warnings:**
- Gateway running without auth token (but localhost only)
- Credential files present
- Services not loaded/configured properly

### Critical (risk_level: "critical")
- Serious security vulnerabilities detected
- Immediate action required
- Should not be used in production
- **Exit code:** `1`

**Critical issues:**
- Gateway exposed to network without authentication
- Shell access enabled
- Filesystem write enabled
- Secrets/API keys in files

## Using Examples

### Validate Against Your Environment

Compare your audit output with these examples:

```bash
# Run audit
./claw-hunter.sh --json-path my-audit.json

# Compare with examples
diff my-audit.json examples/output-clean.json
```

### Test Your Parsing Logic

Use these examples to test integrations:

```bash
# Parse risk level
jq '.security_summary.risk_level' examples/output-critical.json

# Count critical issues
jq '.security_summary.critical_issues' examples/output-critical.json

# List secrets found
jq '.secrets_files[]' examples/output-critical.json
```

### SIEM Integration Testing

Test your SIEM ingestion with these examples:

```bash
# Simulate upload
curl -X POST https://your-siem.com/api/audits \
  -H "Content-Type: application/json" \
  -d @examples/output-critical.json
```

## JSON Structure

All outputs follow this structure:

```json
{
  "mdm_mode": boolean,
  "mdm_metadata": {
    "hostname": "string",
    "serial_number": "string",
    "timestamp": "ISO8601",
    "script_version": "string"
  },
  "security_summary": {
    "risk_level": "clean|warning|critical",
    "critical_issues": number,
    "warnings": number,
    "info_items": number
  },
  "platform": "unix|windows",
  "os": "macos|linux|windows",
  ... // Full audit data
}
```

## Creating Custom Examples

To create your own examples:

1. Run the audit:
   ```bash
   ./claw-hunter.sh --json-path my-example.json
   ```

2. Sanitize sensitive data:
   - Remove actual serial numbers
   - Remove real hostnames
   - Remove API keys/secrets
   - Remove personal paths

3. Add clear documentation

4. Submit via pull request

## See Also

- [Main README](../README.md) - Full documentation
- [MDM Guides](../docs/mdm-guides/) - Deployment instructions
- [API Integration](../docs/api-integration.md) - Upload endpoint spec
