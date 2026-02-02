# Security Policy

**Claw-Hunter by [Backslash Security](https://backslash.security)**

## Supported Versions

- ✅ Reads configuration files
- ✅ Checks for running processes
- ✅ Scans for potential secrets in text files
- ✅ Reports security findings
- ❌ Modify any system configurations
- ❌ Change file permissions
- ❌ Stop or start services
- ❌ Delete or move files
- ❌ Make network connections (except optional upload)
## Security Considerations
### Data Handled by This Tool
The audit script may access and report on:
- OpenClaw configuration files (may contain API keys)
- Process information (PIDs, command lines)
- File paths and metadata
- System information (hostname, serial number)
**Important**: 
- The script does NOT extract actual API keys or secrets, only flags their potential presence
- All data stays local unless `--upload-url` is explicitly used
- Log files may contain file paths but not file contents
### When Using Upload Functionality
If using `--upload-url` to send results to a central API:
1. **Use HTTPS**: Always use HTTPS endpoints
2. **Secure API Keys**: Store API keys in files with restricted permissions (600)
3. **Review Data**: Audit what data is being sent (check JSON output first)
4. **Network Segmentation**: Ensure upload endpoint is on trusted network
5. **Authentication**: Always use `--api-key-file` for authenticated uploads
### MDM Deployment Security
When deploying via MDM:
1. **Least Privilege**: Script runs as root/SYSTEM but performs read-only operations
2. **Secure Storage**: Store scripts in protected directories (`/usr/local/bin`, `C:\Program Files`)
3. **API Key Management**: 
   - Store keys in `/etc/` (Unix) or `C:\ProgramData` (Windows)
   - Set permissions to 600 (Unix) or restricted ACL (Windows)
   - Rotate keys regularly
4. **Log Security**: Protect log files containing system information
5. **Network Security**: If uploading, use VPN or private network
### Permissions Required
**Bash (macOS/Linux):**
- Read access to `~/.openclaw/` directory
- Read access to `/usr/local/bin/openclaw` (or install location)
- Root/sudo for:
  - Serial number extraction
  - System-wide process listing (optional)
  - Writing to `/var/log/` (MDM mode)
**PowerShell (Windows):**
- Read access to `%USERPROFILE%\.openclaw` directory
- Administrator for:
  - WMI queries (serial number)
  - Scheduled task enumeration
  - Writing to `C:\ProgramData` (MDM mode)
## Reporting a Vulnerability
Backslash Security takes security seriously. If you discover a security vulnerability in Claw-Hunter, please follow responsible disclosure:
**Contact Backslash Security:**
- **Email**: hello@backslash.security
- **Website**: https://backslash.security/contact
### What Qualifies as a Security Issue
- Execution of arbitrary code
- Unauthorized file system modifications
- Information disclosure beyond intended scope
- Authentication bypass in upload functionality
- Privilege escalation
- Denial of service vulnerabilities
### What is NOT a Security Issue
- Detection of OpenClaw security issues (that's the tool's purpose)
- False positives in secret scanning
- Compatibility issues
- Feature requests
### How to Report
**DO NOT** open a public GitHub issue for security vulnerabilities.
Instead:
1. **Email**: Send details to hello@backslash.security
2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)
   - Your contact information
3. **Response Timeline**:
   - Initial response: Within 48 hours
   - Status update: Within 7 days
   - Fix timeline: Depends on severity (critical: 7-14 days)
### What to Expect
1. We will acknowledge receipt of your report
2. We will investigate and provide updates
3. We will credit you in the security advisory (unless you prefer to remain anonymous)
4. We will coordinate public disclosure after a fix is available
### Security Advisory Process
1. Vulnerability confirmed
2. Fix developed and tested
3. Security advisory published (GitHub Security Advisories)
4. Patch released
5. Public disclosure (after reasonable time for users to update)
## Security Best Practices for Users
### General
1. **Download from Official Sources**: Only download from official GitHub repository
2. **Verify Integrity**: Check SHA256 hashes if provided
3. **Review Code**: Scripts are open source - review before running
4. **Test First**: Test in non-production environment
5. **Keep Updated**: Use latest version for security fixes
### API Key Security
```bash
# Good: Secure API key file
echo "your-api-key" > /etc/openclaw-audit-key
chmod 600 /etc/openclaw-audit-key
chown root:root /etc/openclaw-audit-key
# Bad: World-readable key
echo "your-api-key" > ~/api-key.txt  # Don't do this!
```
## MDM Deployment
### Good: Restricted script location
/usr/local/bin/claw-hunter.sh  # Requires root to modify
### Bad: User-writable location
~/scripts/claw-hunter.sh  # Any user can modify
## Log File Security
### Good: Restrict log access
chmod 640 /var/log/claw-hunter.log
chown root:adm /var/log/claw-hunter.log
### Implement log rotation
cat > /etc/logrotate.d/openclaw-audit << EOF
/var/log/claw-hunter.log {
    weekly
    rotate 4
    compress
    missingok
    notifempty
}

## Known Limitations
1. **Secret Scanning**: Pattern-based detection may have false positives/negatives
2. **Bash 3.2**: Limited regex capabilities compared to modern versions
3. **Network Detection**: May not detect all network configurations
4. **Process Detection**: Depends on process naming conventions
## Audit Trail
All script executions can be logged:
# Enable audit logging
./claw-hunter.sh --mdm --log-file /var/log/claw-hunter.log
# Review audit trail
grep "Starting OpenClaw security audit" /var/log/claw-hunter.log

**Last Updated**: 2026-02-02  
**Version**: 1.0.0
