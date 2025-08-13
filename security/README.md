# Security Scanning & Reporting

This directory contains security scanning tools and reports for PromptSentinel.

## Quick Start

Run a complete security scan:
```bash
./security/scripts/run_security_scan.sh
```

This will:
1. Scan Python dependencies
2. Scan Docker container
3. Scan JavaScript SDK
4. Scan Python SDK
5. Scan Infrastructure as Code
6. Generate a comprehensive security report

## Files & Directories

### Scripts
- `scripts/run_security_scan.sh` - Main security scanning script
- `scripts/generate_report.py` - Report generation from scan artifacts

### Reports
- `SECURITY_SCAN_REPORT.md` - Latest security scan report

### Artifacts
- `artifacts/snyk/` - Snyk scan results in JSON format

## Configuration

The security scanner automatically loads credentials from:
1. **Vault** (preferred) - Uses `.local/vault_secure.py` to retrieve `api_keys/snyk`
2. **Environment** - Falls back to `SNYK_TOKEN` environment variable
3. **`.env` file** - Last resort fallback

## Requirements

- Snyk CLI installed (`brew install snyk` or see [installation guide](https://docs.snyk.io/snyk-cli/install-the-snyk-cli))
- Python 3.8+ for report generation
- Docker (for container scanning)
- Valid Snyk account and API token

## Authentication

### Using Vault (Recommended)
Store your Snyk token in Vault:
```bash
python3 .local/vault_secure.py set-secret api_keys/snyk YOUR_SNYK_TOKEN
```

### Using Environment Variable
```bash
export SNYK_TOKEN=your_token_here
./security/scripts/run_security_scan.sh
```

### Using .env File
Add to `.env`:
```
SNYK_TOKEN=your_token_here
```


## CI/CD Integration

To add security scanning to CI/CD, add this step to your GitHub Actions workflow:

```yaml
- name: Security Scan
  env:
    SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
  run: |
    npm install -g snyk
    ./security/scripts/run_security_scan.sh
```

## Scan Frequency

Recommended scanning schedule:
- **Daily**: Automated scans in CI/CD for main branch
- **Per PR**: Quick dependency scan on pull requests
- **Pre-release**: Full comprehensive scan before releases
- **Weekly**: Container and dependency vulnerability analysis

## Interpreting Results

### Severity Levels
- 🔴 **Critical**: Fix immediately, may allow remote code execution
- 🟠 **High**: Fix urgently, significant security risk
- 🟡 **Medium**: Fix in next release cycle
- ⚪ **Low**: Review and fix if convenient

### Report Sections
1. **Executive Summary**: High-level vulnerability count
2. **Detailed Results**: Per-component vulnerability breakdown
3. **Recommendations**: Actionable remediation steps
4. **Scan Artifacts**: Links to detailed JSON reports

## Troubleshooting

### Snyk Authentication Failed
- Verify token is valid: `snyk auth YOUR_TOKEN`
- Check token in Vault: `python3 .local/vault_secure.py get-secret api_keys/snyk`

### Docker Scan Fails
- Ensure Docker is running: `docker ps`
- Pull latest image: `docker pull promptsentinelai/prompt-sentinel:latest`

### Python SDK Not Scanned
- The Python SDK uses pyproject.toml which may need special handling
- Check `artifacts/snyk/sdk-python-report.json` for details

## Support

For issues with security scanning:
1. Check the detailed JSON reports in `artifacts/snyk/`
2. Review Snyk documentation at https://docs.snyk.io
3. Open an issue in the PromptSentinel repository