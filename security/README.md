# Security Scanning Documentation

This directory contains security vulnerability scanning infrastructure for PromptSentinel.

## Directory Structure

```
security/
├── SECURITY_SCAN_REPORT.md    # Main consolidated report (committed to Git)
├── artifacts/                  # Scan outputs (committed as proof of scanning)
│   ├── snyk/                  # Snyk scan results
│   ├── npm/                   # NPM audit results
│   ├── go/                    # Go vulnerability results
│   └── sbom/                  # Software Bill of Materials (SBOM) files
└── scripts/                   # Automation scripts
    ├── run_security_scan.sh   # Main scan orchestrator
    └── generate_report.py     # Report generator
```

## Configuration

### Snyk Authentication
To avoid login prompts and enable full scanning features, set your Snyk auth token:

1. Get your token from: https://app.snyk.io/account
2. Add to your `.env` file:
   ```bash
   SNYK_TOKEN=your-snyk-auth-token
   ```
3. Or export as environment variable:
   ```bash
   export SNYK_TOKEN=your-snyk-auth-token
   ```

The scanning script will automatically detect and use the token from either source.

## Usage

### Run Complete Security Scan
```bash
make security-scan
```

This will:
1. Scan Python dependencies (main project)
2. Scan Docker container
3. Scan Python SDK
4. Scan JavaScript SDK
5. Scan Go SDK (if Go is installed)
6. Generate Software Bill of Materials (SBOM)
7. Generate consolidated report

### Other Commands
```bash
make security-report  # Regenerate report from existing artifacts
make security-quick   # Quick Python-only scan
make security-clean   # Clean artifacts (not recommended)
make sbom             # Generate Software Bill of Materials only
```

## Artifacts

The `artifacts/` directory contains JSON output from security scanning tools. These files are **intentionally committed to Git** as:

1. **Proof of security scanning** - Demonstrates due diligence
2. **Audit trail** - Historical record of security posture
3. **No sensitive data** - Contains only:
   - Vulnerability information
   - Package names and versions
   - Public organization name (already in GitHub URL)
   - Local development paths (not production)

## Report

The main report (`SECURITY_SCAN_REPORT.md`) provides:
- Executive summary
- Vulnerability counts by component
- Compliance status
- Recommendations
- Scan commands for reproduction

## Security Status

As of the last scan:
- **0 vulnerabilities** across all components
- **All SDKs scanned** and secure
- **Docker container** using Alpine Linux (zero vulnerabilities)
- **Dependencies** all up-to-date

## Continuous Security

### Before Each Release
1. Run `make security-scan`
2. Review the report
3. Address any vulnerabilities found
4. Commit updated artifacts and report

### Regular Maintenance
- Weekly: Check for new CVEs
- Monthly: Update base Docker image
- Quarterly: Full security audit

## Integration with CI/CD

Add to your CI pipeline:
```yaml
- name: Security Scan
  run: make security-scan
  
- name: Check for Vulnerabilities
  run: |
    VULNS=$(jq '.vulnerabilities | length' security/artifacts/snyk/python-report.json)
    if [ "$VULNS" -gt 0 ]; then
      echo "Found $VULNS vulnerabilities!"
      exit 1
    fi
```

## Software Bill of Materials (SBOM)

The security scan now generates SBOMs in industry-standard formats:

- **CycloneDX** - OWASP standard for software supply chain component analysis
- **SPDX** - Software Package Data Exchange (ISO/IEC 5962:2021 standard)

SBOMs provide:
- Complete dependency inventory
- License information
- Component versions and hashes
- Supply chain transparency

Generated SBOMs are stored in `security/artifacts/sbom/` and include:
- `python-sbom.cdx.json` - Python dependencies SBOM
- `container-sbom.cdx.json` - Docker container SBOM
- `sdk-*-sbom.cdx.json` - SDK SBOMs (when available)

## Tools Used

- **Snyk CLI** - Primary vulnerability scanner and SBOM generator
- **npm audit** - JavaScript dependency scanner
- **govulncheck** - Go vulnerability checker (when available)

## Notes

- Artifacts are kept as proof of scanning
- No sensitive information is stored in artifacts
- Reports use current date, not versioned
- Single source of truth: `SECURITY_SCAN_REPORT.md`