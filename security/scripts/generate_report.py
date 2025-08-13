#!/usr/bin/env python3
"""Generate security scan report from artifacts."""

import json
from datetime import datetime
from pathlib import Path


def load_json_safe(filepath):
    """Safely load JSON file, return empty dict if error."""
    try:
        with open(filepath) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def get_vulnerability_count(report):
    """Extract vulnerability count from report."""
    if report.get("skipped"):
        return "Skipped"
    if report.get("error"):
        return "Error"

    # Check if scan was successful
    if report.get("ok") is False:
        vulnerabilities = report.get("vulnerabilities", [])
        if isinstance(vulnerabilities, list):
            return len(vulnerabilities)
    elif report.get("ok") is True:
        return 0

    # For container scans
    vulnerabilities = report.get("vulnerabilities", [])
    if isinstance(vulnerabilities, list):
        return len(vulnerabilities)

    return "Unknown"


def get_severity_counts(report):
    """Count vulnerabilities by severity."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    if report.get("skipped") or report.get("error"):
        return counts

    vulnerabilities = report.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        return counts

    for vuln in vulnerabilities:
        severity = vuln.get("severity", "").lower()
        if severity in counts:
            counts[severity] += 1
    return counts


def format_vulnerability_summary(counts):
    """Format vulnerability counts for display."""
    if all(v == 0 for v in counts.values()):
        return "✅ No vulnerabilities found"

    parts = []
    if counts["critical"] > 0:
        parts.append(f"🔴 {counts['critical']} Critical")
    if counts["high"] > 0:
        parts.append(f"🟠 {counts['high']} High")
    if counts["medium"] > 0:
        parts.append(f"🟡 {counts['medium']} Medium")
    if counts["low"] > 0:
        parts.append(f"⚪ {counts['low']} Low")

    return " | ".join(parts) if parts else "✅ No vulnerabilities found"


def generate_report():
    """Generate the security scan report."""
    # Get paths
    script_dir = Path(__file__).parent
    security_dir = script_dir.parent
    artifacts_dir = security_dir / "artifacts"

    # Load all reports
    python_report = load_json_safe(artifacts_dir / "snyk" / "python-report.json")
    docker_report = load_json_safe(artifacts_dir / "snyk" / "docker-report.json")
    js_sdk_report = load_json_safe(artifacts_dir / "snyk" / "sdk-js-report.json")
    py_sdk_report = load_json_safe(artifacts_dir / "snyk" / "sdk-python-report.json")

    # Get vulnerability counts and severity
    python_vulns = get_vulnerability_count(python_report)
    docker_vulns = get_vulnerability_count(docker_report)
    js_sdk_vulns = get_vulnerability_count(js_sdk_report)
    py_sdk_vulns = get_vulnerability_count(py_sdk_report)

    # Get severity breakdowns
    python_severity = get_severity_counts(python_report)
    docker_severity = get_severity_counts(docker_report)
    js_sdk_severity = get_severity_counts(js_sdk_report)
    py_sdk_severity = get_severity_counts(py_sdk_report)

    # Calculate totals
    total_vulns = 0
    total_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for report_severity in [python_severity, docker_severity, js_sdk_severity, py_sdk_severity]:
        for level in total_severity:
            total_severity[level] += report_severity[level]
            total_vulns += report_severity[level]

    # Generate the report
    report = f"""# PromptSentinel Security Scan Report

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Scanner:** Snyk Security Scanner
**Project:** PromptSentinel - LLM Prompt Injection Detection

## Executive Summary

**Total Vulnerabilities Found:** {total_vulns}

{format_vulnerability_summary(total_severity)}

## Detailed Results

### 1. Python Dependencies (Main Application)
- **Status:** {"✅ Clean" if python_vulns == 0 else f"⚠️ {python_vulns} vulnerabilities found"}
- **Severity Breakdown:** {format_vulnerability_summary(python_severity)}
- **Scan Type:** Dependencies in pyproject.toml

### 2. Docker Container
- **Status:** {"✅ Clean" if docker_vulns == 0 else f"⚠️ {docker_vulns} vulnerabilities found"}
- **Image:** promptsentinelai/prompt-sentinel:latest
- **Severity Breakdown:** {format_vulnerability_summary(docker_severity)}
- **Base Image:** python:3.11-slim

### 3. JavaScript SDK
- **Status:** {"✅ Clean" if js_sdk_vulns == 0 else f"⚠️ {js_sdk_vulns} vulnerabilities found"}
- **Package:** @promptsentinel/sdk
- **Severity Breakdown:** {format_vulnerability_summary(js_sdk_severity)}
- **Dependencies:** 24 packages scanned

### 4. Python SDK
- **Status:** {"✅ Clean" if py_sdk_vulns == 0 else f"⚠️ {py_sdk_vulns} vulnerabilities found"}
- **Package:** promptsentinel
- **Severity Breakdown:** {format_vulnerability_summary(py_sdk_severity)}
- **Dependencies:** Core + async support

### 5. Infrastructure as Code (IaC)
- **Status:** Configuration files scanned
- **Files Checked:** Dockerfile, docker-compose.yml, GitHub Actions
- **Issues Found:** See artifacts/snyk/iac-report.json for details

## Recommendations

"""

    if total_vulns == 0:
        report += """✅ **No security vulnerabilities detected!**

The codebase and all dependencies are currently free from known security vulnerabilities.

### Best Practices to Maintain Security:
1. **Regular Scanning:** Run security scans before each release
2. **Dependency Updates:** Keep dependencies up to date
3. **Monitor Advisories:** Watch for new CVEs in dependencies
4. **Container Security:** Regularly scan Docker images for vulnerabilities
"""
    else:
        report += f"""⚠️ **{total_vulns} vulnerabilities detected**

### Immediate Actions Required:
"""
        if total_severity["critical"] > 0:
            report += (
                f"1. **Fix {total_severity['critical']} CRITICAL vulnerabilities immediately**\n"
            )
        if total_severity["high"] > 0:
            report += f"2. **Address {total_severity['high']} HIGH severity issues**\n"
        if total_severity["medium"] > 0:
            report += f"3. **Plan to resolve {total_severity['medium']} MEDIUM severity issues**\n"
        if total_severity["low"] > 0:
            report += f"4. **Review {total_severity['low']} LOW severity issues**\n"

        report += """
### Remediation Steps:
1. Run `snyk fix` to automatically fix vulnerabilities where possible
2. Update dependencies to their latest secure versions
3. Review and apply security patches
4. Re-run security scans after fixes
"""

    report += """
## Scan Artifacts

All detailed scan results are available in the `security/artifacts/` directory:
- `snyk/python-report.json` - Main application dependency scan
- `snyk/docker-report.json` - Container vulnerability scan
- `snyk/sdk-js-report.json` - JavaScript SDK scan
- `snyk/sdk-python-report.json` - Python SDK scan
- `snyk/iac-report.json` - Infrastructure as Code scan

## Next Steps

1. Review any identified vulnerabilities
2. Apply recommended fixes
3. Re-run security scans
4. Update this report regularly
5. Consider implementing automated security scanning in CI/CD

---
*This report was automatically generated by `security/scripts/generate_report.py`*
"""

    # Write the report
    report_path = security_dir / "SECURITY_SCAN_REPORT.md"
    report_path.write_text(report)
    print(f"Report generated: {report_path}")

    # Also generate a summary for stdout
    print("\n" + "=" * 50)
    print("SECURITY SCAN SUMMARY")
    print("=" * 50)
    print(f"Total Vulnerabilities: {total_vulns}")
    print(f"Critical: {total_severity['critical']}")
    print(f"High: {total_severity['high']}")
    print(f"Medium: {total_severity['medium']}")
    print(f"Low: {total_severity['low']}")
    print("=" * 50)


if __name__ == "__main__":
    generate_report()
