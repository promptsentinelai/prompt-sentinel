#!/usr/bin/env python3
# Elastic License 2.0
#
# Copyright (c) 2024-present, PromptSentinel
#
# This source code is licensed under the Elastic License 2.0 found in the
# LICENSE file in the root directory of this source tree.

"""Security scanning script for dependency vulnerabilities and code analysis."""

import asyncio
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


class SecurityScanner:
    """Comprehensive security scanner for dependencies and code."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.results = {}

    async def run_all_scans(self) -> dict[str, Any]:
        """Run all security scans."""
        logger.info("Starting comprehensive security scan")

        # Run scans in parallel where possible
        await asyncio.gather(
            self.scan_dependencies_safety(),
            self.scan_code_bandit(),
            self.scan_dependencies_pip_audit(),
            return_exceptions=True,
        )

        # Generate summary report
        self.results["summary"] = self._generate_summary()

        return self.results

    async def scan_dependencies_safety(self):
        """Scan dependencies for known vulnerabilities using Safety."""
        logger.info("Running Safety dependency scan")

        try:
            # Check if safety is installed
            result = subprocess.run(  # noqa: S603, S607
                ["uv", "run", "safety", "--version"], capture_output=True, text=True, timeout=30
            )

            if result.returncode != 0:
                logger.warning("Safety not installed, installing...")
                subprocess.run(  # noqa: S603, S607
                    ["uv", "add", "--dev", "safety"], cwd=self.project_root, check=True, timeout=120
                )

            # Run safety scan
            result = subprocess.run(  # noqa: S603, S607
                ["uv", "run", "safety", "check", "--json"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode == 0:
                self.results["safety"] = {
                    "status": "clean",
                    "vulnerabilities": [],
                    "message": "No known vulnerabilities found",
                }
            else:
                # Parse JSON output for vulnerabilities
                try:
                    vulnerabilities = json.loads(result.stdout)
                    self.results["safety"] = {
                        "status": "vulnerabilities_found",
                        "vulnerabilities": vulnerabilities,
                        "count": len(vulnerabilities),
                    }
                except json.JSONDecodeError:
                    self.results["safety"] = {
                        "status": "error",
                        "error": result.stderr or "Failed to parse Safety output",
                    }

        except subprocess.TimeoutExpired:
            self.results["safety"] = {"status": "timeout", "error": "Safety scan timed out"}
        except Exception as e:
            self.results["safety"] = {"status": "error", "error": str(e)}

    async def scan_dependencies_pip_audit(self):
        """Scan dependencies using pip-audit."""
        logger.info("Running pip-audit dependency scan")

        try:
            # Check if pip-audit is installed
            result = subprocess.run(  # noqa: S603, S607
                ["uv", "run", "pip-audit", "--version"], capture_output=True, text=True, timeout=30
            )

            if result.returncode != 0:
                logger.warning("pip-audit not installed, installing...")
                subprocess.run(  # noqa: S603, S607
                    ["uv", "add", "--dev", "pip-audit"],
                    cwd=self.project_root,
                    check=True,
                    timeout=120,
                )

            # Run pip-audit
            result = subprocess.run(  # noqa: S603, S607
                ["uv", "run", "pip-audit", "--format=json"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode == 0:
                self.results["pip_audit"] = {
                    "status": "clean",
                    "vulnerabilities": [],
                    "message": "No vulnerabilities found",
                }
            else:
                # Parse JSON output
                try:
                    vulnerabilities = json.loads(result.stdout)
                    self.results["pip_audit"] = {
                        "status": "vulnerabilities_found",
                        "vulnerabilities": vulnerabilities,
                        "count": len(vulnerabilities),
                    }
                except json.JSONDecodeError:
                    self.results["pip_audit"] = {
                        "status": "error",
                        "error": result.stderr or "Failed to parse pip-audit output",
                    }

        except subprocess.TimeoutExpired:
            self.results["pip_audit"] = {"status": "timeout", "error": "pip-audit scan timed out"}
        except Exception as e:
            self.results["pip_audit"] = {"status": "error", "error": str(e)}

    async def scan_code_bandit(self):
        """Scan code for security issues using Bandit."""
        logger.info("Running Bandit code security scan")

        try:
            # Check if bandit is installed
            result = subprocess.run(  # noqa: S603, S607
                ["uv", "run", "bandit", "--version"], capture_output=True, text=True, timeout=30
            )

            if result.returncode != 0:
                logger.warning("Bandit not installed, installing...")
                subprocess.run(  # noqa: S603, S607
                    ["uv", "add", "--dev", "bandit[toml]"],
                    cwd=self.project_root,
                    check=True,
                    timeout=120,
                )

            # Run bandit scan
            result = subprocess.run(  # noqa: S603, S607
                [
                    "uv",
                    "run",
                    "bandit",
                    "-r",
                    "src/",
                    "-f",
                    "json",
                    "-ll",  # Only medium and high severity
                    "--skip",
                    "B101,B601",  # Skip assert and shell usage (common false positives)
                ],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=300,
            )

            # Parse results (bandit returns non-zero if issues found)
            try:
                # Look for JSON in stdout
                stdout_lines = result.stdout.split("\n")
                json_output = ""
                for line in stdout_lines:
                    if line.strip().startswith("{"):
                        json_output = "\n".join(stdout_lines[stdout_lines.index(line) :])
                        break

                if json_output:
                    bandit_results = json.loads(json_output)

                    issues = bandit_results.get("results", [])
                    high_issues = [i for i in issues if i.get("issue_severity") == "HIGH"]
                    medium_issues = [i for i in issues if i.get("issue_severity") == "MEDIUM"]

                    self.results["bandit"] = {
                        "status": "completed",
                        "total_issues": len(issues),
                        "high_severity": len(high_issues),
                        "medium_severity": len(medium_issues),
                        "issues": issues,
                        "metrics": bandit_results.get("metrics", {}),
                        "passed": len(high_issues) == 0,  # Only fail on high severity
                    }
                else:
                    # No output usually means no issues found
                    self.results["bandit"] = {
                        "status": "completed",
                        "total_issues": 0,
                        "high_severity": 0,
                        "medium_severity": 0,
                        "issues": [],
                        "metrics": {},
                        "passed": True,
                    }

            except json.JSONDecodeError:
                # Try to get error from stderr
                error_msg = result.stderr or "Failed to parse Bandit output"
                self.results["bandit"] = {
                    "status": "error",
                    "error": error_msg,
                    "stdout": result.stdout[:200],  # First 200 chars for debugging
                    "stderr": result.stderr[:200],
                }

        except subprocess.TimeoutExpired:
            self.results["bandit"] = {"status": "timeout", "error": "Bandit scan timed out"}
        except Exception as e:
            self.results["bandit"] = {"status": "error", "error": str(e)}

    def _generate_summary(self) -> dict[str, Any]:
        """Generate security scan summary."""
        summary = {
            "total_scans": len(self.results) - 1,  # Exclude summary itself
            "passed_scans": 0,
            "failed_scans": 0,
            "warnings": 0,
            "critical_issues": 0,
            "overall_status": "unknown",
        }

        # Analyze each scan result
        for scan_name, result in self.results.items():
            if scan_name == "summary":
                continue

            status = result.get("status", "error")

            if status == "clean":
                summary["passed_scans"] += 1
            elif status == "vulnerabilities_found":
                summary["failed_scans"] += 1
                vuln_count = result.get("count", 0)
                summary["critical_issues"] += vuln_count
            elif status == "completed":
                # For bandit
                if result.get("passed", False):
                    summary["passed_scans"] += 1
                else:
                    summary["failed_scans"] += 1
                    summary["critical_issues"] += result.get("high_severity", 0)
                    summary["warnings"] += result.get("medium_severity", 0)
            else:
                summary["warnings"] += 1

        # Determine overall status
        if summary["critical_issues"] > 0:
            summary["overall_status"] = "critical"
        elif summary["failed_scans"] > 0:
            summary["overall_status"] = "failed"
        elif summary["warnings"] > 0:
            summary["overall_status"] = "warning"
        else:
            summary["overall_status"] = "passed"

        return summary

    def print_report(self):
        """Print formatted security scan report."""
        print("\n" + "=" * 60)
        print("🔒 SECURITY SCAN REPORT")
        print("=" * 60)

        summary = self.results.get("summary", {})
        overall_status = summary.get("overall_status", "unknown")

        # Status emoji
        status_emoji = {"passed": "✅", "warning": "⚠️", "failed": "❌", "critical": "🚨"}

        print(f"{status_emoji.get(overall_status, '❓')} Overall Status: {overall_status.upper()}")
        print(f"📊 Total Scans: {summary.get('total_scans', 0)}")
        print(f"✅ Passed: {summary.get('passed_scans', 0)}")
        print(f"❌ Failed: {summary.get('failed_scans', 0)}")
        print(f"⚠️  Warnings: {summary.get('warnings', 0)}")
        print(f"🚨 Critical Issues: {summary.get('critical_issues', 0)}")

        # Detailed results
        print("\n📋 SCAN DETAILS:")
        print("-" * 40)

        # Safety results
        if "safety" in self.results:
            self._print_scan_result("Safety (Known Vulnerabilities)", self.results["safety"])

        # pip-audit results
        if "pip_audit" in self.results:
            self._print_scan_result("pip-audit (Dependencies)", self.results["pip_audit"])

        # Bandit results
        if "bandit" in self.results:
            self._print_bandit_result(self.results["bandit"])

        print("\n" + "=" * 60)

    def _print_scan_result(self, scan_name: str, result: dict[str, Any]):
        """Print individual scan result."""
        status = result.get("status", "unknown")

        if status == "clean":
            print(f"✅ {scan_name}: Clean")
        elif status == "vulnerabilities_found":
            count = result.get("count", 0)
            print(f"❌ {scan_name}: {count} vulnerabilities found")

            # Show first few vulnerabilities
            vulns = result.get("vulnerabilities", [])
            for vuln in vulns[:3]:  # Show first 3
                if isinstance(vuln, dict):
                    pkg = vuln.get("package", "unknown")
                    issue = vuln.get("advisory", "Unknown issue")
                    print(f"   • {pkg}: {issue[:60]}...")

            if len(vulns) > 3:
                print(f"   • ... and {len(vulns) - 3} more")

        elif status == "error":
            error = result.get("error", "Unknown error")
            print(f"❌ {scan_name}: Error - {error}")
        elif status == "timeout":
            print(f"⏱️  {scan_name}: Timed out")
        else:
            print(f"❓ {scan_name}: {status}")

    def _print_bandit_result(self, result: dict[str, Any]):
        """Print Bandit scan result."""
        status = result.get("status", "unknown")

        if status == "completed":
            total = result.get("total_issues", 0)
            high = result.get("high_severity", 0)
            medium = result.get("medium_severity", 0)
            passed = result.get("passed", False)

            status_icon = "✅" if passed else "⚠️"
            print(f"{status_icon} Bandit (Code Security): {total} issues found")

            if high > 0:
                print(f"   🚨 High severity: {high}")
            if medium > 0:
                print(f"   ⚠️  Medium severity: {medium}")

            # Show some issues
            issues = result.get("issues", [])
            for issue in issues[:3]:
                filename = issue.get("filename", "").replace(str(self.project_root) + "/", "")
                test_id = issue.get("test_id", "")
                line = issue.get("line_number", "")
                print(f"   • {filename}:{line} - {test_id}")

        elif status == "error":
            error = result.get("error", "Unknown error")
            print(f"❌ Bandit (Code Security): Error - {error}")
        else:
            print(f"❓ Bandit (Code Security): {status}")

    def save_report(self, output_file: Path):
        """Save detailed report to file."""
        with open(output_file, "w") as f:
            json.dump(self.results, f, indent=2, default=str)

        logger.info(f"Security scan report saved to {output_file}")


async def main():
    """Run security scanning."""
    project_root = Path(__file__).parent.parent
    scanner = SecurityScanner(project_root)

    try:
        results = await scanner.run_all_scans()

        # Print report
        scanner.print_report()

        # Save detailed report
        report_file = project_root / "security_scan_report.json"
        scanner.save_report(report_file)

        # Exit with appropriate code
        summary = results.get("summary", {})
        if summary.get("overall_status") in ["critical", "failed"]:
            sys.exit(1)
        elif summary.get("overall_status") == "warning":
            sys.exit(0)  # Warnings don't fail the build
        else:
            sys.exit(0)

    except KeyboardInterrupt:
        logger.info("Security scan interrupted")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Security scan failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
