# Security Policy

## Supported Versions

We release patches for security vulnerabilities. Which versions are eligible for receiving such patches depends on the CVSS v3.0 Rating:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

The PromptSentinel team takes security bugs seriously. We appreciate your efforts to responsibly disclose your findings, and will make every effort to acknowledge your contributions.

### Where to Report

**Please DO NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: **security@promptsentinel.ai**

### What to Include

Please include the following information in your report:

- Type of issue (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 5 business days
- **Resolution Timeline**: Depends on severity
  - Critical: 7 days
  - High: 14 days
  - Medium: 30 days
  - Low: 90 days

## Security Considerations for PromptSentinel

### API Keys and Secrets

- **Never commit API keys** to the repository
- Use environment variables or secure secret management
- Rotate API keys regularly
- See [docs/SECURE_SECRETS.md](docs/SECURE_SECRETS.md) for best practices

### LLM Provider Security

When using PromptSentinel with LLM providers:

1. **API Key Protection**
   - Store provider API keys securely
   - Use separate keys for development and production
   - Monitor API key usage for anomalies

2. **Data Privacy**
   - Be aware that prompts are sent to external LLM providers for classification
   - Consider data residency requirements
   - Review provider data retention policies

3. **Rate Limiting**
   - Configure appropriate rate limits
   - Monitor for abuse patterns
   - Implement budget controls

### Deployment Security

1. **Container Security**
   - Run containers as non-root user (already configured)
   - Keep base images updated
   - Scan images for vulnerabilities regularly

2. **Network Security**
   - Use TLS for all external communications
   - Implement proper network segmentation
   - Configure firewall rules appropriately

3. **Authentication & Authorization**
   - Use strong API keys (minimum 32 characters)
   - Implement proper RBAC if using Kubernetes
   - Enable authentication in production deployments

### Security Headers

PromptSentinel includes security headers by default:

- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- X-XSS-Protection: 1; mode=block
- Strict-Transport-Security (when using HTTPS)
- Content-Security-Policy

### Monitoring and Logging

1. **Security Events**
   - Monitor for repeated failed detection attempts
   - Track unusual patterns in API usage
   - Alert on budget threshold breaches

2. **Audit Logging**
   - Log all API key usage
   - Track configuration changes
   - Monitor administrative actions

## Security Tools and Scanning

We use the following tools to maintain security:

- **Snyk**: Dependency vulnerability scanning
- **Bandit**: Python security linting
- **TruffleHog**: Secret scanning
- **Safety**: Python dependency checking

### Running Security Scans

```bash
# Run complete security scan
./security/scripts/run_security_scan.sh

# Python security scan
bandit -r src/

# Dependency scan
safety check

# Container scan
snyk container test promptsentinelai/prompt-sentinel:latest
```

## Disclosure Policy

When we receive a security report, we will:

1. Confirm the problem and determine affected versions
2. Audit code to find similar problems
3. Prepare fixes for all supported versions
4. Release patches as soon as possible

## Comments on this Policy

If you have suggestions on how this process could be improved, please submit a pull request or open an issue to discuss.

## Acknowledgments

We maintain a hall of fame for security researchers who have responsibly disclosed vulnerabilities:

- *Your name could be here!*

Thank you for helping keep PromptSentinel and our users safe!