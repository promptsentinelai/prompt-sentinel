#!/bin/bash

# PromptSentinel Security Vulnerability Scanner
# Runs comprehensive security scans across all components

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECURITY_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$SECURITY_DIR")"
ARTIFACTS_DIR="$SECURITY_DIR/artifacts"

# Create artifact directories if they don't exist
mkdir -p "$ARTIFACTS_DIR"/snyk

echo -e "${GREEN}=== PromptSentinel Security Scan ===${NC}"
echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
echo "Project Root: $PROJECT_ROOT"
echo ""

# Change to project root
cd "$PROJECT_ROOT"

# Check if Snyk is installed
if ! command -v snyk &> /dev/null; then
    echo -e "${RED}Error: Snyk CLI is not installed${NC}"
    echo "Please install Snyk CLI: https://docs.snyk.io/snyk-cli/install-the-snyk-cli"
    exit 1
fi

# Check for Snyk auth token - try Vault first
if [ -z "${SNYK_TOKEN}" ]; then
    # Try to load from Vault
    if [ -f "$PROJECT_ROOT/.local/vault_secure.py" ]; then
        echo -e "${GREEN}Loading SNYK_TOKEN from Vault...${NC}"
        SNYK_TOKEN=$(python3 "$PROJECT_ROOT/.local/vault_secure.py" get-secret api_keys/snyk 2>/dev/null)
        if [ -n "${SNYK_TOKEN}" ]; then
            export SNYK_TOKEN="${SNYK_TOKEN}"
            echo -e "${GREEN}✓ SNYK_TOKEN loaded from Vault${NC}"
        fi
    fi
    
    # Fallback to .env file if still not set
    if [ -z "${SNYK_TOKEN}" ] && [ -f "$PROJECT_ROOT/.env" ]; then
        echo -e "${GREEN}Loading SNYK_TOKEN from .env file...${NC}"
        export $(grep -E '^SNYK_TOKEN=' "$PROJECT_ROOT/.env" | xargs) 2>/dev/null || true
        if [ -n "${SNYK_TOKEN}" ]; then
            echo -e "${GREEN}✓ SNYK_TOKEN loaded from .env${NC}"
        fi
    fi
fi

# Check if we have a token
if [ -z "${SNYK_TOKEN}" ]; then
    echo -e "${YELLOW}Warning: SNYK_TOKEN not found in Vault or .env${NC}"
    echo "Trying to use existing Snyk authentication..."
    if ! snyk auth 2>/dev/null | grep -q "Authenticated"; then
        echo -e "${YELLOW}Warning: Snyk is not authenticated${NC}"
        echo "Please run: snyk auth"
        echo "Continuing with limited scanning..."
    fi
else
    # Authenticate with the token
    echo "${SNYK_TOKEN}" | snyk auth 2>/dev/null || {
        echo -e "${YELLOW}Warning: Failed to authenticate with Snyk token${NC}"
    }
fi

echo -e "${GREEN}1. Scanning Python dependencies...${NC}"
if [ -f "pyproject.toml" ]; then
    # Generate requirements.txt for Snyk
    pip freeze > requirements.txt 2>/dev/null || true
    
    if [ -f "requirements.txt" ]; then
        snyk test --file=requirements.txt --json > "$ARTIFACTS_DIR/snyk/python-report.json" 2>&1 || {
            echo -e "${YELLOW}Warning: Python scan completed with issues${NC}"
        }
        echo "✓ Python scan complete"
        
        # Clean up temporary requirements.txt
        rm -f requirements.txt
    else
        echo -e "${YELLOW}Warning: Could not generate requirements.txt${NC}"
        echo '{"error": "Could not generate requirements.txt"}' > "$ARTIFACTS_DIR/snyk/python-report.json"
    fi
else
    echo -e "${YELLOW}No pyproject.toml found${NC}"
    echo '{"skipped": true, "reason": "No pyproject.toml"}' > "$ARTIFACTS_DIR/snyk/python-report.json"
fi

echo -e "${GREEN}2. Scanning Docker container...${NC}"
if [ -f "Dockerfile" ]; then
    # Try to scan the published Docker image
    IMAGE_NAME="promptsentinelai/prompt-sentinel:latest"
    
    if docker pull "$IMAGE_NAME" 2>/dev/null; then
        snyk container test "$IMAGE_NAME" --json > "$ARTIFACTS_DIR/snyk/docker-report.json" 2>&1 || {
            echo -e "${YELLOW}Warning: Docker scan completed with issues${NC}"
        }
        echo "✓ Docker scan complete"
    else
        echo -e "${YELLOW}Warning: Could not pull Docker image${NC}"
        echo '{"error": "Could not pull Docker image"}' > "$ARTIFACTS_DIR/snyk/docker-report.json"
    fi
else
    echo -e "${YELLOW}No Dockerfile found${NC}"
    echo '{"skipped": true, "reason": "No Dockerfile"}' > "$ARTIFACTS_DIR/snyk/docker-report.json"
fi

echo -e "${GREEN}3. Scanning JavaScript SDK...${NC}"
if [ -d "sdk/javascript" ]; then
    cd "$PROJECT_ROOT/sdk/javascript"
    
    if [ -f "package.json" ]; then
        snyk test --json > "$ARTIFACTS_DIR/snyk/sdk-js-report.json" 2>&1 || {
            echo -e "${YELLOW}Warning: JavaScript SDK scan completed with issues${NC}"
        }
        echo "✓ JavaScript SDK scan complete"
    else
        echo -e "${YELLOW}No package.json found in sdk/javascript${NC}"
        echo '{"skipped": true, "reason": "No package.json"}' > "$ARTIFACTS_DIR/snyk/sdk-js-report.json"
    fi
    
    cd "$PROJECT_ROOT"
else
    echo -e "${YELLOW}No JavaScript SDK found${NC}"
    echo '{"skipped": true, "reason": "No sdk/javascript directory"}' > "$ARTIFACTS_DIR/snyk/sdk-js-report.json"
fi

echo -e "${GREEN}4. Scanning Python SDK...${NC}"
if [ -d "sdk/python" ]; then
    cd "$PROJECT_ROOT/sdk/python"
    
    if [ -f "pyproject.toml" ]; then
        # Try to generate requirements.txt for the SDK
        pip freeze > requirements.txt 2>/dev/null || true
        
        if [ -f "requirements.txt" ]; then
            snyk test --file=requirements.txt --json > "$ARTIFACTS_DIR/snyk/sdk-python-report.json" 2>&1 || {
                echo -e "${YELLOW}Warning: Python SDK scan completed with issues${NC}"
            }
            echo "✓ Python SDK scan complete"
            rm -f requirements.txt
        else
            echo '{"error": "Could not generate requirements.txt"}' > "$ARTIFACTS_DIR/snyk/sdk-python-report.json"
        fi
    else
        echo -e "${YELLOW}No pyproject.toml found in sdk/python${NC}"
        echo '{"skipped": true, "reason": "No pyproject.toml"}' > "$ARTIFACTS_DIR/snyk/sdk-python-report.json"
    fi
    
    cd "$PROJECT_ROOT"
else
    echo -e "${YELLOW}No Python SDK found${NC}"
    echo '{"skipped": true, "reason": "No sdk/python directory"}' > "$ARTIFACTS_DIR/snyk/sdk-python-report.json"
fi

echo -e "${GREEN}5. Infrastructure as Code (IaC) scan...${NC}"
snyk iac test . --json > "$ARTIFACTS_DIR/snyk/iac-report.json" 2>&1 || {
    echo -e "${YELLOW}Warning: IaC scan completed with issues${NC}"
}
echo "✓ IaC scan complete"

echo ""
echo -e "${GREEN}=== Scan Complete ===${NC}"
echo "Artifacts saved to: $ARTIFACTS_DIR"
echo ""

# Generate the report
echo -e "${GREEN}Generating security report...${NC}"
if [ -f "$SECURITY_DIR/scripts/generate_report.py" ]; then
    python3 "$SECURITY_DIR/scripts/generate_report.py"
    echo "✓ Security report generated: $SECURITY_DIR/SECURITY_SCAN_REPORT.md"
else
    echo -e "${YELLOW}Warning: generate_report.py not found${NC}"
fi

echo ""
echo -e "${GREEN}Security scan finished successfully!${NC}"