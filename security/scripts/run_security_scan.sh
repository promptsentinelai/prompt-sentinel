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
mkdir -p "$ARTIFACTS_DIR"/{snyk,npm,go}

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

# Check for Snyk auth token
if [ -z "${SNYK_TOKEN}" ]; then
    # Try to load from .env file if exists
    if [ -f "$PROJECT_ROOT/.env" ]; then
        export $(grep -E '^SNYK_TOKEN=' "$PROJECT_ROOT/.env" | xargs) 2>/dev/null || true
    fi
fi

# Authenticate Snyk if token is provided
if [ -n "${SNYK_TOKEN}" ]; then
    echo -e "${GREEN}Using Snyk auth token from environment${NC}"
    export SNYK_TOKEN="${SNYK_TOKEN}"
else
    echo -e "${YELLOW}Warning: SNYK_TOKEN not set. Some features may require authentication.${NC}"
    echo "Set SNYK_TOKEN in your .env file or environment to avoid login prompts."
fi

echo -e "${YELLOW}[1/5] Scanning Python Dependencies...${NC}"
# Generate requirements.txt if needed
if [ ! -f requirements.txt ] || [ pyproject.toml -nt requirements.txt ]; then
    echo "Generating requirements.txt from pyproject.toml..."
    uv pip compile pyproject.toml -o requirements.txt || pip-compile pyproject.toml -o requirements.txt
fi

# Scan Python dependencies
snyk test --skip-unresolved --json > "$ARTIFACTS_DIR/snyk/python-report.json" 2>/dev/null || true
PYTHON_VULNS=$(jq '.vulnerabilities | length' "$ARTIFACTS_DIR/snyk/python-report.json" 2>/dev/null || echo "?")
echo -e "Python Dependencies: ${GREEN}$PYTHON_VULNS vulnerabilities${NC}"

echo -e "${YELLOW}[2/5] Scanning Docker Container...${NC}"
# Check if Docker image exists
if docker images | grep -q "promptsentinel-prompt-sentinel"; then
    snyk container test promptsentinel-prompt-sentinel:latest --json > "$ARTIFACTS_DIR/snyk/container-report.json" 2>/dev/null || true
    CONTAINER_VULNS=$(jq '.vulnerabilities | length' "$ARTIFACTS_DIR/snyk/container-report.json" 2>/dev/null || echo "?")
    echo -e "Docker Container: ${GREEN}$CONTAINER_VULNS vulnerabilities${NC}"
else
    echo -e "${YELLOW}Docker image not found, skipping container scan${NC}"
    echo '{"skipped": true, "reason": "Image not built"}' > "$ARTIFACTS_DIR/snyk/container-report.json"
fi

echo -e "${YELLOW}[3/5] Scanning Python SDK...${NC}"
if [ -d "sdk/python" ]; then
    cd sdk/python
    if [ -f "setup.py" ]; then
        # Create temporary requirements file for SDK
        python -c "
import re
with open('setup.py', 'r') as f:
    content = f.read()
    # Extract install_requires
    match = re.search(r'install_requires=\[(.*?)\]', content, re.DOTALL)
    if match:
        deps = match.group(1)
        deps = re.findall(r'\"([^\"]+)\"', deps)
        for dep in deps:
            print(dep)
" > temp_requirements.txt 2>/dev/null || echo "" > temp_requirements.txt
        
        if [ -s temp_requirements.txt ]; then
            snyk test --file=temp_requirements.txt --json > "$ARTIFACTS_DIR/snyk/sdk-python-report.json" 2>/dev/null || true
            rm -f temp_requirements.txt
            SDK_PYTHON_VULNS=$(jq '.vulnerabilities | length' "$ARTIFACTS_DIR/snyk/sdk-python-report.json" 2>/dev/null || echo "0")
        else
            echo '{"vulnerabilities": []}' > "$ARTIFACTS_DIR/snyk/sdk-python-report.json"
            SDK_PYTHON_VULNS="0"
        fi
    else
        echo '{"skipped": true, "reason": "No setup.py found"}' > "$ARTIFACTS_DIR/snyk/sdk-python-report.json"
        SDK_PYTHON_VULNS="N/A"
    fi
    cd "$PROJECT_ROOT"
    echo -e "Python SDK: ${GREEN}$SDK_PYTHON_VULNS vulnerabilities${NC}"
else
    echo -e "${YELLOW}Python SDK not found${NC}"
fi

echo -e "${YELLOW}[4/5] Scanning JavaScript SDK...${NC}"
if [ -d "sdk/javascript" ] && [ -f "sdk/javascript/package.json" ]; then
    cd sdk/javascript
    
    # Check if node_modules exists
    if [ ! -d "node_modules" ]; then
        echo "Installing JavaScript SDK dependencies..."
        npm install --silent 2>/dev/null || true
    fi
    
    # Run npm audit
    npm audit --json > "$ARTIFACTS_DIR/npm/audit-report.json" 2>/dev/null || true
    
    # Try Snyk if available
    snyk test --json > "$ARTIFACTS_DIR/snyk/sdk-js-report.json" 2>/dev/null || \
        echo '{"vulnerabilities": []}' > "$ARTIFACTS_DIR/snyk/sdk-js-report.json"
    
    JS_VULNS=$(jq '.vulnerabilities | length' "$ARTIFACTS_DIR/snyk/sdk-js-report.json" 2>/dev/null || echo "0")
    cd "$PROJECT_ROOT"
    echo -e "JavaScript SDK: ${GREEN}$JS_VULNS vulnerabilities${NC}"
else
    echo -e "${YELLOW}JavaScript SDK not found${NC}"
    echo '{"skipped": true, "reason": "SDK not found"}' > "$ARTIFACTS_DIR/snyk/sdk-js-report.json"
fi

echo -e "${YELLOW}[5/5] Scanning Go SDK...${NC}"
if [ -d "sdk/go" ] && [ -f "sdk/go/go.mod" ]; then
    cd sdk/go
    
    # Check for vulnerabilities using go mod
    if command -v go &> /dev/null; then
        # Go 1.18+ has built-in vulnerability checking
        go list -json -m all | jq -s '.' > "$ARTIFACTS_DIR/go/dependencies.json" 2>/dev/null || true
        
        # Try govulncheck if available
        if command -v govulncheck &> /dev/null; then
            govulncheck -json ./... > "$ARTIFACTS_DIR/go/vulncheck-report.json" 2>/dev/null || true
        fi
        
        # Try Snyk
        snyk test --json > "$ARTIFACTS_DIR/snyk/sdk-go-report.json" 2>/dev/null || \
            echo '{"vulnerabilities": []}' > "$ARTIFACTS_DIR/snyk/sdk-go-report.json"
        
        GO_VULNS=$(jq '.vulnerabilities | length' "$ARTIFACTS_DIR/snyk/sdk-go-report.json" 2>/dev/null || echo "0")
    else
        echo -e "${YELLOW}Go not installed, skipping Go SDK scan${NC}"
        echo '{"skipped": true, "reason": "Go not installed"}' > "$ARTIFACTS_DIR/snyk/sdk-go-report.json"
        GO_VULNS="N/A"
    fi
    cd "$PROJECT_ROOT"
    echo -e "Go SDK: ${GREEN}$GO_VULNS vulnerabilities${NC}"
else
    echo -e "${YELLOW}Go SDK not found${NC}"
    echo '{"skipped": true, "reason": "SDK not found"}' > "$ARTIFACTS_DIR/snyk/sdk-go-report.json"
fi

echo ""
echo -e "${GREEN}=== Scan Complete ===${NC}"
echo "Artifacts saved to: $ARTIFACTS_DIR"
echo ""

# Generate summary
echo -e "${YELLOW}Summary:${NC}"
echo "- Python Dependencies: $PYTHON_VULNS vulnerabilities"
echo "- Docker Container: $CONTAINER_VULNS vulnerabilities"
echo "- Python SDK: $SDK_PYTHON_VULNS vulnerabilities"
echo "- JavaScript SDK: $JS_VULNS vulnerabilities"
echo "- Go SDK: $GO_VULNS vulnerabilities"

# Generate the markdown report
echo ""
echo -e "${YELLOW}Generating markdown report...${NC}"
python3 "$SCRIPT_DIR/generate_report.py"

echo -e "${GREEN}Report generated: $SECURITY_DIR/SECURITY_SCAN_REPORT.md${NC}"