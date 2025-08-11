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

# Check for Snyk auth token - prefer environment, then Vault, then .env
if [ -z "${SNYK_TOKEN}" ]; then
    # Try to load from Vault first if available
    if [ -f "$PROJECT_ROOT/.local/vault_secure.py" ]; then
        echo -e "${GREEN}Attempting to load SNYK_TOKEN from Vault...${NC}"
        VAULT_TOKEN=$(python3 "$PROJECT_ROOT/.local/vault_secure.py" get-secret api_keys/snyk 2>/dev/null)
        if [ -n "${VAULT_TOKEN}" ]; then
            export SNYK_TOKEN="${VAULT_TOKEN}"
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

# Check for Snyk org ID - prefer environment, then Vault, then .env
if [ -z "${SNYK_ORG_ID}" ]; then
    # Try to load from Vault first if available
    if [ -f "$PROJECT_ROOT/.local/vault_secure.py" ]; then
        echo -e "${GREEN}Attempting to load SNYK_ORG_ID from Vault...${NC}"
        VAULT_ORG_ID=$(python3 "$PROJECT_ROOT/.local/vault_secure.py" get-secret api_keys/snyk_org 2>/dev/null)
        if [ -n "${VAULT_ORG_ID}" ]; then
            export SNYK_ORG_ID="${VAULT_ORG_ID}"
            echo -e "${GREEN}✓ SNYK_ORG_ID loaded from Vault${NC}"
        fi
    fi
    
    # Fallback to .env file if still not set
    if [ -z "${SNYK_ORG_ID}" ] && [ -f "$PROJECT_ROOT/.env" ]; then
        echo -e "${GREEN}Loading SNYK_ORG_ID from .env file...${NC}"
        export $(grep -E '^SNYK_ORG_ID=' "$PROJECT_ROOT/.env" | xargs) 2>/dev/null || true
        if [ -n "${SNYK_ORG_ID}" ]; then
            echo -e "${GREEN}✓ SNYK_ORG_ID loaded from .env${NC}"
        fi
    fi
fi

# Authenticate Snyk if token is provided
if [ -n "${SNYK_TOKEN}" ]; then
    echo -e "${GREEN}✓ Snyk authentication configured${NC}"
    export SNYK_TOKEN="${SNYK_TOKEN}"
else
    echo -e "${YELLOW}Warning: SNYK_TOKEN not set. Some features may require authentication.${NC}"
    echo "Set SNYK_TOKEN in Vault or .env file to avoid login prompts."
fi

echo -e "${YELLOW}[1/6] Scanning Python Dependencies...${NC}"
# Generate requirements.txt if needed
if [ ! -f requirements.txt ] || [ pyproject.toml -nt requirements.txt ]; then
    echo "Generating requirements.txt from pyproject.toml..."
    uv pip compile pyproject.toml -o requirements.txt || pip-compile pyproject.toml -o requirements.txt
fi

# Scan Python dependencies
snyk test --skip-unresolved --json > "$ARTIFACTS_DIR/snyk/python-report.json" 2>/dev/null || true
PYTHON_VULNS=$(jq '.vulnerabilities | length' "$ARTIFACTS_DIR/snyk/python-report.json" 2>/dev/null || echo "?")
echo -e "Python Dependencies: ${GREEN}$PYTHON_VULNS vulnerabilities${NC}"

echo -e "${YELLOW}[2/6] Scanning Docker Container...${NC}"
# Check if Docker image exists
if docker images | grep -q "promptsentinel-prompt-sentinel"; then
    snyk container test promptsentinel-prompt-sentinel:latest --json > "$ARTIFACTS_DIR/snyk/container-report.json" 2>/dev/null || true
    CONTAINER_VULNS=$(jq '.vulnerabilities | length' "$ARTIFACTS_DIR/snyk/container-report.json" 2>/dev/null || echo "?")
    echo -e "Docker Container: ${GREEN}$CONTAINER_VULNS vulnerabilities${NC}"
else
    echo -e "${YELLOW}Docker image not found, skipping container scan${NC}"
    echo '{"skipped": true, "reason": "Image not built"}' > "$ARTIFACTS_DIR/snyk/container-report.json"
fi

echo -e "${YELLOW}[3/6] Scanning Python SDK...${NC}"
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

echo -e "${YELLOW}[4/6] Scanning JavaScript SDK...${NC}"
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

echo -e "${YELLOW}[5/6] Scanning Go SDK...${NC}"
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

echo -e "${YELLOW}[6/6] Generating Software Bill of Materials (SBOM)...${NC}"
cd "$PROJECT_ROOT"

# Create SBOM directory
mkdir -p "$ARTIFACTS_DIR/sbom"

# Generate SBOM for Python project
echo "Generating SBOM for Python dependencies..."
if [ -n "${SNYK_TOKEN}" ] && [ -n "${SNYK_ORG_ID}" ]; then
    # Generate SBOM in SPDX format with org ID
    snyk sbom --org="${SNYK_ORG_ID}" --format=spdx2.3+json --file=requirements.txt > "$ARTIFACTS_DIR/sbom/python-sbom.spdx.json" 2>/dev/null || {
        echo -e "${YELLOW}Warning: Could not generate SPDX SBOM, trying CycloneDX format...${NC}"
        snyk sbom --org="${SNYK_ORG_ID}" --format=cyclonedx1.4+json --file=requirements.txt > "$ARTIFACTS_DIR/sbom/python-sbom.cdx.json" 2>/dev/null || {
            echo -e "${YELLOW}Warning: SBOM generation failed${NC}"
            echo '{"error": "SBOM generation failed"}' > "$ARTIFACTS_DIR/sbom/python-sbom.json"
        }
    }
elif [ -n "${SNYK_TOKEN}" ]; then
    # Try without org ID (may fail)
    snyk sbom --format=cyclonedx1.4+json --file=requirements.txt > "$ARTIFACTS_DIR/sbom/python-sbom.cdx.json" 2>/dev/null || {
        echo -e "${YELLOW}Warning: SBOM generation requires SNYK_ORG_ID${NC}"
        echo '{"error": "Org ID required"}' > "$ARTIFACTS_DIR/sbom/python-sbom.json"
    }
else
    echo -e "${YELLOW}Warning: SBOM generation requires SNYK_TOKEN and SNYK_ORG_ID${NC}"
    echo '{"error": "Authentication required"}' > "$ARTIFACTS_DIR/sbom/python-sbom.json"
fi

# Generate SBOM for Docker container if image exists
if docker images | grep -q "promptsentinel-prompt-sentinel"; then
    echo "Generating SBOM for Docker container..."
    if [ -n "${SNYK_ORG_ID}" ]; then
        snyk sbom --org="${SNYK_ORG_ID}" --format=cyclonedx1.4+json --docker promptsentinel-prompt-sentinel:latest > "$ARTIFACTS_DIR/sbom/container-sbom.cdx.json" 2>/dev/null || {
            echo -e "${YELLOW}Warning: Could not generate container SBOM${NC}"
            echo '{"error": "Container SBOM generation failed"}' > "$ARTIFACTS_DIR/sbom/container-sbom.json"
        }
    else
        echo -e "${YELLOW}Skipping container SBOM (requires SNYK_ORG_ID)${NC}"
        echo '{"error": "Org ID required"}' > "$ARTIFACTS_DIR/sbom/container-sbom.json"
    fi
fi

# Generate SBOM for JavaScript SDK if exists
if [ -d "sdk/javascript" ] && [ -f "sdk/javascript/package.json" ]; then
    echo "Generating SBOM for JavaScript SDK..."
    cd sdk/javascript
    if [ -n "${SNYK_ORG_ID}" ]; then
        snyk sbom --org="${SNYK_ORG_ID}" --format=cyclonedx1.4+json > "$ARTIFACTS_DIR/sbom/sdk-js-sbom.cdx.json" 2>/dev/null || {
            echo -e "${YELLOW}Warning: Could not generate JavaScript SDK SBOM${NC}"
            echo '{"error": "JS SDK SBOM generation failed"}' > "$ARTIFACTS_DIR/sbom/sdk-js-sbom.json"
        }
    else
        echo '{"error": "Org ID required"}' > "$ARTIFACTS_DIR/sbom/sdk-js-sbom.json"
    fi
    cd "$PROJECT_ROOT"
fi

# Generate SBOM for Go SDK if exists
if [ -d "sdk/go" ] && [ -f "sdk/go/go.mod" ]; then
    echo "Generating SBOM for Go SDK..."
    cd sdk/go
    if [ -n "${SNYK_ORG_ID}" ]; then
        snyk sbom --org="${SNYK_ORG_ID}" --format=cyclonedx1.4+json > "$ARTIFACTS_DIR/sbom/sdk-go-sbom.cdx.json" 2>/dev/null || {
            echo -e "${YELLOW}Warning: Could not generate Go SDK SBOM${NC}"
            echo '{"error": "Go SDK SBOM generation failed"}' > "$ARTIFACTS_DIR/sbom/sdk-go-sbom.json"
        }
    else
        echo '{"error": "Org ID required"}' > "$ARTIFACTS_DIR/sbom/sdk-go-sbom.json"
    fi
    cd "$PROJECT_ROOT"
fi

# Generate a summary of SBOMs
echo "Creating SBOM summary..."
python3 -c "
import json
import os
from pathlib import Path

sbom_dir = Path('$ARTIFACTS_DIR/sbom')
summary = {
    'generated_at': '$(date -u +"%Y-%m-%dT%H:%M:%SZ")',
    'sboms': []
}

for sbom_file in sbom_dir.glob('*.json'):
    if sbom_file.name.endswith(('.spdx.json', '.cdx.json')):
        try:
            with open(sbom_file) as f:
                data = json.load(f)
                sbom_info = {
                    'name': sbom_file.stem,
                    'format': 'SPDX' if 'spdx' in sbom_file.suffix else 'CycloneDX',
                    'file': sbom_file.name,
                    'size_bytes': sbom_file.stat().st_size
                }
                
                # Extract component count based on format
                if 'components' in data:  # CycloneDX
                    sbom_info['component_count'] = len(data.get('components', []))
                elif 'packages' in data:  # SPDX
                    sbom_info['package_count'] = len(data.get('packages', []))
                
                summary['sboms'].append(sbom_info)
        except Exception as e:
            print(f'Error processing {sbom_file}: {e}')

# Write summary
with open(sbom_dir / 'sbom-summary.json', 'w') as f:
    json.dump(summary, f, indent=2)

print(f'SBOM Summary: {len(summary[\"sboms\"])} SBOMs generated')
for sbom in summary['sboms']:
    print(f\"  - {sbom['name']}: {sbom.get('component_count', sbom.get('package_count', 'N/A'))} components\")
" 2>/dev/null || echo -e "${YELLOW}Could not create SBOM summary${NC}"

# Check if any SBOMs were generated
SBOM_COUNT=$(ls -1 "$ARTIFACTS_DIR/sbom"/*.json 2>/dev/null | wc -l)
if [ "$SBOM_COUNT" -gt 0 ]; then
    echo -e "${GREEN}Generated $SBOM_COUNT SBOM file(s)${NC}"
else
    echo -e "${YELLOW}No SBOMs generated (authentication may be required)${NC}"
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