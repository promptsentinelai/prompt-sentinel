#!/bin/bash
#
# Setup script for local Vault integration with PromptSentinel
# This script initializes and syncs secrets between Vault and .env
#
# Usage: .local/setup_vault.sh
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
VAULT_ADDR="http://127.0.0.1:8200"
VAULT_PATH_PREFIX="secret/promptsentinel"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo -e "${BLUE}🔐 PromptSentinel Vault Setup${NC}"
echo "================================"
echo ""

# Check if Vault is accessible
echo -e "${YELLOW}Checking Vault status...${NC}"
if ! curl -s "$VAULT_ADDR/v1/sys/health" > /dev/null 2>&1; then
    echo -e "${RED}❌ Vault is not running at $VAULT_ADDR${NC}"
    echo "Please start your personal vault first:"
    echo "  cd ~/Code/Tools/macos-local-vaults"
    echo "  ./personal/start.sh"
    exit 1
fi

# Check if vault is sealed
SEALED=$(curl -s "$VAULT_ADDR/v1/sys/health" | jq -r '.sealed')
if [ "$SEALED" = "true" ]; then
    echo -e "${YELLOW}Vault is sealed. Attempting to unseal...${NC}"
    /Users/rhoska/Code/Tools/macos-local-vaults/scripts/unseal.sh personal
fi

echo -e "${GREEN}✅ Vault is running and unsealed${NC}"
echo ""

# Run the Python vault loader
echo -e "${YELLOW}Syncing secrets from Vault...${NC}"
python3 "$SCRIPT_DIR/vault_loader.py"

echo ""
echo -e "${GREEN}✨ Setup complete!${NC}"
echo ""
echo "Your secrets are now managed by HashiCorp Vault."
echo ""
echo -e "${BLUE}Quick Reference:${NC}"
echo "  View secrets:    vaultx personal kv list $VAULT_PATH_PREFIX/"
echo "  Get a secret:    vaultx personal kv get $VAULT_PATH_PREFIX/api_keys/anthropic"
echo "  Update a secret: vaultx personal kv put $VAULT_PATH_PREFIX/api_keys/anthropic value=<new-key>"
echo "  Sync to .env:    .local/setup_vault.sh"
echo ""
echo -e "${YELLOW}Note:${NC} The .env file is generated from Vault and should not be edited directly."