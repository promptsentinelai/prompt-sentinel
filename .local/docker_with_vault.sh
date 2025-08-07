#!/bin/bash
#
# Run Docker container with secrets from HashiCorp Vault
# This script fetches secrets from Vault and passes them to Docker
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🐳 Running PromptSentinel Docker with Vault Secrets${NC}"
echo "=================================================="

# Check if Vault is accessible
VAULT_ADDR="http://127.0.0.1:8200"
if ! curl -s "$VAULT_ADDR/v1/sys/health" > /dev/null 2>&1; then
    echo -e "${RED}❌ Vault is not running at $VAULT_ADDR${NC}"
    echo "Please start your personal vault first"
    exit 1
fi

# Get Vault token
VAULT_TOKEN=$(jq -r '.root_token' ~/dotfiles/.vault/personal/init.json)
if [ -z "$VAULT_TOKEN" ]; then
    echo -e "${RED}❌ Could not get Vault token${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Connected to Vault${NC}"

# Fetch secrets from Vault
export VAULT_ADDR="$VAULT_ADDR"
export VAULT_TOKEN="$VAULT_TOKEN"

echo "Fetching secrets from Vault..."

# Get secrets
ANTHROPIC_API_KEY=$(vault kv get -field=value secret/promptsentinel/api_keys/anthropic 2>/dev/null || echo "")
OPENAI_API_KEY=$(vault kv get -field=value secret/promptsentinel/api_keys/openai 2>/dev/null || echo "")
GEMINI_API_KEY=$(vault kv get -field=value secret/promptsentinel/api_keys/gemini 2>/dev/null || echo "")
SNYK_TOKEN=$(vault kv get -field=value secret/promptsentinel/api_keys/snyk 2>/dev/null || echo "")
REDIS_PASSWORD=$(vault kv get -field=value secret/promptsentinel/redis/password 2>/dev/null || echo "")

# Count loaded secrets
loaded=0
[ -n "$ANTHROPIC_API_KEY" ] && ((loaded++)) && echo "✓ Loaded ANTHROPIC_API_KEY"
[ -n "$OPENAI_API_KEY" ] && ((loaded++)) && echo "✓ Loaded OPENAI_API_KEY"
[ -n "$GEMINI_API_KEY" ] && ((loaded++)) && echo "✓ Loaded GEMINI_API_KEY"
[ -n "$SNYK_TOKEN" ] && ((loaded++)) && echo "✓ Loaded SNYK_TOKEN"
[ -n "$REDIS_PASSWORD" ] && ((loaded++)) && echo "✓ Loaded REDIS_PASSWORD"

echo -e "\n${GREEN}✓ Loaded $loaded secrets from Vault${NC}"

# Build image if needed
IMAGE_NAME="promptsentinel-vault:latest"
echo -e "\n${YELLOW}Building Docker image...${NC}"
docker build -t $IMAGE_NAME . || exit 1

# Run container with secrets from Vault
echo -e "\n${BLUE}Starting container with secrets...${NC}"

# Check if running interactively
if [ -t 0 ]; then
    # Interactive mode
    docker run --rm -it \
        --name prompt-sentinel-vault \
        -p 8090:8080 \
        --env-file .env \
        -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
        -e OPENAI_API_KEY="$OPENAI_API_KEY" \
        -e GEMINI_API_KEY="$GEMINI_API_KEY" \
        -e SNYK_TOKEN="$SNYK_TOKEN" \
        -e REDIS_PASSWORD="$REDIS_PASSWORD" \
        $IMAGE_NAME
else
    # Detached mode
    docker run --rm -d \
        --name prompt-sentinel-vault \
        -p 8090:8080 \
        --env-file .env \
        -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
        -e OPENAI_API_KEY="$OPENAI_API_KEY" \
        -e GEMINI_API_KEY="$GEMINI_API_KEY" \
        -e SNYK_TOKEN="$SNYK_TOKEN" \
        -e REDIS_PASSWORD="$REDIS_PASSWORD" \
        $IMAGE_NAME
    
    echo -e "${GREEN}✓ Container started in background${NC}"
    echo "Container name: prompt-sentinel-vault"
    echo "Port: 8090"
    echo ""
    echo "Check logs: docker logs -f prompt-sentinel-vault"
    echo "Stop: docker stop prompt-sentinel-vault"
fi