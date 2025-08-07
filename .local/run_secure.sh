#!/bin/bash
#
# Secure launcher for PromptSentinel with HashiCorp Vault
# This script loads secrets from Vault without writing them to disk
#
# Usage:
#   .local/run_secure.sh         # Run the application
#   .local/run_secure.sh check   # Check available secrets
#   .local/run_secure.sh shell   # Start shell with secrets loaded
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Change to project root
cd "$PROJECT_ROOT"

# Run the secure vault loader
exec python3 "$SCRIPT_DIR/vault_secure.py" "$@"