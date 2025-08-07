#!/usr/bin/env python3
"""
Local Vault integration for PromptSentinel.
This script fetches secrets from HashiCorp Vault and creates/updates the .env file.

Usage:
    python .local/vault_loader.py
    
This file is NOT part of the public repository and should remain local only.
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional

# Configuration
VAULT_ADDR = os.getenv("VAULT_PERSONAL_ADDR", "http://127.0.0.1:8200")
VAULT_PATH_PREFIX = "secret/promptsentinel"
DOTFILES_PATH = Path.home() / "dotfiles" / ".vault" / "personal" / "init.json"
ENV_FILE_PATH = Path(__file__).parent.parent / ".env"


def get_vault_token() -> Optional[str]:
    """Get Vault token from dotfiles."""
    if not DOTFILES_PATH.exists():
        print(f"Error: Vault init file not found at {DOTFILES_PATH}")
        return None
    
    try:
        with open(DOTFILES_PATH, 'r') as f:
            data = json.load(f)
            return data.get('root_token')
    except (json.JSONDecodeError, KeyError) as e:
        print(f"Error reading Vault token: {e}")
        return None


def check_vault_status() -> bool:
    """Check if Vault is running and unsealed."""
    try:
        result = subprocess.run(
            ["curl", "-s", f"{VAULT_ADDR}/v1/sys/health"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            health = json.loads(result.stdout)
            if health.get('sealed'):
                print("Vault is sealed. Attempting to unseal...")
                unseal_result = subprocess.run(
                    ["/Users/rhoska/Code/Tools/macos-local-vaults/scripts/unseal.sh", "personal"],
                    capture_output=True,
                    text=True
                )
                if unseal_result.returncode != 0:
                    print("Failed to unseal vault")
                    return False
            return True
    except Exception as e:
        print(f"Error checking Vault status: {e}")
    return False


def fetch_secret_from_vault(token: str, path: str) -> Optional[str]:
    """Fetch a secret value from Vault."""
    full_path = f"{VAULT_PATH_PREFIX}/{path}"
    cmd = [
        "vault", "kv", "get",
        "-field=value",
        full_path
    ]
    
    env = os.environ.copy()
    env["VAULT_ADDR"] = VAULT_ADDR
    env["VAULT_TOKEN"] = token
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env
        )
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            # Secret might not exist yet
            return None
    except Exception as e:
        print(f"Error fetching {path}: {e}")
        return None


def store_secret_in_vault(token: str, path: str, value: str) -> bool:
    """Store a secret in Vault."""
    full_path = f"{VAULT_PATH_PREFIX}/{path}"
    cmd = [
        "vault", "kv", "put",
        full_path,
        f"value={value}"
    ]
    
    env = os.environ.copy()
    env["VAULT_ADDR"] = VAULT_ADDR
    env["VAULT_TOKEN"] = token
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env
        )
        return result.returncode == 0
    except Exception as e:
        print(f"Error storing {path}: {e}")
        return False


def load_current_env() -> Dict[str, str]:
    """Load current .env file."""
    env_vars = {}
    if ENV_FILE_PATH.exists():
        with open(ENV_FILE_PATH, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    env_vars[key.strip()] = value.strip()
    return env_vars


def update_env_file(secrets: Dict[str, str]):
    """Update .env file with secrets from Vault, preserving non-secret configs."""
    # Read existing .env file to preserve structure and non-secret values
    lines = []
    if ENV_FILE_PATH.exists():
        with open(ENV_FILE_PATH, 'r') as f:
            lines = f.readlines()
    
    # Update lines with new secret values
    updated = set()
    new_lines = []
    
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith('#') and '=' in stripped:
            key = stripped.split('=', 1)[0].strip()
            if key in secrets:
                new_lines.append(f"{key}={secrets[key]}\n")
                updated.add(key)
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)
    
    # Add any new secrets that weren't in the file
    for key, value in secrets.items():
        if key not in updated:
            new_lines.append(f"{key}={value}\n")
    
    # Write updated .env file
    with open(ENV_FILE_PATH, 'w') as f:
        f.writelines(new_lines)
    
    print(f"✅ Updated .env file with {len(secrets)} secrets from Vault")


def main():
    """Main function to sync secrets between Vault and .env file."""
    print("🔐 PromptSentinel Vault Loader")
    print(f"   Vault: {VAULT_ADDR}")
    print(f"   Path: {VAULT_PATH_PREFIX}/")
    print()
    
    # Check Vault status
    if not check_vault_status():
        print("❌ Vault is not available")
        return 1
    
    # Get Vault token
    token = get_vault_token()
    if not token:
        print("❌ Could not get Vault token")
        return 1
    
    # Define secret mappings (vault_path: env_var_name)
    secret_mappings = {
        "api_keys/anthropic": "ANTHROPIC_API_KEY",
        "api_keys/openai": "OPENAI_API_KEY",
        "api_keys/gemini": "GEMINI_API_KEY",
        "api_keys/snyk": "SNYK_TOKEN",
        "redis/password": "REDIS_PASSWORD",
    }
    
    # Load current env for migration if needed
    current_env = load_current_env()
    
    # Fetch or migrate secrets
    secrets = {}
    for vault_path, env_key in secret_mappings.items():
        print(f"📥 Fetching {env_key}...", end=" ")
        
        # Try to fetch from Vault
        value = fetch_secret_from_vault(token, vault_path)
        
        if value:
            secrets[env_key] = value
            print("✅ Found in Vault")
        elif env_key in current_env and current_env[env_key] and not current_env[env_key].startswith("your-"):
            # Migrate from .env to Vault if not already there
            print("📤 Migrating to Vault...", end=" ")
            if store_secret_in_vault(token, vault_path, current_env[env_key]):
                secrets[env_key] = current_env[env_key]
                print("✅ Migrated")
            else:
                print("❌ Failed to migrate")
        else:
            print("⚠️  Not found (set manually in Vault)")
    
    # Update .env file
    if secrets:
        update_env_file(secrets)
    else:
        print("\n⚠️  No secrets found to update")
    
    print("\n✨ Done! Your .env file is synced with Vault")
    print("\nTo manually add secrets to Vault, use:")
    print(f"  vaultx personal kv put {VAULT_PATH_PREFIX}/api_keys/anthropic value=<your-key>")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())