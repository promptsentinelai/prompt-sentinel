#!/usr/bin/env python3
"""
Secure Vault integration for PromptSentinel.
This script loads secrets from HashiCorp Vault directly to memory/environment.
Secrets are NEVER written to disk.

Usage:
    python .local/vault_secure.py [command]

    Commands:
        run     - Load secrets and run the application
        check   - Check what secrets are available in Vault
        shell   - Load secrets and start an interactive shell
"""

import json
import os
import subprocess
import sys
from pathlib import Path

# Configuration
VAULT_ADDR = os.getenv("VAULT_PERSONAL_ADDR", "http://127.0.0.1:8200")
VAULT_PATH_PREFIX = "secret/promptsentinel"
DOTFILES_PATH = Path.home() / "dotfiles" / ".vault" / "personal" / "init.json"

# Define secret mappings (vault_path: env_var_name)
SECRET_MAPPINGS = {
    "api_keys/anthropic": "ANTHROPIC_API_KEY",
    "api_keys/openai": "OPENAI_API_KEY",
    "api_keys/gemini": "GEMINI_API_KEY",
    "api_keys/snyk": "SNYK_TOKEN",
    "api_keys/snyk_org": "SNYK_ORG_ID",
    "redis/password": "REDIS_PASSWORD",
}


def get_vault_token() -> str | None:
    """Get Vault token from dotfiles."""
    if not DOTFILES_PATH.exists():
        print(f"Error: Vault init file not found at {DOTFILES_PATH}")
        return None

    try:
        with open(DOTFILES_PATH) as f:
            data = json.load(f)
            return data.get("root_token")
    except (json.JSONDecodeError, KeyError) as e:
        print(f"Error reading Vault token: {e}")
        return None


def check_vault_status() -> bool:
    """Check if Vault is running and unsealed."""
    try:
        result = subprocess.run(
            ["curl", "-s", f"{VAULT_ADDR}/v1/sys/health"], capture_output=True, text=True
        )
        if result.returncode == 0:
            health = json.loads(result.stdout)
            if health.get("sealed"):
                print("Vault is sealed. Attempting to unseal...")
                unseal_result = subprocess.run(
                    ["/Users/rhoska/Code/Tools/macos-local-vaults/scripts/unseal.sh", "personal"],
                    capture_output=True,
                    text=True,
                )
                if unseal_result.returncode != 0:
                    print("Failed to unseal vault")
                    return False
            return True
    except Exception as e:
        print(f"Error checking Vault status: {e}")
    return False


def fetch_secret_from_vault(token: str, path: str) -> str | None:
    """Fetch a secret value from Vault."""
    full_path = f"{VAULT_PATH_PREFIX}/{path}"
    cmd = ["vault", "kv", "get", "-field=value", full_path]

    env = os.environ.copy()
    env["VAULT_ADDR"] = VAULT_ADDR
    env["VAULT_TOKEN"] = token

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception as e:
        print(f"Error fetching {path}: {e}")
    return None


def load_secrets_to_env(token: str) -> dict[str, str]:
    """
    Load all secrets from Vault directly to environment variables.
    Returns dict of loaded secrets for verification (without exposing values).
    """
    loaded = {}

    for vault_path, env_key in SECRET_MAPPINGS.items():
        value = fetch_secret_from_vault(token, vault_path)
        if value:
            os.environ[env_key] = value
            # Store masked value for display
            if len(value) > 8:
                loaded[env_key] = f"***{value[-4:]}"
            else:
                loaded[env_key] = "****"
            print(f"✓ Loaded {env_key} from Vault")
        else:
            print(f"⚠ {env_key} not found in Vault")

    return loaded


def load_config_from_env_file():
    """Load non-sensitive configuration from .env file."""
    env_file = Path(__file__).parent.parent / ".env"
    if not env_file.exists():
        return

    # List of sensitive keys that should NEVER be loaded from .env
    SENSITIVE_KEYS = {
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "GEMINI_API_KEY",
        "SNYK_TOKEN",
        "REDIS_PASSWORD",
    }

    loaded_configs = []
    with open(env_file) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                key = key.strip()

                # Only load non-sensitive configuration
                if key not in SENSITIVE_KEYS:
                    os.environ[key] = value.strip()
                    loaded_configs.append(key)

    if loaded_configs:
        print(f"✓ Loaded {len(loaded_configs)} config values from .env")


def run_application():
    """Run the PromptSentinel application with loaded secrets."""
    print("\n🚀 Starting PromptSentinel with secrets from Vault...")
    print("-" * 50)

    # Run uvicorn
    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "prompt_sentinel.main:app",
        "--reload",
        "--host",
        os.getenv("API_HOST", "0.0.0.0"),
        "--port",
        os.getenv("API_PORT", "8080"),
    ]

    try:
        # Execute and replace current process
        os.execvp(cmd[0], cmd)
    except KeyboardInterrupt:
        print("\n\n✓ Application stopped")
    except Exception as e:
        print(f"\n❌ Error running application: {e}")
        sys.exit(1)


def run_shell():
    """Start an interactive shell with secrets loaded."""
    print("\n🐚 Starting shell with secrets loaded...")
    print("   Secrets are in environment variables")
    print("   Type 'exit' to quit\n")

    shell = os.environ.get("SHELL", "/bin/bash")
    os.execvp(shell, [shell])


def check_secrets(token: str):
    """Check what secrets are available in Vault without loading them."""
    print("\n🔍 Checking secrets in Vault...")
    print(f"   Path: {VAULT_PATH_PREFIX}/\n")

    for vault_path, env_key in SECRET_MAPPINGS.items():
        value = fetch_secret_from_vault(token, vault_path)
        if value:
            masked = f"***{value[-4:]}" if len(value) > 8 else "****"
            print(f"✓ {env_key:30} {masked}")
        else:
            print(f"✗ {env_key:30} (not set)")


def main():
    """Main entry point."""
    # Parse command
    command = sys.argv[1] if len(sys.argv) > 1 else "run"

    # Only print header for interactive commands
    if command != "get-secret":
        print("🔐 PromptSentinel Secure Vault Loader")
        print("=" * 50)

    # Check Vault status
    if not check_vault_status():
        if command != "get-secret":
            print("❌ Vault is not available")
        else:
            print("Error: Vault is not available", file=sys.stderr)
        return 1

    # Get Vault token
    token = get_vault_token()
    if not token:
        if command != "get-secret":
            print("❌ Could not get Vault token")
        else:
            print("Error: Could not get Vault token", file=sys.stderr)
        return 1

    if command != "get-secret":
        print(f"✓ Connected to Vault at {VAULT_ADDR}\n")

    if command == "check":
        check_secrets(token)
    elif command == "shell":
        # Load config from .env (non-sensitive only)
        load_config_from_env_file()
        # Load secrets from Vault
        loaded = load_secrets_to_env(token)
        print(f"\n✓ Loaded {len(loaded)} secrets from Vault")
        run_shell()
    elif command == "run":
        # Load config from .env (non-sensitive only)
        load_config_from_env_file()
        # Load secrets from Vault
        loaded = load_secrets_to_env(token)
        print(f"\n✓ Loaded {len(loaded)} secrets from Vault")
        run_application()
    elif command == "get-secret":
        # Get a specific secret value (for use in scripts)
        # Suppress all output except the secret value
        if len(sys.argv) < 3:
            print("Error: get-secret requires a vault path", file=sys.stderr)
            return 1
        vault_path = sys.argv[2]

        # Map the vault path to env key
        env_key = SECRET_MAPPINGS.get(vault_path)
        if not env_key:
            print(f"Error: Unknown vault path: {vault_path}", file=sys.stderr)
            return 1

        value = fetch_secret_from_vault(token, vault_path)
        if value:
            # Output only the value (for script consumption)
            print(value, end="")
            return 0
        else:
            print(f"Error: Could not fetch secret from {vault_path}", file=sys.stderr)
            return 1
    else:
        print(f"Unknown command: {command}")
        print("\nAvailable commands:")
        print("  run        - Load secrets and run application (default)")
        print("  check      - Check available secrets without loading")
        print("  get-secret - Get a specific secret value (for scripts)")
        return 1

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n✓ Stopped")
        sys.exit(0)
