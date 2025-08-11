#!/usr/bin/env python3
"""
HashiCorp Vault integration example for PromptSentinel.

This example demonstrates how to securely fetch API keys and other secrets
from HashiCorp Vault instead of storing them in .env files.

Prerequisites:
    pip install hvac python-dotenv

Usage:
    1. Start Vault: vault server -dev
    2. Store secrets: vault kv put secret/promptsentinel/api_keys anthropic=key1 openai=key2
    3. Run this script: python vault_example.py
"""

import os
import sys

try:
    import hvac
except ImportError:
    print("Please install hvac: pip install hvac")
    sys.exit(1)


class VaultSecretManager:
    """Manage secrets using HashiCorp Vault."""

    def __init__(
        self, vault_addr: str = None, vault_token: str = None, mount_point: str = "secret"
    ):
        """
        Initialize Vault client.

        Args:
            vault_addr: Vault server address (default: VAULT_ADDR env var)
            vault_token: Authentication token (default: VAULT_TOKEN env var)
            mount_point: KV secrets engine mount point
        """
        self.vault_addr = vault_addr or os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
        self.mount_point = mount_point

        # Initialize client
        self.client = hvac.Client(url=self.vault_addr)

        # Authenticate
        token = vault_token or os.getenv("VAULT_TOKEN")
        if token:
            self.client.token = token
        else:
            print("Warning: No VAULT_TOKEN provided. Attempting to read from ~/.vault-token")
            self._read_token_file()

    def _read_token_file(self):
        """Read token from ~/.vault-token file (created by vault login)."""
        token_file = os.path.expanduser("~/.vault-token")
        if os.path.exists(token_file):
            with open(token_file) as f:
                self.client.token = f.read().strip()

    def is_authenticated(self) -> bool:
        """Check if client is authenticated."""
        try:
            return self.client.is_authenticated()
        except Exception:
            return False

    def get_secret(self, path: str) -> dict | None:
        """
        Fetch a secret from Vault.

        Args:
            path: Secret path (e.g., "promptsentinel/api_keys")

        Returns:
            Dictionary of secret data or None if error
        """
        if not self.is_authenticated():
            print("Error: Not authenticated to Vault")
            return None

        try:
            response = self.client.secrets.kv.v2.read_secret_version(
                path=path, mount_point=self.mount_point
            )
            return response["data"]["data"]
        except hvac.exceptions.InvalidPath:
            print(f"Secret not found at path: {path}")
            return None
        except Exception as e:
            print(f"Error fetching secret: {e}")
            return None

    def store_secret(self, path: str, data: dict) -> bool:
        """
        Store a secret in Vault.

        Args:
            path: Secret path
            data: Dictionary of secret data

        Returns:
            True if successful
        """
        if not self.is_authenticated():
            print("Error: Not authenticated to Vault")
            return False

        try:
            self.client.secrets.kv.v2.create_or_update_secret(
                path=path, secret=data, mount_point=self.mount_point
            )
            return True
        except Exception as e:
            print(f"Error storing secret: {e}")
            return False

    def load_promptsentinel_secrets(self) -> bool:
        """
        Load PromptSentinel secrets from Vault to environment variables.

        Returns:
            True if successful
        """
        # Define secret paths and their environment variable mappings
        secret_mappings = {
            "promptsentinel/api_keys": {
                "anthropic": "ANTHROPIC_API_KEY",
                "openai": "OPENAI_API_KEY",
                "gemini": "GEMINI_API_KEY",
                "snyk": "SNYK_TOKEN",
            },
            "promptsentinel/redis": {"password": "REDIS_PASSWORD"},
        }

        success = True
        for path, mappings in secret_mappings.items():
            secrets = self.get_secret(path)
            if secrets:
                for secret_key, env_var in mappings.items():
                    if secret_key in secrets:
                        os.environ[env_var] = secrets[secret_key]
                        print(f"✓ Loaded {env_var} from Vault")
                    else:
                        print(f"✗ {secret_key} not found in {path}")
                        success = False
            else:
                print(f"✗ No secrets found at {path}")
                success = False

        return success


def example_usage():
    """Demonstrate Vault integration."""
    print("PromptSentinel Vault Integration Example")
    print("=" * 40)

    # Initialize Vault client
    vault = VaultSecretManager()

    # Check authentication
    if not vault.is_authenticated():
        print("\n❌ Not authenticated to Vault!")
        print("\nTo authenticate:")
        print("  1. Set VAULT_TOKEN environment variable")
        print("  2. Or run: vault login")
        return

    print(f"\n✅ Connected to Vault at {vault.vault_addr}")

    # Example 1: Store secrets (first time setup)
    print("\n1. Storing example secrets...")
    example_secrets = {
        "anthropic": "sk-ant-example-key",
        "openai": "sk-example-key",
        "gemini": "AIza-example-key",
    }

    if vault.store_secret("promptsentinel/api_keys", example_secrets):
        print("   ✓ Stored API keys in Vault")

    # Example 2: Fetch specific secret
    print("\n2. Fetching specific secret...")
    api_keys = vault.get_secret("promptsentinel/api_keys")
    if api_keys:
        print(f"   Found {len(api_keys)} API keys")
        for key in api_keys:
            print(f"   - {key}: {'*' * 10}{api_keys[key][-4:]}")

    # Example 3: Load all secrets to environment
    print("\n3. Loading secrets to environment...")
    if vault.load_promptsentinel_secrets():
        print("\n✅ All secrets loaded successfully!")

        # Verify environment variables
        print("\nEnvironment variables set:")
        for var in ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY"]:
            value = os.getenv(var)
            if value:
                print(f"  {var}: {'*' * 10}{value[-4:]}")


def integration_with_settings():
    """Show how to integrate with PromptSentinel settings."""
    print("\nIntegration with PromptSentinel Settings")
    print("=" * 40)

    # Load secrets from Vault before initializing settings
    vault = VaultSecretManager()
    vault.load_promptsentinel_secrets()

    # Now import and use settings (which will read from environment)
    try:
        from prompt_sentinel.config.settings import Settings

        settings = Settings()

        print("\nSettings loaded with Vault secrets:")
        print(f"  Anthropic API Key: {'✓' if settings.anthropic_api_key else '✗'}")
        print(f"  OpenAI API Key: {'✓' if settings.openai_api_key else '✗'}")
        print(f"  Gemini API Key: {'✓' if settings.gemini_api_key else '✗'}")
    except ImportError:
        print("\nTo use with PromptSentinel, run this from the project root:")
        print("  python examples/secret_management/vault_example.py")


if __name__ == "__main__":
    example_usage()
    print("\n" + "=" * 40)
    integration_with_settings()
