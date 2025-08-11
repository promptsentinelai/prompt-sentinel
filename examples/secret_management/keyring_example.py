#!/usr/bin/env python3
"""
Python Keyring integration example for PromptSentinel.

This example demonstrates how to use the system keyring (macOS Keychain,
Windows Credential Manager, Linux Secret Service) to securely store API keys.

Prerequisites:
    pip install keyring

Usage:
    1. First time: python keyring_example.py --store
    2. Load secrets: python keyring_example.py
"""

import argparse
import os
import sys

try:
    import keyring
    from keyring import errors
except ImportError:
    print("Please install keyring: pip install keyring")
    sys.exit(1)


class KeyringSecretManager:
    """Manage secrets using the system keyring."""

    SERVICE_NAME = "promptsentinel"

    # Define all secret keys we manage
    SECRET_KEYS = [
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "GEMINI_API_KEY",
        "SNYK_TOKEN",
        "REDIS_PASSWORD",
    ]

    @classmethod
    def get_backend(cls) -> str:
        """Get the current keyring backend name."""
        backend = keyring.get_keyring()
        return backend.__class__.__name__

    @classmethod
    def is_secure_backend(cls) -> bool:
        """Check if the current backend is secure."""
        backend_name = cls.get_backend()
        secure_backends = [
            "Keyring",  # macOS Keychain
            "WinVaultKeyring",  # Windows Credential Manager
            "SecretService",  # Linux Secret Service
            "KWallet",  # KDE Wallet
        ]
        return any(name in backend_name for name in secure_backends)

    @classmethod
    def store_secret(cls, key: str, value: str) -> bool:
        """
        Store a secret in the keyring.

        Args:
            key: Secret key name
            value: Secret value

        Returns:
            True if successful
        """
        try:
            keyring.set_password(cls.SERVICE_NAME, key, value)
            return True
        except errors.KeyringError as e:
            print(f"Error storing {key}: {e}")
            return False

    @classmethod
    def get_secret(cls, key: str) -> str | None:
        """
        Retrieve a secret from the keyring.

        Args:
            key: Secret key name

        Returns:
            Secret value or None
        """
        try:
            return keyring.get_password(cls.SERVICE_NAME, key)
        except errors.KeyringError as e:
            print(f"Error retrieving {key}: {e}")
            return None

    @classmethod
    def delete_secret(cls, key: str) -> bool:
        """
        Delete a secret from the keyring.

        Args:
            key: Secret key name

        Returns:
            True if successful
        """
        try:
            keyring.delete_password(cls.SERVICE_NAME, key)
            return True
        except errors.PasswordDeleteError:
            return False
        except errors.KeyringError as e:
            print(f"Error deleting {key}: {e}")
            return False

    @classmethod
    def list_secrets(cls) -> list[str]:
        """
        List all stored secret keys.

        Returns:
            List of secret keys that have values
        """
        stored = []
        for key in cls.SECRET_KEYS:
            if cls.get_secret(key):
                stored.append(key)
        return stored

    @classmethod
    def load_to_env(cls) -> int:
        """
        Load all secrets from keyring to environment variables.

        Returns:
            Number of secrets loaded
        """
        loaded = 0
        for key in cls.SECRET_KEYS:
            value = cls.get_secret(key)
            if value:
                os.environ[key] = value
                loaded += 1
        return loaded

    @classmethod
    def interactive_store(cls):
        """Interactively store secrets."""
        print("\nStore PromptSentinel Secrets")
        print("=" * 40)
        print(f"Keyring backend: {cls.get_backend()}")

        if not cls.is_secure_backend():
            print("\n⚠️  WARNING: Using potentially insecure backend!")
            print("   Secrets may be stored in plain text.")
            response = input("\nContinue anyway? (y/N): ")
            if response.lower() != "y":
                return

        print("\nEnter secret values (press Enter to skip):\n")

        for key in cls.SECRET_KEYS:
            current = cls.get_secret(key)
            if current:
                print(f"{key}: {'*' * 10}{current[-4:]} (current)")
                response = input("  Enter new value (or press Enter to keep): ")
                if response:
                    if cls.store_secret(key, response):
                        print(f"  ✓ Updated {key}")
            else:
                value = input(f"{key}: ")
                if value:
                    if cls.store_secret(key, value):
                        print(f"  ✓ Stored {key}")

        print("\n✅ Secrets stored in system keyring")

    @classmethod
    def show_status(cls):
        """Display current status of stored secrets."""
        print("\nPromptSentinel Keyring Status")
        print("=" * 40)
        print(f"Service: {cls.SERVICE_NAME}")
        print(f"Backend: {cls.get_backend()}")
        print(f"Secure: {'✓' if cls.is_secure_backend() else '✗ (potentially insecure)'}")

        stored = cls.list_secrets()
        print(f"\nStored secrets ({len(stored)}/{len(cls.SECRET_KEYS)}):")

        for key in cls.SECRET_KEYS:
            value = cls.get_secret(key)
            if value:
                # Show masked value
                if len(value) > 4:
                    masked = "*" * 10 + value[-4:]
                else:
                    masked = "*" * len(value)
                print(f"  ✓ {key}: {masked}")
            else:
                print(f"  ✗ {key}: (not set)")


def example_usage():
    """Demonstrate keyring usage."""
    print("PromptSentinel Keyring Integration Example")
    print("=" * 40)

    # Show current status
    KeyringSecretManager.show_status()

    # Load secrets to environment
    print("\nLoading secrets to environment...")
    loaded = KeyringSecretManager.load_to_env()
    print(f"✓ Loaded {loaded} secrets")

    # Verify environment variables
    if loaded > 0:
        print("\nEnvironment variables set:")
        for key in KeyringSecretManager.SECRET_KEYS:
            value = os.getenv(key)
            if value:
                masked = "*" * 10 + value[-4:] if len(value) > 4 else "*" * len(value)
                print(f"  {key}: {masked}")


def platform_specific_instructions():
    """Show platform-specific instructions."""
    print("\nPlatform-Specific Instructions")
    print("=" * 40)

    backend = KeyringSecretManager.get_backend()

    if "Keychain" in backend:
        print("\nmacOS Keychain:")
        print("  • Open Keychain Access app to view/edit secrets")
        print("  • Secrets are stored under 'promptsentinel'")
        print("  • Synced with iCloud Keychain if enabled")

    elif "WinVault" in backend:
        print("\nWindows Credential Manager:")
        print("  • Open: Control Panel → Credential Manager → Windows Credentials")
        print("  • Look for 'promptsentinel' entries")
        print("  • Backed up with Windows backup")

    elif "SecretService" in backend:
        print("\nLinux Secret Service:")
        print("  • View with Seahorse (GNOME) or KWalletManager (KDE)")
        print("  • Requires running desktop session")
        print("  • SSH sessions may not have access")

    else:
        print(f"\nBackend: {backend}")
        print("  ⚠️  May not be using secure storage")
        print("  Consider installing a proper keyring service")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="PromptSentinel Keyring Secret Manager")
    parser.add_argument("--store", "-s", action="store_true", help="Interactively store secrets")
    parser.add_argument("--delete", "-d", metavar="KEY", help="Delete a specific secret")
    parser.add_argument("--get", "-g", metavar="KEY", help="Get a specific secret value")
    parser.add_argument("--list", "-l", action="store_true", help="List stored secret keys")
    parser.add_argument(
        "--info", "-i", action="store_true", help="Show platform-specific information"
    )

    args = parser.parse_args()

    if args.store:
        KeyringSecretManager.interactive_store()
    elif args.delete:
        if KeyringSecretManager.delete_secret(args.delete):
            print(f"✓ Deleted {args.delete}")
        else:
            print(f"✗ Could not delete {args.delete}")
    elif args.get:
        value = KeyringSecretManager.get_secret(args.get)
        if value:
            print(value)
        else:
            print(f"Secret {args.get} not found", file=sys.stderr)
            sys.exit(1)
    elif args.list:
        secrets = KeyringSecretManager.list_secrets()
        for secret in secrets:
            print(secret)
    elif args.info:
        platform_specific_instructions()
    else:
        example_usage()


if __name__ == "__main__":
    main()
