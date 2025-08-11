#!/usr/bin/env python3
"""
Encrypted .env file example using python-dotenv-vault for PromptSentinel.

This example demonstrates how to encrypt your .env file for secure storage
and deployment, allowing you to safely commit encrypted secrets to version control.

Prerequisites:
    pip install python-dotenv-vault
    npm install -g dotenv-vault (for CLI commands)

Usage:
    1. Create .env with secrets
    2. Encrypt: dotenv-vault local build
    3. Run: python dotenv_vault_example.py
"""

import os
from pathlib import Path

try:
    from dotenv_vault import load_dotenv
except ImportError:
    print("Please install python-dotenv-vault: pip install python-dotenv-vault")
    print("Falling back to standard python-dotenv...")
    from dotenv import load_dotenv


class DotenvVaultManager:
    """Manage encrypted .env files with dotenv-vault."""

    def __init__(self, env_path: str = "."):
        """
        Initialize the manager.

        Args:
            env_path: Path to directory containing .env files
        """
        self.env_path = Path(env_path)
        self.env_file = self.env_path / ".env"
        self.vault_file = self.env_path / ".env.vault"
        self.keys_file = self.env_path / ".env.keys"

    def has_vault(self) -> bool:
        """Check if .env.vault exists."""
        return self.vault_file.exists()

    def has_keys(self) -> bool:
        """Check if .env.keys exists."""
        return self.keys_file.exists()

    def load_secrets(self) -> bool:
        """
        Load secrets from .env.vault or .env file.

        Returns:
            True if secrets were loaded
        """
        # Check for DOTENV_KEY in environment
        dotenv_key = os.getenv("DOTENV_KEY")

        if dotenv_key and self.has_vault():
            print("✓ Loading encrypted secrets from .env.vault")
            load_dotenv()  # dotenv-vault handles decryption automatically
            return True
        elif self.env_file.exists():
            print("✓ Loading secrets from .env file")
            load_dotenv(self.env_file)
            return True
        else:
            print("✗ No .env or .env.vault file found")
            return False

    def get_dotenv_key(self, environment: str = "development") -> str | None:
        """
        Extract DOTENV_KEY for a specific environment from .env.keys.

        Args:
            environment: Environment name (development, staging, production)

        Returns:
            The DOTENV_KEY value or None
        """
        if not self.has_keys():
            return None

        try:
            with open(self.keys_file) as f:
                for line in f:
                    if f"DOTENV_KEY_{environment.upper()}=" in line:
                        return line.split("=", 1)[1].strip().strip('"')
        except Exception as e:
            print(f"Error reading .env.keys: {e}")

        return None

    def create_example_env(self):
        """Create an example .env file."""
        example_content = """# PromptSentinel Configuration
ANTHROPIC_API_KEY=sk-ant-api-example-key
OPENAI_API_KEY=sk-proj-example-key
GEMINI_API_KEY=AIzaSy-example-key
SNYK_TOKEN=example-snyk-token

# Redis Configuration
REDIS_PASSWORD=changeme-in-production
REDIS_HOST=localhost
REDIS_PORT=6379

# Detection Settings
DETECTION_MODE=strict
LLM_CLASSIFICATION_ENABLED=true
"""

        if self.env_file.exists():
            print(f"✗ {self.env_file} already exists")
            return False

        with open(self.env_file, "w") as f:
            f.write(example_content)

        print(f"✓ Created example {self.env_file}")
        return True

    def show_status(self):
        """Display current vault status."""
        print("\nDotenv Vault Status")
        print("=" * 40)
        print(f"Directory: {self.env_path.absolute()}")
        print(f".env file: {'✓' if self.env_file.exists() else '✗'}")
        print(f".env.vault: {'✓' if self.has_vault() else '✗'}")
        print(f".env.keys: {'✓' if self.has_keys() else '✗'}")

        if os.getenv("DOTENV_KEY"):
            print("DOTENV_KEY: ✓ (set in environment)")
        else:
            print("DOTENV_KEY: ✗ (not set)")

        if self.has_keys():
            print("\nAvailable environments:")
            for env in ["development", "staging", "production"]:
                key = self.get_dotenv_key(env)
                if key:
                    print(f"  • {env}: {key[:20]}...")


def setup_instructions():
    """Show setup instructions for dotenv-vault."""
    print("\nDotenv Vault Setup Instructions")
    print("=" * 40)
    print(
        """
1. Install the CLI tool:
   npm install -g dotenv-vault

2. Create your .env file with real secrets:
   cat > .env << EOF
   ANTHROPIC_API_KEY=your-real-key
   OPENAI_API_KEY=your-real-key
   GEMINI_API_KEY=your-real-key
   EOF

3. Build the encrypted vault:
   dotenv-vault local build

   This creates:
   • .env.vault - Encrypted secrets (safe to commit)
   • .env.keys - Decryption keys (DO NOT COMMIT)

4. Add to .gitignore:
   echo ".env.keys" >> .gitignore
   echo ".env" >> .gitignore

5. For deployment, set the DOTENV_KEY:
   export DOTENV_KEY="dotenv://:key_xxx@dotenv.local/vault/.env.vault?environment=production"

6. Your application will automatically use the encrypted vault!
"""
    )


def deployment_examples():
    """Show deployment examples."""
    print("\nDeployment Examples")
    print("=" * 40)

    print("\nDocker:")
    print(
        """
# Dockerfile
FROM python:3.11-slim
COPY .env.vault .
ENV DOTENV_KEY="dotenv://:key_xxx@dotenv.local/vault/.env.vault?environment=production"
"""
    )

    print("\nDocker Compose:")
    print(
        """
services:
  app:
    environment:
      - DOTENV_KEY=${DOTENV_KEY}
    volumes:
      - ./.env.vault:/app/.env.vault:ro
"""
    )

    print("\nKubernetes:")
    print(
        """
apiVersion: v1
kind: Secret
metadata:
  name: dotenv-key
stringData:
  DOTENV_KEY: "dotenv://:key_xxx@dotenv.local/vault/.env.vault?environment=production"
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: env-vault
data:
  .env.vault: |
    <contents of .env.vault>
"""
    )

    print("\nGitHub Actions:")
    print(
        """
- name: Deploy
  env:
    DOTENV_KEY: ${{ secrets.DOTENV_KEY }}
  run: |
    python app.py
"""
    )


def example_usage():
    """Demonstrate dotenv-vault usage."""
    print("PromptSentinel Dotenv Vault Example")
    print("=" * 40)

    manager = DotenvVaultManager()

    # Show current status
    manager.show_status()

    # Load secrets
    print("\nLoading secrets...")
    if manager.load_secrets():
        # Check what was loaded
        secrets_loaded = []
        for key in ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY"]:
            if os.getenv(key):
                secrets_loaded.append(key)

        if secrets_loaded:
            print(f"\n✓ Loaded {len(secrets_loaded)} secrets:")
            for key in secrets_loaded:
                value = os.getenv(key)
                masked = "*" * 10 + value[-4:] if len(value) > 4 else "*" * len(value)
                print(f"  {key}: {masked}")
        else:
            print("\n⚠️  No PromptSentinel secrets found in environment")

    # Show setup instructions if no vault
    if not manager.has_vault():
        print("\n💡 Tip: Create an encrypted vault for secure secret storage")
        print("   Run with --setup for instructions")


def migration_guide():
    """Show migration guide from plain .env to encrypted vault."""
    print("\nMigration Guide: .env → .env.vault")
    print("=" * 40)
    print(
        """
Step 1: Backup your current .env
   cp .env .env.backup

Step 2: Install dotenv-vault
   npm install -g dotenv-vault

Step 3: Build encrypted vault
   dotenv-vault local build

Step 4: Test loading from vault
   DOTENV_KEY=$(grep DOTENV_KEY_DEVELOPMENT .env.keys | cut -d'"' -f2) python app.py

Step 5: Update your application
   # No code changes needed! python-dotenv-vault is backward compatible

Step 6: Secure your keys
   # Store .env.keys securely (password manager, vault, etc.)
   # Add to .gitignore
   echo ".env.keys" >> .gitignore

Step 7: Commit the encrypted vault
   git add .env.vault
   git commit -m "Add encrypted secrets vault"

Step 8: Deploy with DOTENV_KEY
   # Set DOTENV_KEY in your deployment environment
   # Remove plain .env from production
"""
    )


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Dotenv Vault Example for PromptSentinel")
    parser.add_argument("--setup", action="store_true", help="Show setup instructions")
    parser.add_argument("--deploy", action="store_true", help="Show deployment examples")
    parser.add_argument("--migrate", action="store_true", help="Show migration guide")
    parser.add_argument("--create-example", action="store_true", help="Create example .env file")

    args = parser.parse_args()

    if args.setup:
        setup_instructions()
    elif args.deploy:
        deployment_examples()
    elif args.migrate:
        migration_guide()
    elif args.create_example:
        manager = DotenvVaultManager()
        manager.create_example_env()
    else:
        example_usage()


if __name__ == "__main__":
    main()
