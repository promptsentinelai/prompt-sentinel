# Secure Secret Management for PromptSentinel

This guide provides best practices and multiple options for securely managing API keys and other sensitive configuration values when deploying PromptSentinel.

## ⚠️ Security Warning

**Never commit API keys or sensitive credentials to version control!** The `.env` file should contain only non-sensitive configuration or placeholder values when committed.

## Quick Start

Choose the method that best fits your security requirements and deployment environment:

1. **[HashiCorp Vault](#option-1-hashicorp-vault)** - Best for teams and production
2. **[Python Keyring](#option-2-python-keyring)** - Simple local development
3. **[Encrypted .env Files](#option-3-encrypted-env-files)** - Portable and secure
4. **[Cloud Secret Managers](#option-4-cloud-secret-managers)** - Cloud-native deployments

## Option 1: HashiCorp Vault

HashiCorp Vault provides enterprise-grade secret management with audit logging, access control, and secret rotation capabilities.

### Benefits
- Centralized secret management
- Audit trail for all secret access
- Dynamic secret generation
- Secret rotation and leasing
- Fine-grained access control

### Basic Setup

1. **Install Vault** (macOS example):
```bash
brew tap hashicorp/tap
brew install hashicorp/tap/vault
```

2. **Start Vault in development mode** (for testing):
```bash
vault server -dev
export VAULT_ADDR='http://127.0.0.1:8200'
```

3. **Store secrets**:
```bash
vault kv put secret/promptsentinel/api_keys \
  anthropic="your-anthropic-key" \
  openai="your-openai-key" \
  gemini="your-gemini-key"
```

### Python Integration

```python
import hvac
import os
from typing import Dict, Optional

class VaultSecretManager:
    def __init__(self, vault_addr: str = "http://127.0.0.1:8200"):
        self.client = hvac.Client(url=vault_addr)
        # Authenticate with token (store token securely!)
        token = os.getenv("VAULT_TOKEN")
        if token:
            self.client.token = token
    
    def get_secrets(self, path: str) -> Optional[Dict]:
        """Fetch secrets from Vault."""
        try:
            response = self.client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_path="secret"
            )
            return response["data"]["data"]
        except Exception as e:
            print(f"Error fetching secrets: {e}")
            return None
    
    def load_to_env(self):
        """Load secrets from Vault to environment variables."""
        secrets = self.get_secrets("promptsentinel/api_keys")
        if secrets:
            os.environ["ANTHROPIC_API_KEY"] = secrets.get("anthropic", "")
            os.environ["OPENAI_API_KEY"] = secrets.get("openai", "")
            os.environ["GEMINI_API_KEY"] = secrets.get("gemini", "")

# Usage
vault = VaultSecretManager()
vault.load_to_env()
```

### Docker Integration

Add to your `docker-compose.yml`:
```yaml
services:
  prompt-sentinel:
    environment:
      - VAULT_ADDR=${VAULT_ADDR:-http://host.docker.internal:8200}
      - VAULT_TOKEN=${VAULT_TOKEN}
```

## Option 2: Python Keyring

Python keyring provides secure local storage using the operating system's native credential store.

### Benefits
- Uses OS-native secure storage (macOS Keychain, Windows Credential Manager, Linux Secret Service)
- No additional infrastructure needed
- Simple API
- Cross-platform support

### Installation

```bash
pip install keyring
```

### Basic Usage

```python
import keyring
import os

class KeyringSecretManager:
    SERVICE_NAME = "promptsentinel"
    
    @classmethod
    def store_secret(cls, key: str, value: str):
        """Store a secret in the system keyring."""
        keyring.set_password(cls.SERVICE_NAME, key, value)
    
    @classmethod
    def get_secret(cls, key: str) -> str:
        """Retrieve a secret from the system keyring."""
        return keyring.get_password(cls.SERVICE_NAME, key)
    
    @classmethod
    def load_to_env(cls):
        """Load all secrets to environment variables."""
        keys = [
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY", 
            "GEMINI_API_KEY",
            "SNYK_TOKEN"
        ]
        
        for key in keys:
            value = cls.get_secret(key)
            if value:
                os.environ[key] = value

# First time setup - store your keys
KeyringSecretManager.store_secret("ANTHROPIC_API_KEY", "your-key-here")
KeyringSecretManager.store_secret("OPENAI_API_KEY", "your-key-here")

# In your application
KeyringSecretManager.load_to_env()
```

### Platform Considerations

- **macOS**: Uses Keychain, accessible via Keychain Access app
- **Windows**: Uses Windows Credential Manager
- **Linux**: Uses Secret Service (requires gnome-keyring or similar)
- **Headless servers**: Falls back to encrypted file storage (less secure)

## Option 3: Encrypted .env Files

Using `python-dotenv-vault` to encrypt your `.env` file for secure storage and deployment.

### Benefits
- Encrypted secrets can be safely committed to version control
- Single decryption key for deployment
- Backward compatible with standard python-dotenv
- No external dependencies in production

### Installation

```bash
pip install python-dotenv-vault
```

### Setup

1. **Create your `.env` file** with actual values:
```bash
ANTHROPIC_API_KEY=your-actual-key
OPENAI_API_KEY=your-actual-key
GEMINI_API_KEY=your-actual-key
```

2. **Encrypt the file**:
```bash
npx dotenv-vault local build
```

This creates:
- `.env.vault` - Encrypted secrets (safe to commit)
- `.env.keys` - Decryption keys (DO NOT COMMIT)

3. **In your Python application**:
```python
from dotenv_vault import load_dotenv

# Automatically uses .env.vault if DOTENV_KEY is set
# Falls back to .env for local development
load_dotenv()
```

4. **For deployment**, set the decryption key:
```bash
export DOTENV_KEY="dotenv://:key_1234567890@dotenv.local/vault/.env.vault?environment=production"
```

## Option 4: Cloud Secret Managers

For cloud-native deployments, use your cloud provider's secret management service.

### AWS Secrets Manager

```python
import boto3
import json
import os

def load_aws_secrets(secret_name: str, region: str = "us-east-1"):
    """Load secrets from AWS Secrets Manager."""
    client = boto3.client("secretsmanager", region_name=region)
    
    try:
        response = client.get_secret_value(SecretId=secret_name)
        secrets = json.loads(response["SecretString"])
        
        # Load to environment
        for key, value in secrets.items():
            os.environ[key] = value
            
    except Exception as e:
        print(f"Error retrieving secrets: {e}")
        raise

# Usage
load_aws_secrets("promptsentinel/api-keys")
```

### Azure Key Vault

```python
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
import os

def load_azure_secrets(vault_url: str):
    """Load secrets from Azure Key Vault."""
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=vault_url, credential=credential)
    
    secret_names = [
        "anthropic-api-key",
        "openai-api-key",
        "gemini-api-key"
    ]
    
    for name in secret_names:
        secret = client.get_secret(name)
        env_name = name.upper().replace("-", "_")
        os.environ[env_name] = secret.value

# Usage
load_azure_secrets("https://your-vault.vault.azure.net/")
```

### Google Secret Manager

```python
from google.cloud import secretmanager
import os

def load_gcp_secrets(project_id: str):
    """Load secrets from Google Secret Manager."""
    client = secretmanager.SecretManagerServiceClient()
    
    secrets = {
        "anthropic-api-key": "ANTHROPIC_API_KEY",
        "openai-api-key": "OPENAI_API_KEY",
        "gemini-api-key": "GEMINI_API_KEY"
    }
    
    for secret_id, env_var in secrets.items():
        name = f"projects/{project_id}/secrets/{secret_id}/versions/latest"
        response = client.access_secret_version(request={"name": name})
        os.environ[env_var] = response.payload.data.decode("UTF-8")

# Usage
load_gcp_secrets("your-project-id")
```

## Integration with PromptSentinel

### Modify your application startup

Create a `config/secrets.py` file:

```python
import os
from typing import Optional

def load_secrets(method: Optional[str] = None):
    """
    Load secrets using the configured method.
    Falls back to .env file if no method specified.
    """
    method = method or os.getenv("SECRET_METHOD", "dotenv")
    
    if method == "vault":
        from .vault_secrets import VaultSecretManager
        vault = VaultSecretManager()
        vault.load_to_env()
    
    elif method == "keyring":
        from .keyring_secrets import KeyringSecretManager
        KeyringSecretManager.load_to_env()
    
    elif method == "aws":
        from .aws_secrets import load_aws_secrets
        load_aws_secrets("promptsentinel/api-keys")
    
    elif method == "azure":
        from .azure_secrets import load_azure_secrets
        vault_url = os.getenv("AZURE_VAULT_URL")
        if vault_url:
            load_azure_secrets(vault_url)
    
    elif method == "gcp":
        from .gcp_secrets import load_gcp_secrets
        project_id = os.getenv("GCP_PROJECT_ID")
        if project_id:
            load_gcp_secrets(project_id)
    
    # Default: dotenv (or dotenv-vault if DOTENV_KEY is set)
    else:
        from dotenv import load_dotenv
        load_dotenv()

# Call this before initializing your settings
load_secrets()
```

### Update your settings.py

```python
from pydantic_settings import BaseSettings
from .secrets import load_secrets

# Load secrets before settings initialization
load_secrets()

class Settings(BaseSettings):
    # Your existing settings...
    pass
```

## Security Best Practices

1. **Never commit secrets**: Add `.env` to `.gitignore`
2. **Use strong, unique API keys**: Rotate regularly
3. **Limit access**: Use principle of least privilege
4. **Audit access**: Enable logging for secret access
5. **Encrypt in transit**: Use TLS/HTTPS for all connections
6. **Rotate secrets**: Implement regular rotation policies
7. **Use separate keys**: Different keys for dev/staging/production
8. **Monitor usage**: Set up alerts for unusual access patterns

## Environment-Specific Configuration

### Development
- Use `.env` files with real keys (never commit)
- Or use local Vault/Keyring for better security

### CI/CD
- Use CI/CD platform's secret management (GitHub Secrets, GitLab CI variables)
- Or use cloud secret managers with service account authentication

### Production
- Use cloud secret managers or HashiCorp Vault
- Enable audit logging
- Implement secret rotation
- Use service accounts with minimal permissions

## Troubleshooting

### Common Issues

**Issue**: "API key not found"
- Verify secret is stored in your chosen system
- Check environment variable names match exactly
- Ensure secrets are loaded before application initialization

**Issue**: "Permission denied accessing secrets"
- Check authentication credentials (Vault token, cloud IAM)
- Verify network connectivity to secret service
- Review access policies and permissions

**Issue**: "Keyring not available"
- Install system keyring service (Linux)
- Run with GUI session (not SSH)
- Fall back to encrypted file storage

## Additional Resources

- [HashiCorp Vault Documentation](https://www.vaultproject.io/docs)
- [Python Keyring Documentation](https://pypi.org/project/keyring/)
- [Dotenv Vault Documentation](https://www.dotenv.org/docs/security/vault)
- [AWS Secrets Manager](https://docs.aws.amazon.com/secretsmanager/)
- [Azure Key Vault](https://docs.microsoft.com/en-us/azure/key-vault/)
- [Google Secret Manager](https://cloud.google.com/secret-manager/docs)