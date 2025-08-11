# Secret Management Examples

This directory contains example implementations for securely managing API keys and other sensitive configuration values in PromptSentinel.

## 🔐 Available Examples

### 1. HashiCorp Vault (`vault_example.py`)
Enterprise-grade secret management with audit logging and access control.

```bash
# Install dependencies
pip install hvac

# Run example
python vault_example.py
```

**Best for:** Teams, production deployments, environments requiring audit trails

### 2. Python Keyring (`keyring_example.py`)
OS-native secure storage using system keychains.

```bash
# Install dependencies
pip install keyring

# Store secrets interactively
python keyring_example.py --store

# Load secrets
python keyring_example.py
```

**Best for:** Local development, single-user deployments

### 3. Encrypted .env Files (`dotenv_vault_example.py`)
Encrypt your .env file for safe version control storage.

```bash
# Install dependencies
pip install python-dotenv-vault
npm install -g dotenv-vault

# Show setup instructions
python dotenv_vault_example.py --setup

# Run example
python dotenv_vault_example.py
```

**Best for:** Projects needing to commit encrypted secrets to Git

## 🚀 Quick Start

### Step 1: Choose Your Method

| Method | Security | Ease of Use | Team Friendly | Cloud Ready |
|--------|----------|-------------|---------------|-------------|
| HashiCorp Vault | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| Python Keyring | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐ |
| Encrypted .env | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |

### Step 2: Run the Example

Each example includes:
- Setup instructions
- Interactive secret storage
- Integration with PromptSentinel
- Platform-specific guidance

### Step 3: Integrate with Your Deployment

See the main [SECURE_SECRETS.md](../../docs/SECURE_SECRETS.md) documentation for detailed integration instructions.

## 📝 Example Usage in PromptSentinel

### Option 1: Modify Application Startup

```python
# In your main application file
from examples.secret_management.vault_example import VaultSecretManager

# Load secrets before initializing settings
vault = VaultSecretManager()
vault.load_promptsentinel_secrets()

# Now start your application
from prompt_sentinel.config.settings import Settings
settings = Settings()  # Will use secrets from environment
```

### Option 2: Environment Variable Approach

All examples load secrets to environment variables, so they work seamlessly with PromptSentinel's existing configuration:

```python
# 1. Load secrets using any method
python keyring_example.py  # Loads to environment

# 2. Start PromptSentinel normally
python -m uvicorn prompt_sentinel.main:app
```

### Option 3: Docker Integration

```dockerfile
# Use encrypted vault in Docker
COPY .env.vault /app/
ENV DOTENV_KEY="dotenv://:key_xxx@dotenv.local/vault/.env.vault?environment=production"
```

## 🔒 Security Best Practices

1. **Never commit plain text secrets** - Use `.gitignore` for `.env` files
2. **Use different keys for each environment** - dev, staging, production
3. **Rotate secrets regularly** - Implement rotation policies
4. **Audit access** - Log who accesses which secrets
5. **Principle of least privilege** - Grant minimal necessary permissions

## 📚 Additional Resources

- [HashiCorp Vault Documentation](https://www.vaultproject.io/docs)
- [Python Keyring Documentation](https://pypi.org/project/keyring/)
- [Dotenv Vault Documentation](https://www.dotenv.org/docs/security/vault)
- [PromptSentinel Security Guide](../../docs/SECURE_SECRETS.md)

## 💡 Tips

- **Development**: Use keyring for simplicity
- **CI/CD**: Use encrypted .env files or CI platform secrets
- **Production**: Use HashiCorp Vault or cloud secret managers
- **Testing**: Create separate test secrets, never use production keys

## 🤝 Contributing

Have a better secret management approach? We'd love to see it! Please contribute:

1. Add your example to this directory
2. Update this README
3. Submit a pull request

## ⚠️ Disclaimer

These examples are for educational purposes. Always follow your organization's security policies and compliance requirements when handling sensitive data.