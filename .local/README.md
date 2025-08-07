# Local Vault Integration (Private - Not in Git)

This directory contains your personal HashiCorp Vault integration for PromptSentinel.
These files are NOT part of the public repository and should remain local only.

## 🔐 Secure Architecture

### How It Works
1. **Secrets in Vault** - All API keys and passwords stored in HashiCorp Vault
2. **Config in .env** - Only non-sensitive configuration in .env file  
3. **Runtime Loading** - Secrets loaded from Vault to memory at startup
4. **Never on Disk** - Secrets are NEVER written to files

### Security Benefits
- ✅ No plain text secrets in files
- ✅ Centralized secret management
- ✅ Audit trail in Vault
- ✅ Easy secret rotation
- ✅ Secure even if .env is compromised

## 🚀 Usage

### Run Application with Secrets
```bash
.local/run_secure.sh
```
This will:
1. Connect to your personal Vault
2. Load secrets to environment variables (memory only)
3. Load non-sensitive config from .env
4. Start PromptSentinel with all configuration

### Check Available Secrets
```bash
.local/run_secure.sh check
```
Shows what secrets are available in Vault (masked values).

### Interactive Shell with Secrets
```bash
.local/run_secure.sh shell
```
Starts a shell with secrets loaded in environment variables.

## 📁 Files

- `vault_secure.py` - Secure loader that never writes secrets to disk
- `run_secure.sh` - Convenient launcher script
- `vault_loader.py` - OLD VERSION (writes to .env - don't use!)
- `setup_vault.sh` - OLD VERSION (writes to .env - don't use!)

## 🔑 Secret Paths in Vault

Your secrets are stored at these paths in Vault:

| Secret | Vault Path | Environment Variable |
|--------|------------|---------------------|
| Anthropic API Key | `secret/promptsentinel/api_keys/anthropic` | `ANTHROPIC_API_KEY` |
| OpenAI API Key | `secret/promptsentinel/api_keys/openai` | `OPENAI_API_KEY` |
| Gemini API Key | `secret/promptsentinel/api_keys/gemini` | `GEMINI_API_KEY` |
| Snyk Token | `secret/promptsentinel/api_keys/snyk` | `SNYK_TOKEN` |
| Redis Password | `secret/promptsentinel/redis/password` | `REDIS_PASSWORD` |

## 🔧 Managing Secrets

### View a Secret
```bash
vaultx personal kv get secret/promptsentinel/api_keys/anthropic
```

### Update a Secret
```bash
vaultx personal kv put secret/promptsentinel/api_keys/anthropic value="new-key-here"
```

### List All Secrets
```bash
vaultx personal kv list secret/promptsentinel/
```

## ⚠️ Important Notes

1. **Never add secrets to .env** - The .env file should only contain non-sensitive configuration
2. **Keep this directory private** - These files are in .gitignore and should never be committed
3. **Vault must be running** - Ensure your personal vault is running and unsealed
4. **Use run_secure.sh** - Always use the secure launcher, not the old vault_loader.py

## 🚨 Troubleshooting

### "Vault is sealed"
```bash
cd ~/Code/Tools/macos-local-vaults
./scripts/unseal.sh personal
```

### "Vault not running"
```bash
cd ~/Code/Tools/macos-local-vaults
./personal/start.sh
```

### "Secret not found"
Add the secret to Vault:
```bash
vaultx personal kv put secret/promptsentinel/api_keys/anthropic value="your-key"
```

## 🔄 Migration from .env

If you had secrets in .env before:
1. They've been migrated to Vault already ✅
2. The .env file has been cleaned of secrets ✅
3. Use `.local/run_secure.sh` to run the app ✅

## 🎯 Best Practices

1. **Rotate keys regularly** - Update in Vault, not in files
2. **Use separate keys** - Different keys for dev/staging/production
3. **Monitor access** - Check Vault audit logs
4. **Never share tokens** - Each developer should have their own Vault token

---

Remember: This setup keeps your secrets secure while maintaining compatibility with the PromptSentinel codebase!