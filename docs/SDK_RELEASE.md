# SDK Release Guide

This document outlines the process for releasing the PromptSentinel SDKs to their respective package repositories.

## Version 1.0.0 Release Status

All three SDKs are functionally complete and ready for v1.0.0 release:

| SDK | Status | Package Registry | Package Name |
|-----|--------|-----------------|--------------|
| Python | ✅ Ready | PyPI | `promptsentinel` |
| JavaScript | ✅ Ready | npm | `@promptsentinel/sdk` |
| Go | ✅ Ready | Go Modules | `github.com/promptsentinelai/prompt-sentinel/sdk/go` |

## Pre-Release Checklist

### All SDKs
- [x] Version updated to 1.0.0
- [x] Documentation complete
- [x] Examples provided
- [x] GitHub repository references updated to `promptsentinelai`
- [x] License files in place (MIT for SDKs)

### Python SDK
- [x] `setup.py` configured
- [x] `README.md` with comprehensive examples
- [x] Basic usage examples in `/examples`
- [x] All dependencies specified

### JavaScript SDK
- [x] Distribution files built (`dist/`)
- [x] TypeScript definitions generated
- [x] `package.json` configured
- [x] Rollup build configuration fixed

### Go SDK
- [x] `go.mod` with correct module path
- [x] Comprehensive documentation
- [x] All types and methods documented
- [x] Examples in README

## Release Process

### Python SDK Release

1. **Build the distribution:**
   ```bash
   cd sdk/python
   python -m pip install --upgrade build
   python -m build
   ```

2. **Upload to PyPI:**
   ```bash
   python -m pip install --upgrade twine
   python -m twine upload dist/*
   ```

3. **Verify installation:**
   ```bash
   pip install promptsentinel
   ```

### JavaScript SDK Release

1. **Ensure distribution is built:**
   ```bash
   cd sdk/javascript
   npm run build
   ```

2. **Login to npm:**
   ```bash
   npm login
   ```

3. **Publish to npm:**
   ```bash
   npm publish --access public
   ```

4. **Verify installation:**
   ```bash
   npm install @promptsentinel/sdk
   ```

### Go SDK Release

1. **Create a git tag for the SDK:**
   ```bash
   git tag sdk/go/v1.0.0
   git push origin sdk/go/v1.0.0
   ```

2. **The Go module will be automatically available via:**
   ```bash
   go get github.com/promptsentinelai/prompt-sentinel/sdk/go@v1.0.0
   ```

3. **Verify installation:**
   ```bash
   go get github.com/promptsentinelai/prompt-sentinel/sdk/go
   ```

## Post-Release Tasks

1. **Update main README** with SDK installation instructions
2. **Create GitHub Release** with SDK highlights
3. **Announce on social media** (if applicable)
4. **Update documentation site** with SDK references

## Version Management

### Semantic Versioning
All SDKs follow semantic versioning (MAJOR.MINOR.PATCH):
- MAJOR: Breaking API changes
- MINOR: New features, backward compatible
- PATCH: Bug fixes, backward compatible

### Version Sync
While SDKs can have independent versions, for major releases it's recommended to keep them in sync for clarity.

## Testing Before Release

### Local Testing

#### Python
```bash
cd sdk/python
pip install -e .
python examples/basic_usage.py
```

#### JavaScript
```bash
cd sdk/javascript
npm link
# In test project:
npm link @promptsentinel/sdk
```

#### Go
```bash
cd sdk/go
go run cmd/example/main.go
```

## Troubleshooting

### Python Issues
- Ensure `~/.pypirc` is configured with PyPI credentials
- Check that all files are included in `MANIFEST.in`
- Verify Python version compatibility

### JavaScript Issues
- Ensure npm account has scope permissions for @promptsentinel
- Check that `.npmignore` excludes unnecessary files
- Verify Node.js version requirements

### Go Issues
- Ensure repository is public on GitHub
- Tag must follow format `sdk/go/vX.Y.Z`
- Allow time for Go proxy to update (up to 30 minutes)

## Security Notes

- Never commit API keys or credentials
- Use environment variables for sensitive configuration
- Ensure examples use placeholder values
- Review code for any hardcoded secrets before release

## Support

For SDK-specific issues:
- Python: Create issue with `sdk-python` label
- JavaScript: Create issue with `sdk-javascript` label
- Go: Create issue with `sdk-go` label

Repository: https://github.com/promptsentinelai/prompt-sentinel/issues