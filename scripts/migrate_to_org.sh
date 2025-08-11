#!/bin/bash
# Script to migrate repository references from personal account to organization
# Usage: ./scripts/migrate_to_org.sh

set -e

OLD_GITHUB="rhoska/prompt-sentinel"
NEW_GITHUB="promptsentinelai/prompt-sentinel"
OLD_DOCKER="rhoska"
NEW_DOCKER="promptsentinelai"
OLD_GO_MODULE="github.com/rhoska/prompt-sentinel"
NEW_GO_MODULE="github.com/promptsentinelai/prompt-sentinel"

echo "🚀 Starting migration from personal account to organization..."

# Update GitHub repository references
echo "📝 Updating GitHub repository references..."

# Update CI/CD workflow
sed -i '' "s|${OLD_DOCKER}/prompt-sentinel|${NEW_DOCKER}/prompt-sentinel|g" .github/workflows/ci.yml

# Update README
sed -i '' "s|${OLD_GITHUB}|${NEW_GITHUB}|g" README.md

# Update pyproject.toml
sed -i '' "s|${OLD_GITHUB}|${NEW_GITHUB}|g" pyproject.toml

# Update SDK package files
echo "📦 Updating SDK package references..."

# JavaScript SDK
sed -i '' "s|${OLD_GITHUB}|${NEW_GITHUB}|g" sdk/javascript/package.json
sed -i '' "s|${OLD_GITHUB}|${NEW_GITHUB}|g" sdk/javascript/README.md

# Python SDK
sed -i '' "s|${OLD_GITHUB}|${NEW_GITHUB}|g" sdk/python/setup.py
sed -i '' "s|${OLD_GITHUB}|${NEW_GITHUB}|g" sdk/python/README.md

# Go SDK - special handling for module path
sed -i '' "s|${OLD_GO_MODULE}|${NEW_GO_MODULE}|g" sdk/go/go.mod
sed -i '' "s|${OLD_GITHUB}|${NEW_GITHUB}|g" sdk/go/README.md
sed -i '' "s|${OLD_GO_MODULE}|${NEW_GO_MODULE}|g" sdk/go/cmd/example/main.go

# Update documentation files
echo "📚 Updating documentation..."
find docs -name "*.md" -type f -exec sed -i '' "s|${OLD_GITHUB}|${NEW_GITHUB}|g" {} \;

# Update deployment files
echo "🚢 Updating deployment configurations..."
sed -i '' "s|${OLD_GITHUB}|${NEW_GITHUB}|g" deployment/helm/Chart.yaml
sed -i '' "s|${OLD_DOCKER}|${NEW_DOCKER}|g" deployment/helm/values.yaml 2>/dev/null || true

# Update docker files
sed -i '' "s|${OLD_GITHUB}|${NEW_GITHUB}|g" docker/README.md

# Update security scan reports
echo "🔒 Updating security scan references..."
sed -i '' "s|${OLD_GO_MODULE}|${NEW_GO_MODULE}|g" security/SECURITY_SCAN_REPORT.md
sed -i '' "s|${OLD_GITHUB}|${NEW_GITHUB}|g" security/scripts/generate_report.py

# Update API docs
sed -i '' "s|${OLD_GITHUB}|${NEW_GITHUB}|g" src/prompt_sentinel/api_docs.py

# Update git remote
echo "🔗 Updating git remote..."
echo "Current remote:"
git remote -v

echo ""
echo "To update the git remote, run:"
echo "  git remote set-url origin https://github.com/${NEW_GITHUB}.git"
echo ""

echo "✅ Migration script completed!"
echo ""
echo "Next steps:"
echo "1. Review the changes: git diff"
echo "2. Transfer the repository on GitHub to promptsentinelai organization"
echo "3. Update git remote: git remote set-url origin https://github.com/${NEW_GITHUB}.git"
echo "4. Commit changes: git add -A && git commit -m 'chore: migrate repository to promptsentinelai organization'"
echo "5. Push to new repository: git push origin main"
echo "6. Update Docker Hub credentials in GitHub Secrets"
echo "7. Test CI/CD pipeline with a new commit"# Migration Complete
