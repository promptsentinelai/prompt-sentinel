#!/bin/bash

# Build and test Docker image locally

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
IMAGE_NAME="promptsentinelai/prompt-sentinel"
TAG="${1:-latest}"
PLATFORM="${2:-linux/amd64}"

echo -e "${GREEN}🐳 Building PromptSentinel Docker Image${NC}"
echo "Image: ${IMAGE_NAME}:${TAG}"
echo "Platform: ${PLATFORM}"
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker is not installed${NC}"
    exit 1
fi

# Build the image
echo -e "${YELLOW}📦 Building Docker image...${NC}"
docker build \
    --platform ${PLATFORM} \
    --tag ${IMAGE_NAME}:${TAG} \
    --build-arg VERSION=${TAG} \
    --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
    .

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Build successful${NC}"
else
    echo -e "${RED}❌ Build failed${NC}"
    exit 1
fi

# Get image size
IMAGE_SIZE=$(docker images ${IMAGE_NAME}:${TAG} --format "{{.Size}}")
echo -e "${GREEN}📏 Image size: ${IMAGE_SIZE}${NC}"

# Run security scan with Trivy (if installed)
if command -v trivy &> /dev/null; then
    echo -e "${YELLOW}🔍 Running security scan...${NC}"
    trivy image --severity HIGH,CRITICAL ${IMAGE_NAME}:${TAG}
else
    echo -e "${YELLOW}⚠️  Trivy not installed, skipping security scan${NC}"
    echo "   Install with: brew install aquasecurity/trivy/trivy"
fi

# Test the image
echo -e "${YELLOW}🧪 Testing Docker image...${NC}"

# Create a test .env file if it doesn't exist
if [ ! -f .env.test ]; then
    cat > .env.test << EOF
# Test environment variables
API_HOST=0.0.0.0
API_PORT=8080
LOG_LEVEL=INFO
DETECTION_MODE=moderate
CONFIDENCE_THRESHOLD=0.7
HEURISTIC_ENABLED=true
PII_DETECTION_ENABLED=true
EOF
fi

# Run the container
echo -e "${YELLOW}🚀 Starting container...${NC}"
CONTAINER_ID=$(docker run -d \
    --name prompt-sentinel-test \
    -p 8080:8080 \
    --env-file .env.test \
    ${IMAGE_NAME}:${TAG})

# Wait for container to be healthy
echo -e "${YELLOW}⏳ Waiting for container to be healthy...${NC}"
TIMEOUT=30
ELAPSED=0

while [ $ELAPSED -lt $TIMEOUT ]; do
    if docker exec prompt-sentinel-test curl -f http://localhost:8080/health &> /dev/null; then
        echo -e "${GREEN}✅ Container is healthy${NC}"
        break
    fi
    sleep 1
    ELAPSED=$((ELAPSED + 1))
    echo -n "."
done

if [ $ELAPSED -ge $TIMEOUT ]; then
    echo -e "${RED}❌ Container failed to become healthy${NC}"
    docker logs prompt-sentinel-test
    docker rm -f prompt-sentinel-test
    exit 1
fi

# Run basic API tests
echo -e "${YELLOW}🧪 Running API tests...${NC}"

# Test health endpoint
echo -n "Testing /health endpoint... "
HEALTH_RESPONSE=$(curl -s http://localhost:8080/health)
if echo $HEALTH_RESPONSE | grep -q "status"; then
    echo -e "${GREEN}✅${NC}"
else
    echo -e "${RED}❌${NC}"
    echo "Response: $HEALTH_RESPONSE"
fi

# Test OpenAPI endpoint
echo -n "Testing /openapi.json endpoint... "
OPENAPI_RESPONSE=$(curl -s http://localhost:8080/openapi.json)
if echo $OPENAPI_RESPONSE | grep -q "openapi"; then
    echo -e "${GREEN}✅${NC}"
else
    echo -e "${RED}❌${NC}"
fi

# Test detection endpoint (will fail without API keys, but should return proper error)
echo -n "Testing /v1/detect endpoint... "
DETECT_RESPONSE=$(curl -s -X POST http://localhost:8080/v1/detect \
    -H "Content-Type: application/json" \
    -d '{"prompt": "Hello world"}')
if echo $DETECT_RESPONSE | grep -q "verdict\|detail"; then
    echo -e "${GREEN}✅${NC}"
else
    echo -e "${RED}❌${NC}"
    echo "Response: $DETECT_RESPONSE"
fi

# Show container logs
echo -e "${YELLOW}📋 Container logs:${NC}"
docker logs --tail 20 prompt-sentinel-test

# Cleanup
echo -e "${YELLOW}🧹 Cleaning up...${NC}"
docker rm -f prompt-sentinel-test

echo -e "${GREEN}✨ Docker image ready: ${IMAGE_NAME}:${TAG}${NC}"
echo ""
echo "To run the container:"
echo "  docker run -p 8080:8080 --env-file .env ${IMAGE_NAME}:${TAG}"
echo ""
echo "To push to Docker Hub:"
echo "  docker push ${IMAGE_NAME}:${TAG}"