#!/bin/bash
# Local development run script for PromptSentinel

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting PromptSentinel in development mode...${NC}"

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo -e "${YELLOW}Virtual environment not found. Creating...${NC}"
    uv venv --python 3.11
fi

# Activate virtual environment
source .venv/bin/activate

# Ensure PATH includes UV
export PATH="$HOME/.local/bin:$PATH"

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}Creating .env file from .env.example...${NC}"
    cp .env.example .env
    echo -e "${YELLOW}Please update .env with your API keys${NC}"
fi

# Export Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"

# Run the application
echo -e "${GREEN}Starting FastAPI server...${NC}"
uv run uvicorn prompt_sentinel.main:app --reload --host 0.0.0.0 --port 8080