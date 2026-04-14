#!/bin/bash
set -e

echo "Starting Ollama..."
ollama serve &
OLLAMA_PID=$!

echo "Waiting for Ollama to be ready..."
until curl -s http://localhost:11434/api/tags > /dev/null 2>&1; do
    sleep 2
done

echo "Pulling models (first run only)..."
ollama pull qwen2.5-coder:7b || true
ollama pull phi3:3.8b || true

echo "Starting CryptoGuard dashboard on port 8080..."
cd /app
uvicorn src.api.main:app --host 0.0.0.0 --port 8080 --workers 1

wait $OLLAMA_PID