FROM python:3.12-slim

# System dependencies
RUN apt-get update && apt-get install -y \
    curl wget git openjdk-17-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

# Install Ollama
RUN curl -fsSL https://ollama.com/install.sh | sh

# Working directory
WORKDIR /app
COPY . .

# Python dependencies
RUN pip install --no-cache-dir \
    tree-sitter==0.25.2 \
    tree-sitter-java==0.23.5 \
    tree-sitter-kotlin==1.1.0 \
    requests fastapi uvicorn python-multipart

# Pull models at build time (requires network)
# Comment out for faster builds — models will pull on first run
# RUN ollama serve & sleep 5 && ollama pull qwen2.5-coder:7b && ollama pull phi3:3.8b

# Startup script
COPY docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080 11434

ENTRYPOINT ["/entrypoint.sh"]