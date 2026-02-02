FROM python:3.11-slim

WORKDIR /app

# Install client first
COPY client/ /tmp/client/
RUN pip install /tmp/client/

# Install MCP dependencies
RUN pip install mcp>=0.4.0

# Copy server
COPY mcp-server/server.py .

# Create data directory for identity
RUN mkdir -p /data

VOLUME ["/data"]

CMD ["python", "server.py"]
