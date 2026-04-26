FROM python:3.12-slim

LABEL maintainer="HNG DevSecOps"
LABEL description="HNG Anomaly Detection Daemon"

# Install iptables and system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iptables \
        iproute2 \
        procps && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source files
COPY . .

# Create log directory
RUN mkdir -p /var/log/detector

# Run as root (required for iptables). In production consider using
# a dedicated non-root user with CAP_NET_ADMIN capability.
CMD ["python", "main.py", "--config", "/app/config.yaml"]
