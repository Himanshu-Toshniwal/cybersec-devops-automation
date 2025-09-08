# Multi-stage build for cybersecurity platform
FROM python:3.10-slim as builder

# Set working directory
WORKDIR /app

# Install system dependencies for security tools
RUN apt-get update && apt-get install -y \
    nmap \
    dnsutils \
    whois \
    curl \
    wget \
    gcc \
    g++ \
    libssl-dev \
    libffi-dev \
    netcat-traditional \
    iputils-ping \
    traceroute \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.10-slim

# Install runtime dependencies for cybersecurity tools
RUN apt-get update && apt-get install -y \
    nmap \
    dnsutils \
    whois \
    curl \
    netcat-traditional \
    iputils-ping \
    traceroute \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash --uid 1000 cybersec

# Set working directory
WORKDIR /app

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.10/site-packages /usr/local/lib/python3.10/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY src/ ./src/
COPY tests/ ./tests/

# Create necessary directories for cybersecurity platform
RUN mkdir -p /app/logs /app/reports /app/scans /app/data

# Set proper permissions
RUN chown -R cybersec:cybersec /app

# Switch to non-root user
USER cybersec

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=src/main.py
ENV FLASK_ENV=production

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/ || exit 1

# Default command
CMD ["python", "src/main.py"]