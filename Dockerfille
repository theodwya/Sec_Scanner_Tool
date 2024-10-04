# Use python:3.11-slim as the base image for a lightweight and secure environment
FROM python:3.11-slim AS builder

# Set environment variables
ENV PATH="/app/venv/bin:$PATH" \
    UPLOAD_FOLDER=/app/uploads \
    SCAN_RESULTS_FOLDER=/app/output/scan-results \
    PYTHONUNBUFFERED=1

# Create app directory
WORKDIR /app

# Install necessary system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    libmagic1 \
    libmagic-dev \
    yara \
    clamav \
    clamav-daemon \
    docker.io && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    freshclam

# Install Trivy and Grype
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin && \
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install YARA rules
RUN mkdir -p /opt/yara && \
    curl -o /opt/yara/malware_index.yar https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/malware_index.yar

# Create virtual environment and install dependencies
COPY requirements.txt .
RUN python3 -m venv /app/venv && \
    /app/venv/bin/pip install --upgrade pip && \
    /app/venv/bin/pip install --no-cache-dir -r requirements.txt

# Set permissions for /app directories
RUN mkdir -p /app/uploads /app/output/scan-results && \
    chown -R root:root /app

# Copy application code
COPY . /app

# Stage 2: Production stage using the same lightweight python image
FROM python:3.11-slim

# Set environment variables
ENV PATH="/app/venv/bin:$PATH" \
    UPLOAD_FOLDER=/app/uploads \
    SCAN_RESULTS_FOLDER=/app/output/scan-results \
    PYTHONUNBUFFERED=1 \
    YARA_RULES_PATH="/opt/yara/malware_index.yar"

# Ensure output and upload directories exist
RUN mkdir -p /app/output /app/uploads /app/output/scan-results && \
    chown -R root:root /app

# Copy files from builder
COPY --from=builder /app /app
COPY --from=builder /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=builder /usr/local/bin/grype /usr/local/bin/grype
COPY --from=builder /opt/yara /opt/yara

# Set working directory
WORKDIR /app

# Expose the application port
EXPOSE 8000

# Run FastAPI application using uvicorn
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
