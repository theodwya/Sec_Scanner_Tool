# Stage 1: Build stage for installing dependencies and building the environment
FROM python:3.11-slim AS builder

# Set environment variables
ENV PATH="/app/venv/bin:$PATH" \
    UPLOAD_FOLDER=/app/uploads \
    SCAN_RESULTS_FOLDER=/app/output/scan-results \
    PYTHONUNBUFFERED=1

# Create app directory
WORKDIR /app

# Install necessary system dependencies, including OpenSSL, libmagic, and security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    build-essential \
    libmagic1 \
    libmagic-dev \
    yara \
    clamav \
    clamav-daemon \
    docker.io \
    libssl-dev \
    openssl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    freshclam

# Install Trivy and Grype
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin && \
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install YARA rules
RUN mkdir -p /opt/yara && \
    curl -o /opt/yara/malware_index.yar https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/malware_index.yar

# Create a virtual environment and install Python dependencies
COPY requirements.txt .
RUN python3 -m venv /app/venv && \
    /app/venv/bin/pip install --upgrade pip && \
    /app/venv/bin/pip install --no-cache-dir -r requirements.txt

# Set permissions for /app directories
RUN mkdir -p /app/uploads /app/output/scan-results && \
    chown -R root:root /app

# Copy application code
COPY . /app

# Stage 2: Production stage using a lightweight image for running the application
FROM python:3.11-slim

# Set environment variables
ENV PATH="/app/venv/bin:$PATH" \
    UPLOAD_FOLDER=/app/uploads \
    SCAN_RESULTS_FOLDER=/app/output/scan-results \
    PYTHONUNBUFFERED=1 \
    YARA_RULES_PATH="/opt/yara/malware_index.yar"

# Create necessary directories and set permissions
RUN mkdir -p /app/output /app/uploads /app/output/scan-results && \
    chown -R root:root /app

# Install runtime dependencies, including ClamAV, in the production stage
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    clamav \
    clamav-daemon && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    freshclam

# Create necessary directories and set permissions for ClamAV
RUN mkdir -p /var/run/clamav && \
    chown clamav:clamav /var/run/clamav && \
    chmod 755 /var/run/clamav

# Ensure ClamAV uses the correct socket
RUN echo "LocalSocket /var/run/clamav/clamd.ctl" >> /etc/clamav/clamd.conf

# Copy files from the builder stage
COPY --from=builder /app /app
COPY --from=builder /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=builder /usr/local/bin/grype /usr/local/bin/grype
COPY --from=builder /opt/yara /opt/yara

# Set working directory
WORKDIR /app

# Expose the application port
EXPOSE 8000

# Start the ClamAV daemon in the background and the FastAPI app using Uvicorn
CMD ["sh", "-c", "clamd & uvicorn app:app --host 0.0.0.0 --port 8000"]
