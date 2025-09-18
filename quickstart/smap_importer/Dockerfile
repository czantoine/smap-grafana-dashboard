FROM python:3.12-slim

# Install required system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       git \
       golang-go \
       sqlite3 \
       ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy Python script and targets.txt
COPY import_smap.py targets.txt ./

# Copy entrypoint
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Install smap
RUN GOPATH=/root/go /usr/bin/env bash -c \
    "go install -v github.com/s0md3v/smap/cmd/smap@latest && \
     cp /root/go/bin/smap /usr/local/bin/ && \
     /usr/local/bin/smap -h >/dev/null 2>&1 || true"

# Create scans directory inside container
RUN mkdir -p /app/scans

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["python", "import_smap.py"]
