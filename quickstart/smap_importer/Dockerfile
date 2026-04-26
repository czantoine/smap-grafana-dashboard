# ══════════════════════════════════════════════════════════════
# Stage 1: Build smap with Go 1.25+
# ══════════════════════════════════════════════════════════════
FROM golang:1.25-bookworm AS smap-builder

RUN go install -v github.com/s0md3v/smap/cmd/smap@latest
RUN /go/bin/smap -h >/dev/null 2>&1 || true

# ══════════════════════════════════════════════════════════════
# Stage 2: Runtime
# ══════════════════════════════════════════════════════════════
FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        sqlite3 \
        curl \
        dnsutils \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=smap-builder /go/bin/smap /usr/local/bin/smap
RUN chmod +x /usr/local/bin/smap

WORKDIR /app
RUN mkdir -p /app/scans /app/data

COPY import_smap.py /app/import_smap.py
COPY targets.txt /app/targets.txt
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]