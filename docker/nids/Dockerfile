# Netra NIDS/IPS container: live capture, detection engine, iptables response, event API.
# Build context is the repository root (see docker-compose.yml).
FROM python:3.11-slim

# iptables: response actions. tcpdump: scapy uses it to compile BPF capture filters.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables tcpdump iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY docker/nids/requirements-nids.txt .
RUN pip install --no-cache-dir -r requirements-nids.txt

COPY src/ src/

# Trained models are mounted read-only at /app/models by docker-compose.
ENV PYTHONUNBUFFERED=1 \
    NETRA_FIREWALL_BACKEND=iptables \
    NETRA_IFACE=auto

EXPOSE 8000
CMD ["python", "-m", "src.cli", "live", "--host", "0.0.0.0", "--port", "8000"]
