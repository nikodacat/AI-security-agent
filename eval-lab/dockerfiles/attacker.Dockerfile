# eval-attacker: coordinator-side box for network-prober and external assessment tools.
# Provisions nmap and coordinator tooling on the evallab network to probe lab targets.
FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap \
      iputils-ping \
      curl \
      netcat-openbsd \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
      python-nmap \
      pyyaml \
      rich \
      httpx \
      jsonschema

# Make network-prober importable without callers setting PYTHONPATH themselves.
# /repo is the read-only bind-mount of the AI-security-agent repo root (see
# docker-compose.yml). This lets `python -m network_prober` work as-is.
ENV PYTHONPATH=/repo/network-prober

WORKDIR /opt/coordinator

CMD ["sleep", "infinity"]
