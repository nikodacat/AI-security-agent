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
      httpx

WORKDIR /opt/coordinator

CMD ["sleep", "infinity"]
