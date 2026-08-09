# db-exposed: Redis 6.2.6 bound to all interfaces with no auth.
# Illustrates the classic "internal-service-published-to-the-internet" pattern.
# Redis 6.2.6 also carries CVE-2022-0543 (Lua sandbox escape) on Debian builds.
FROM redis:6.2.6

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip \
      procps \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --no-cache-dir \
      psutil rapidfuzz httpx pyyaml rich

# Deliberately-permissive redis config. bind 0.0.0.0 + no requirepass is the
# whole point of this container.
RUN mkdir -p /usr/local/etc/redis \
    && printf 'bind 0.0.0.0\nprotected-mode no\n' > /usr/local/etc/redis/redis.conf

COPY host-scanner /opt/host-scanner
COPY eval-lab/scan_target.py /opt/host-scanner/scan_target.py

WORKDIR /opt/host-scanner

CMD ["redis-server", "/usr/local/etc/redis/redis.conf"]
