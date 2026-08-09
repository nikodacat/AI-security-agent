# cms-plugin: WordPress 5.7 on Apache. The image bundles known-vulnerable
# versions of apache2, openssl, and the WordPress core itself.
#
# We don't need WordPress to actually serve pages — the point is for the
# vulnerable *packages* to be present so host-scanner picks them up.
FROM wordpress:5.7-apache

# wordpress:5.7-apache is Debian buster (EOL) -- redirect apt at archive.debian.org.
RUN printf 'deb http://archive.debian.org/debian buster main\ndeb http://archive.debian.org/debian-security buster/updates main\n' \
      > /etc/apt/sources.list \
    && printf 'Acquire::Check-Valid-Until "false";\n' \
      > /etc/apt/apt.conf.d/99no-check-valid-until \
    && apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip \
      procps \
    && rm -rf /var/lib/apt/lists/*

# buster ships pip 18.1 which can't parse modern pyproject.toml; upgrade first.
RUN python3 -m pip install --no-cache-dir --upgrade "pip>=23.0" \
    && python3 -m pip install --no-cache-dir \
      psutil rapidfuzz httpx pyyaml rich

COPY host-scanner /opt/host-scanner
COPY eval-lab/scan_target.py /opt/host-scanner/scan_target.py

WORKDIR /opt/host-scanner
