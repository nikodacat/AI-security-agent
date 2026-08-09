# web-vuln: Apache httpd 2.4.49 — CVE-2021-42013 (path traversal → RCE)
#
# The base image is a Docker Official one, pinned to the exact vulnerable
# version. We add python3 + minimal scanner deps + a copy of host-scanner
# so `docker exec eval-web-vuln python /opt/host-scanner/scan_target.py`
# produces a gray-box scan JSON.
FROM httpd:2.4.49

# httpd:2.4.49 is Debian-11-slim based. Install python + the small subset of
# host-scanner deps we actually need for a scan-only run (no fastapi/uvicorn,
# no rich analysis, no Claude).
# httpd:2.4.49 is Debian buster (EOL) -- redirect apt at archive.debian.org.
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

# Enable mod_cgi so CVE-2021-42013 is actually exploitable (base image ships
# with it disabled). This matters for chunk H ground-truth work later — the
# static scan already sees the vulnerable version regardless.
RUN echo "LoadModule cgid_module modules/mod_cgid.so" >> /usr/local/apache2/conf/httpd.conf \
    && echo "ScriptAlias /cgi-bin/ /usr/local/apache2/cgi-bin/" >> /usr/local/apache2/conf/httpd.conf \
    && sed -i 's|Require all denied|Require all granted|' /usr/local/apache2/conf/httpd.conf || true

# host-scanner code + eval-lab scan bootstrap
COPY host-scanner /opt/host-scanner
COPY eval-lab/scan_target.py /opt/host-scanner/scan_target.py

WORKDIR /opt/host-scanner
