FROM python:3.12-slim

# nmap/iproute2/procps/ufw/git back the agents' subprocess calls
# (NetworkScanAgent, PortMonitorAgent/NetworkConnAgent, ProcessMonitorAgent,
# block_threat(), github_reporter.py respectively) -- none of these ship as
# pip packages, they're real Linux binaries the code shells out to.
# supervisor runs the three long-running processes as one container PID 1.
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap \
      iproute2 \
      iputils-ping \
      ieee-data \
      procps \
      git \
      ufw \
      supervisor \
      curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ backend/
COPY docker/docker-entrypoint.sh /docker-entrypoint.sh
COPY docker/run-github-reporter.sh /docker/run-github-reporter.sh
COPY docker/supervisord.conf /etc/supervisor/conf.d/swarmsentinel.conf
RUN chmod +x /docker-entrypoint.sh /docker/run-github-reporter.sh

ENV DATA_DIR=/data
VOLUME /data
EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD curl -fsS http://localhost:5000/health || exit 1

ENTRYPOINT ["/docker-entrypoint.sh"]
