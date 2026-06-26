# BehaveGuard - eBPF + ML Linux anomaly detector
#
# IMPORTANT: eBPF runs against the HOST kernel, not the container's view.
# This image MUST be run with elevated privileges and host resources mounted:
#
#   docker run --privileged \
#     -v /lib/modules:/lib/modules:ro \
#     -v /usr/src:/usr/src:ro \
#     -v /sys/fs/bpf:/sys/fs/bpf \
#     -v /proc:/proc:ro \
#     behaveguard
#
# Instead of --privileged you may scope capabilities down to:
#     --cap-add SYS_ADMIN --cap-add NET_ADMIN
# (plus the volume mounts above). BCC compiles BPF programs at runtime and
# needs the HOST kernel headers (/lib/modules, /usr/src) to do so, and host
# /proc so the collector can resolve real PIDs/processes on the machine.
#
# See docker-compose.yml for the recommended, fully-wired invocation.

FROM ubuntu:22.04

# Non-interactive apt and unbuffered Python for clean container logging.
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# System dependencies:
#   python3 / pip      - runtime + package install (>=3.10; jammy ships 3.10)
#   bpfcc-tools        - BCC userspace tooling
#   libbpfcc-dev       - BCC development headers (for python bcc bindings)
#   linux-headers-generic - fallback kernel headers (host headers preferred)
#   gcc, make          - BCC compiles BPF programs at runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-dev \
        bpfcc-tools \
        libbpfcc-dev \
        linux-headers-generic \
        gcc \
        make \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first so this layer is cached independently of
# the application source changing.
COPY requirements.txt ./
RUN python3 -m pip install --no-cache-dir -r requirements.txt

# Install the application itself.
COPY . .
RUN python3 -m pip install -e .

# 8888 - REST API / health endpoint
# 8050 - dashboard (Dash)
EXPOSE 8888 8050

# Invoke via the module entry point (`python3 -m behaveguard`) rather than the
# console script, so the smoke/run commands don't depend on the script being on
# PATH. Default to the detector with the dashboard disabled; override CMD to
# enable it (e.g. `docker run ... behaveguard run`).
ENTRYPOINT ["python3", "-m", "behaveguard"]
CMD ["run", "--no-dashboard"]
