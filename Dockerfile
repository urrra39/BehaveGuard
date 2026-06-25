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
#   python3.11 / pip   - runtime + package install
#   bpfcc-tools        - BCC userspace tooling
#   libbpfcc-dev       - BCC development headers (for python bcc bindings)
#   linux-headers-generic - fallback kernel headers (host headers preferred)
#   gcc, make          - BCC compiles BPF programs at runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3.11 \
        python3-pip \
        bpfcc-tools \
        libbpfcc-dev \
        linux-headers-generic \
        gcc \
        make \
        curl \
        ca-certificates \
    && ln -sf /usr/bin/python3.11 /usr/local/bin/python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first so this layer is cached independently of
# the application source changing.
COPY requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt

# Install the application itself (editable so the console script is wired up).
COPY . .
RUN pip3 install -e .

# 8888 - REST API / health endpoint
# 8050 - dashboard (Dash)
EXPOSE 8888 8050

# Default to running the detector with the dashboard disabled; override CMD to
# enable it (e.g. `docker run ... behaveguard run`).
ENTRYPOINT ["behaveguard"]
CMD ["run", "--no-dashboard"]
