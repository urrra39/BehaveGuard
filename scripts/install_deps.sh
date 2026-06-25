#!/usr/bin/env bash
#
# install_deps.sh — install BehaveGuard's system + Python dependencies.
#
# BehaveGuard loads eBPF programs via BCC, so it needs the BCC toolchain, the BCC
# development headers, and the running kernel's headers (to compile the eBPF C
# programs against this exact kernel). This script installs those on
# Debian/Ubuntu, then installs the BehaveGuard package itself in editable mode.
#
# REQUIREMENTS:
#   * A Debian/Ubuntu system with `apt-get` (other distros: install the BCC
#     equivalents manually, then run `pip install -e .`).
#   * Linux 5.15+ (eBPF ring buffers) and Python 3.10+.
#   * ROOT / sudo: installing apt packages requires elevated privileges. Run as
#       sudo ./scripts/install_deps.sh
#
# The script is idempotent: re-running it is safe. apt-get install is a no-op for
# already-present packages, and `pip install -e .` simply re-resolves.

set -euo pipefail

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
log()  { printf '\033[1;34m[install_deps]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[install_deps] WARNING:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[install_deps] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# Resolve the repository root (parent of this script's directory) so the script
# works regardless of the directory it is invoked from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# --------------------------------------------------------------------------- #
# Pre-flight checks
# --------------------------------------------------------------------------- #
log "BehaveGuard dependency installer"
log "Repository: ${REPO_ROOT}"

if [[ "$(uname -s)" != "Linux" ]]; then
  die "BehaveGuard requires Linux (eBPF). Detected: $(uname -s)."
fi

# Determine how to run privileged commands. If we're already root, run directly;
# otherwise use sudo. If neither is available, instruct the user.
if [[ "$(id -u)" -eq 0 ]]; then
  SUDO=""
  log "Running as root."
else
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
    warn "Not running as root; will use sudo for apt-get. You may be prompted for a password."
  else
    die "This script needs root to install system packages. Re-run as: sudo $0"
  fi
fi

if ! command -v apt-get >/dev/null 2>&1; then
  die "apt-get not found. This installer targets Debian/Ubuntu. On other distros, install BCC (bpfcc) + your kernel headers, then run: pip install -e ${REPO_ROOT}"
fi

KERNEL_RELEASE="$(uname -r)"
log "Detected kernel: ${KERNEL_RELEASE}"

# --------------------------------------------------------------------------- #
# Step 1/3 — system packages (BCC + headers + build tools)
# --------------------------------------------------------------------------- #
log "[1/3] Updating apt package index..."
${SUDO} apt-get update

log "[1/3] Installing BCC toolchain, kernel headers, and build tools..."
# - bpfcc-tools / libbpfcc-dev : BCC runtime + development headers
# - linux-headers-$(uname -r)  : headers for THIS kernel (eBPF compilation)
# - python3-pip, gcc, make     : to build the eBPF programs and install the pkg
${SUDO} apt-get install -y \
  bpfcc-tools \
  libbpfcc-dev \
  "linux-headers-${KERNEL_RELEASE}" \
  python3-pip \
  gcc \
  make

log "[1/3] System dependencies installed."

# --------------------------------------------------------------------------- #
# Step 2/3 — sanity check the kernel headers
# --------------------------------------------------------------------------- #
log "[2/3] Verifying kernel headers are present..."
if [[ -d "/lib/modules/${KERNEL_RELEASE}/build" || -d "/usr/src/linux-headers-${KERNEL_RELEASE}" ]]; then
  log "[2/3] Kernel headers for ${KERNEL_RELEASE} found."
else
  warn "Could not confirm kernel headers for ${KERNEL_RELEASE}. eBPF compilation may fail."
  warn "If you are on a cloud/managed kernel, you may need a vendor-specific headers package."
fi

# --------------------------------------------------------------------------- #
# Step 3/3 — install the BehaveGuard Python package (editable)
# --------------------------------------------------------------------------- #
log "[3/3] Installing BehaveGuard (editable) and its Python dependencies..."
# Install as the invoking (non-root) user when running under sudo, so the
# editable install and console scripts land in that user's environment rather
# than root's. Falls back to a plain pip install when not under sudo.
if [[ -n "${SUDO}" && -n "${SUDO_USER:-}" ]]; then
  log "[3/3] Installing as user '${SUDO_USER}'."
  ${SUDO} -u "${SUDO_USER}" python3 -m pip install -e "${REPO_ROOT}"
else
  python3 -m pip install -e "${REPO_ROOT}"
fi

log "[3/3] BehaveGuard package installed."

# --------------------------------------------------------------------------- #
# Done
# --------------------------------------------------------------------------- #
log "All dependencies installed successfully."
log "Next steps:"
log "  1. Initialize:        sudo behaveguard init"
log "  2. Build a baseline:  sudo behaveguard train --duration 60"
log "  3. Run the detector:  sudo behaveguard run"
log "Note: running the detector requires root (eBPF program loading)."
