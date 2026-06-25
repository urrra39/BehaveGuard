#!/usr/bin/env bash
#
# generate_training_data.sh — build per-process behavioral baselines.
#
# BehaveGuard detects anomalies by comparing each process against a learned model
# of its OWN normal behavior. Before it can detect anything, those baselines must
# be trained. This script observes the processes currently running on the host
# for a fixed duration and trains a baseline (LSTM + VAE) for each, by invoking
# the BehaveGuard CLI's training command.
#
# USAGE:
#   sudo ./scripts/generate_training_data.sh [DURATION_MINUTES]
#
#   DURATION_MINUTES  How long to observe normal behavior, in minutes.
#                     Optional; defaults to 60.
#
# EXAMPLES:
#   sudo ./scripts/generate_training_data.sh         # observe for 60 minutes
#   sudo ./scripts/generate_training_data.sh 120     # observe for 2 hours
#
# IMPORTANT:
#   * Run this on a system that is behaving NORMALLY. Whatever the processes do
#     during the observation window becomes the definition of "normal" — so do
#     not train during an incident, a deploy, or unusual load, or you will teach
#     the detector to treat malicious/abnormal behavior as baseline.
#   * Longer observation windows capture more behavioral variety (cron jobs,
#     log rotation, periodic tasks) and produce more robust baselines. 60 minutes
#     is a reasonable minimum; several hours is better for production hosts.
#   * Requires ROOT: eBPF program loading needs elevated privileges, so the
#     underlying `behaveguard train` runs under sudo.

set -euo pipefail

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
# Observation duration in minutes; first positional arg, default 60.
DURATION="${1:-60}"

log() { printf '\033[1;34m[training-data]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[training-data] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# Validate the duration is a positive integer.
if ! [[ "${DURATION}" =~ ^[0-9]+$ ]] || [[ "${DURATION}" -eq 0 ]]; then
  die "DURATION_MINUTES must be a positive integer (got: '${DURATION}'). Usage: $0 [DURATION_MINUTES]"
fi

# --------------------------------------------------------------------------- #
# Pre-flight
# --------------------------------------------------------------------------- #
if ! command -v behaveguard >/dev/null 2>&1; then
  die "the 'behaveguard' CLI was not found on PATH. Install it first: sudo ./scripts/install_deps.sh"
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  die "BehaveGuard training requires Linux (eBPF). Detected: $(uname -s)."
fi

# Decide how to gain root for the training command.
if [[ "$(id -u)" -eq 0 ]]; then
  SUDO=""
else
  command -v sudo >/dev/null 2>&1 || die "training requires root. Re-run as: sudo $0 ${DURATION}"
  SUDO="sudo"
fi

# --------------------------------------------------------------------------- #
# Guidance
# --------------------------------------------------------------------------- #
log "BehaveGuard baseline training"
log "Observation window : ${DURATION} minute(s)"
log ""
log "BehaveGuard will now watch the running processes and learn what 'normal'"
log "looks like for each of them. Keep the system in a representative steady"
log "state for the whole window — avoid deploys, benchmarks, or unusual activity,"
log "since everything observed now becomes the baseline of normal behavior."
log ""
log "This will run for ${DURATION} minute(s). You can leave it unattended."
log ""

# --------------------------------------------------------------------------- #
# Train
# --------------------------------------------------------------------------- #
# Observe all running processes for the given duration and build their baselines.
log "Starting: behaveguard train --duration ${DURATION}"
${SUDO} behaveguard train --duration "${DURATION}"

log ""
log "Baseline training complete."
log "Trained model bundles are stored under: ~/.behaveguard/models/<process>/"
log "Inspect them with:   behaveguard status"
log "Then start detection: sudo behaveguard run"
