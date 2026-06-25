#!/usr/bin/env python3
"""Throughput benchmark for the BehaveGuard feature extractor.

This measures how fast the *pure-Python* feature pipeline turns a window of raw
syscall events into a fixed-length feature vector. It exercises
:meth:`behaveguard.features.extractor.FeatureExtractor.extract_vector`, which is
the hot path that runs once per process per sliding window in production.

Why this matters
----------------
BehaveGuard observes *every* process on a host. The collector groups events into
30-second sliding windows and, for each window, must produce a feature vector for
the ML ensemble. If feature extraction is slow, the detector falls behind the
event stream. This script gives a concrete ``windows/sec`` number so regressions
in the extraction code are caught early.

Design constraints
-------------------
* **No numpy, no torch, no bcc.** Only ``extract_vector`` (the ``list[float]``
  path) is used, never ``extract`` (the numpy path). The script therefore runs on
  a stock Python 3.9+ interpreter with nothing installed but the standard library
  and the ``behaveguard`` package itself.
* **Synthetic, deterministic input.** Events are generated with a fixed PRNG seed
  so successive runs are comparable. The synthetic distribution mimics a busy but
  realistic process: a heavy tail of common syscalls (read/write/mmap/...) plus a
  sprinkling of sensitive ones (execve/ptrace/...).
* **Steady-state timing.** A warm-up pass primes interpreter caches and the
  per-extractor state before the measured loop, and timing uses
  :func:`time.perf_counter` (a monotonic high-resolution clock) rather than
  :func:`time.time`.

Usage
-----
    python scripts/benchmark.py [--events N] [--iterations M] [--window SECONDS]

Run it from the repository root so that ``import behaveguard`` resolves against
the working tree (or install the package with ``pip install -e .`` first).
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time
from typing import List

# Make sure the repository root is importable when this script is run directly
# (``python scripts/benchmark.py``) without the package being installed.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from behaveguard.collector.event_types import SyscallEvent, syscall_name  # noqa: E402
from behaveguard.features.extractor import FeatureExtractor  # noqa: E402

# A realistic-ish syscall mix: hot, mundane calls dominate; a few sensitive calls
# appear rarely. (number, relative weight). Names are resolved via the canonical
# x86_64 table so the synthetic events look like the real thing.
_SYSCALL_MIX = [
    (0, 30),    # read
    (1, 30),    # write
    (9, 12),    # mmap
    (8, 8),     # lseek
    (257, 8),   # openat
    (3, 8),     # close
    (202, 10),  # futex
    (16, 6),    # ioctl
    (13, 4),    # rt_sigaction
    (59, 2),    # execve   (sensitive)
    (101, 1),   # ptrace   (sensitive)
    (105, 1),   # setuid   (sensitive)
]


def build_window(num_events: int, seed: int = 1337) -> List[SyscallEvent]:
    """Construct ``num_events`` synthetic :class:`SyscallEvent` objects.

    The events span a single 30-second window with monotonically increasing
    timestamps and are drawn from :data:`_SYSCALL_MIX` using a fixed seed so the
    benchmark is reproducible run to run.

    Args:
        num_events: Number of syscall events to generate.
        seed: PRNG seed controlling the (otherwise fixed) event mix.

    Returns:
        A list of fully-populated :class:`SyscallEvent` instances.
    """
    rng = random.Random(seed)
    numbers = [nr for nr, weight in _SYSCALL_MIX for _ in range(weight)]

    base_ns = 1_000_000_000_000  # arbitrary monotonic-clock origin in ns
    window_ns = 30 * 1_000_000_000
    # Spread events evenly across the 30s window, with a little jitter.
    step = max(window_ns // max(num_events, 1), 1)

    events: List[SyscallEvent] = []
    for i in range(num_events):
        nr = rng.choice(numbers)
        ts = base_ns + i * step + rng.randint(0, step)
        events.append(
            SyscallEvent(
                timestamp_ns=ts,
                pid=4242,
                tgid=4242,
                uid=1000,
                comm="benchmark",
                syscall_nr=nr,
                syscall_name=syscall_name(nr),
                ret=0,
                args=[0, 0, 0],
            )
        )
    return events


def run_benchmark(num_events: int, iterations: int, window_seconds: int) -> None:
    """Time ``extract_vector`` over many iterations and print the throughput.

    Args:
        num_events: Events per synthetic window.
        iterations: Number of timed ``extract_vector`` calls.
        window_seconds: Window length passed to the extractor.
    """
    extractor = FeatureExtractor(window_seconds=window_seconds)
    events = build_window(num_events)

    # Warm-up: prime interpreter/method caches and validate the output shape
    # before the measured loop so the first-call cost is excluded.
    warm_vector = extractor.extract_vector(events)
    feature_dim = len(warm_vector)
    assert feature_dim == FeatureExtractor.NUM_FEATURES, (
        f"vector length {feature_dim} != NUM_FEATURES {FeatureExtractor.NUM_FEATURES}"
    )
    for _ in range(max(iterations // 20, 5)):
        extractor.extract_vector(events)

    # Measured loop.
    start = time.perf_counter()
    for _ in range(iterations):
        extractor.extract_vector(events)
    elapsed = time.perf_counter() - start

    windows_per_sec = iterations / elapsed if elapsed > 0 else float("inf")
    events_per_sec = windows_per_sec * num_events
    us_per_window = (elapsed / iterations) * 1_000_000.0

    print("BehaveGuard feature-extractor benchmark")
    print("=" * 44)
    print(f"  python              : {sys.version.split()[0]}")
    print(f"  feature dimension   : {feature_dim}")
    print(f"  events per window   : {num_events}")
    print(f"  iterations (windows): {iterations}")
    print(f"  window_seconds      : {window_seconds}")
    print(f"  elapsed             : {elapsed:.4f} s")
    print(f"  latency per window  : {us_per_window:.1f} us")
    print("-" * 44)
    print(f"  THROUGHPUT          : {windows_per_sec:,.1f} windows/sec")
    print(f"  events processed    : {events_per_sec:,.0f} events/sec")


def main() -> None:
    """Parse arguments and run the benchmark."""
    parser = argparse.ArgumentParser(
        description="Benchmark BehaveGuard feature extraction throughput.",
    )
    parser.add_argument(
        "--events",
        type=int,
        default=500,
        help="number of syscall events per window (default: 500)",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=2000,
        help="number of timed extract_vector calls (default: 2000)",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=30,
        help="window length in seconds (default: 30)",
    )
    args = parser.parse_args()
    run_benchmark(args.events, args.iterations, args.window)


if __name__ == "__main__":
    main()
