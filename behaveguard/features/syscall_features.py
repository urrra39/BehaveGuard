"""Syscall-derived features: per-syscall frequency + sequence bigrams.

Two design notes that matter for a *security* detector:

* The frequency vector is sized to the full x86_64 syscall table
  (``NUM_SYSCALLS`` derived from :data:`event_types.SYSCALL_NAMES`), not the 311
  the original sketch used — otherwise ``execveat`` (322), a sensitive
  exec-family call, would fall outside the vector and be invisible.
* Bigrams are folded into a fixed number of buckets with a *deterministic* hash.
  Python's built-in ``hash()`` is salted per process (PYTHONHASHSEED), which
  would make the same event stream produce different vectors on each run and
  silently poison training. A small fixed polynomial hash keeps it reproducible.
"""

from __future__ import annotations

from typing import List

from behaveguard.collector.event_types import SYSCALL_NAMES, SyscallEvent

# Size the frequency vector to cover every known syscall number (0..max).
NUM_SYSCALLS: int = max(SYSCALL_NAMES) + 1
NUM_BIGRAMS: int = 50


def _bigram_bucket(a: int, b: int) -> int:
    """Deterministically map a syscall bigram ``(a, b)`` to ``[0, NUM_BIGRAMS)``."""
    # 337 is the smallest prime above the current max syscall number, giving a
    # collision-light, PYTHONHASHSEED-independent fold.
    return (a * 337 + b) % NUM_BIGRAMS


class SyscallFeatureExtractor:
    """Turns a window of syscall events into a frequency + bigram vector."""

    @staticmethod
    def feature_names() -> List[str]:
        """Names for the ``NUM_SYSCALLS`` frequency slots then ``NUM_BIGRAMS`` bigrams."""
        return [f"syscall_{i}_freq" for i in range(NUM_SYSCALLS)] + [
            f"syscall_bigram_{i}" for i in range(NUM_BIGRAMS)
        ]

    @staticmethod
    def dim() -> int:
        """Total length of the syscall feature block."""
        return NUM_SYSCALLS + NUM_BIGRAMS

    def extract(self, events: List[SyscallEvent], window_seconds: int) -> List[float]:
        """Return relative syscall frequencies followed by hashed bigram weights.

        All values are in ``[0, 1]``: frequencies are counts divided by the total
        number of syscalls in the window, bigram buckets by the total bigram count.
        """
        freq = [0.0] * NUM_SYSCALLS
        sequence: List[int] = []

        for event in events:
            nr = int(event.syscall_nr)
            idx = nr if 0 <= nr < NUM_SYSCALLS else NUM_SYSCALLS - 1
            freq[idx] += 1.0
            sequence.append(idx)

        total = sum(freq)
        if total > 0.0:
            freq = [count / total for count in freq]

        bigrams = [0.0] * NUM_BIGRAMS
        for a, b in zip(sequence, sequence[1:]):
            bigrams[_bigram_bucket(a, b)] += 1.0

        bigram_total = sum(bigrams)
        if bigram_total > 0.0:
            bigrams = [count / bigram_total for count in bigrams]

        return freq + bigrams
