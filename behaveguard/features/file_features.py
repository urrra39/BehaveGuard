"""File-access features derived from a window of FileEvent objects.

Reads of credential stores and accesses under system directories are the
fingerprint of credential dumping and recon; a burst of writes signals tampering
or staging; high path entropy hints at randomized drop paths. Path matching
tolerates both full paths (mock / userspace-resolved) and bare basenames (the
best-effort name the eBPF probe captures), so sensitive files are caught either
way.
"""

from __future__ import annotations

import math
from typing import List

from behaveguard.collector.event_types import SENSITIVE_PATHS, FileEvent

CAP_FILES = 50.0

# Directory prefixes whose contents are sensitive to read/enumerate.
SYSTEM_DIRS = ("/etc", "/proc", "/sys", "/dev", "/root", "/boot")

# Hints that an opened file is executable/loadable code.
_EXEC_SUFFIXES = (".so", ".sh", ".bin", ".elf", ".py", ".pl", ".rb", ".out")
_EXEC_DIRS = ("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin")

# Basenames of the sensitive paths, for matching against bare filenames.
_SENSITIVE_BASENAMES = {p.rstrip("/").rsplit("/", 1)[-1] for p in SENSITIVE_PATHS if p.rstrip("/")}


def _saturate(value: float, cap: float) -> float:
    if cap <= 0.0:
        return 0.0
    return min(value / cap, 1.0)


def _basename(path: str) -> str:
    return path.rstrip("/").rsplit("/", 1)[-1]


def _is_sensitive(path: str) -> bool:
    """Match a path against the sensitive set by prefix or by basename."""
    if any(path.startswith(p.rstrip("*")) for p in SENSITIVE_PATHS):
        return True
    return _basename(path) in _SENSITIVE_BASENAMES


def _in_system_dir(path: str) -> bool:
    return path.startswith(SYSTEM_DIRS)


def _looks_executable(path: str) -> bool:
    lowered = path.lower()
    if lowered.endswith(_EXEC_SUFFIXES):
        return True
    return path.startswith(_EXEC_DIRS)


def _path_entropy(paths: List[str]) -> float:
    """Shannon entropy of the concatenated path characters, scaled to ``[0, 1]``.

    Normalized by 8 bits (``log2(256)``) since paths are treated as byte strings.
    """
    if not paths:
        return 0.0
    blob = "".join(paths)
    if not blob:
        return 0.0

    counts: dict[str, int] = {}
    for ch in blob:
        counts[ch] = counts.get(ch, 0) + 1

    length = len(blob)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return min(entropy / 8.0, 1.0)


class FileFeatureExtractor:
    """Aggregates a window of file events into five access-pattern features."""

    @staticmethod
    def feature_names() -> List[str]:
        return [
            "unique_files_opened",
            "files_in_system_dirs",
            "executable_files_opened",
            "files_written_count",
            "entropy_of_file_paths",
        ]

    @staticmethod
    def dim() -> int:
        return 5

    def extract(self, events: List[FileEvent], window_seconds: int) -> List[float]:
        opened = set()
        system_dir_hits = 0
        executable_opens = 0
        writes = 0
        paths: List[str] = []

        for event in events:
            path = event.path or ""
            operation = event.operation
            paths.append(path)

            if operation == "open":
                opened.add(path)
                if _looks_executable(path):
                    executable_opens += 1
            elif operation == "write":
                writes += 1

            if _in_system_dir(path) or _is_sensitive(path):
                system_dir_hits += 1

        return [
            _saturate(len(opened), CAP_FILES),
            _saturate(system_dir_hits, CAP_FILES),
            _saturate(executable_opens, CAP_FILES),
            _saturate(writes, CAP_FILES),
            _path_entropy(paths),
        ]
