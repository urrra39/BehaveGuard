"""Feature extraction package.

Raw events -> sliding windows -> fixed-length feature vectors. numpy is only
pulled in lazily by :class:`FeatureExtractor.extract` and
:class:`FeatureNormalizer`, so importing this package never requires it.
"""

from behaveguard.features.extractor import FeatureExtractor
from behaveguard.features.file_features import FileFeatureExtractor
from behaveguard.features.network_features import NetworkFeatureExtractor
from behaveguard.features.normalizer import FeatureNormalizer
from behaveguard.features.process_features import ProcessFeatureExtractor
from behaveguard.features.syscall_features import SyscallFeatureExtractor
from behaveguard.features.window import PerProcessWindowManager, TimeWindow

__all__ = [
    "FeatureExtractor",
    "FeatureNormalizer",
    "SyscallFeatureExtractor",
    "NetworkFeatureExtractor",
    "FileFeatureExtractor",
    "ProcessFeatureExtractor",
    "TimeWindow",
    "PerProcessWindowManager",
]
