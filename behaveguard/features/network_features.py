"""Network-connection features derived from a window of NetworkEvent objects.

Counts and rates are squashed into ``[0, 1]`` with fixed saturating caps so the
extractor output is bounded without needing a fitted scaler; the booleans are
already 0/1. The Tor-port and RFC1918 flags are cheap, high-signal indicators of
anonymized C2 and lateral movement respectively.
"""

from __future__ import annotations

import ipaddress
from typing import List

from behaveguard.collector.event_types import NetworkEvent

# Saturating caps (value that maps to 1.0).
CAP_UNIQUE_IPS = 50.0
CAP_UNIQUE_PORTS = 50.0
CAP_CONN_RATE = 20.0          # outbound connections / second
CAP_BYTES_RATE = 1_000_000.0  # bytes / second

# Ports commonly used by Tor (SOCKS proxy, control, ORPort, dir).
TOR_PORTS = {9050, 9051, 9001, 9030}

_RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def _saturate(value: float, cap: float) -> float:
    """Map a non-negative ``value`` into ``[0, 1]`` saturating at ``cap``."""
    if cap <= 0.0:
        return 0.0
    return min(value / cap, 1.0)


def _is_rfc1918(ip: str) -> bool:
    """True if ``ip`` is a private RFC1918 address (ignores unparseable input)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _RFC1918)


class NetworkFeatureExtractor:
    """Aggregates a window of network events into seven connection features."""

    @staticmethod
    def feature_names() -> List[str]:
        return [
            "unique_remote_ips",
            "unique_remote_ports",
            "outbound_connection_rate",
            "bytes_sent_per_second",
            "bytes_recv_per_second",
            "is_using_tor_port",
            "is_connecting_to_rfc1918",
        ]

    @staticmethod
    def dim() -> int:
        return 7

    def extract(self, events: List[NetworkEvent], window_seconds: int) -> List[float]:
        seconds = float(max(window_seconds, 1))

        remote_ips = set()
        remote_ports = set()
        outbound_conns = 0
        bytes_sent = 0
        bytes_recv = 0
        uses_tor = 0.0
        hits_rfc1918 = 0.0

        for event in events:
            dst_ip = event.dst_ip
            dst_port = int(event.dst_port)
            remote_ips.add(dst_ip)
            remote_ports.add(dst_port)

            if event.direction == "outbound":
                outbound_conns += 1
                bytes_sent += int(event.bytes_count)
            else:
                bytes_recv += int(event.bytes_count)

            if dst_port in TOR_PORTS:
                uses_tor = 1.0
            if _is_rfc1918(dst_ip):
                hits_rfc1918 = 1.0

        return [
            _saturate(len(remote_ips), CAP_UNIQUE_IPS),
            _saturate(len(remote_ports), CAP_UNIQUE_PORTS),
            _saturate(outbound_conns / seconds, CAP_CONN_RATE),
            _saturate(bytes_sent / seconds, CAP_BYTES_RATE),
            _saturate(bytes_recv / seconds, CAP_BYTES_RATE),
            uses_tor,
            hits_rfc1918,
        ]
