"""Detector for IPv4 addresses (private network topology and public hosts)."""

import hashlib
import ipaddress
import re
from typing import List
from app.detection.base import BaseDetector, Detection
from app.models.response import SeverityLevel


class IPAddressDetector(BaseDetector):
    """Detects valid IPv4 addresses, ignoring version-like strings and trivial loopback/unspecified IPs."""

    name = "ip_address_detector"
    entity_type = "IP_ADDRESS"

    PATTERN = re.compile(
        r"(?<![\d.])((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})(?![\d]|\.\d)"
    )

    def detect(self, text: str) -> List[Detection]:
        detections: List[Detection] = []
        for match in self.PATTERN.finditer(text):
            raw_ip = match.group(1)
            try:
                ip = ipaddress.IPv4Address(raw_ip)
            except ValueError:
                continue

            # Loopback / unspecified / broadcast carry no infrastructure information
            if ip.is_loopback or ip.is_unspecified or raw_ip == "255.255.255.255":
                continue

            start, end = match.span(1)
            octets = raw_ip.split(".")
            ip_hash = hashlib.sha256(raw_ip.encode("utf-8")).hexdigest()[:12]
            detections.append(
                Detection(
                    type=self.entity_type,
                    start=start,
                    end=end,
                    confidence=0.9 if ip.is_private else 0.8,
                    severity=SeverityLevel.MEDIUM,
                    strategy="ipv4_octet_validation",
                    raw_value=raw_ip,
                    normalized_key=f"ip:{ip_hash}",
                    masked_value=f"{octets[0]}.***.***.{octets[3]}",
                )
            )
        return detections
