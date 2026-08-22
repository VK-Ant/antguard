"""antguard correlation engine. Matches file data to outbound network data."""

import time
from typing import List, Dict, Optional

from .models import (
    FileEvent, NetworkEvent, CorrelationMatch,
    FileAction, RiskLevel,
)


# known encoding size ratios
SIZE_RATIOS = {
    "raw": (0.95, 1.05),
    "base64": (1.28, 1.40),
    "gzip": (0.1, 0.8),
    "partial": (0.01, 0.95),
}


class CorrelationEngine:

    def __init__(
        self,
        file_fingerprints: Optional[Dict[str, dict]] = None,
        time_window_sec: float = 30.0,
        chunk_size: int = 4096,
    ):
        self._fingerprints = file_fingerprints or {}
        self._time_window = time_window_sec
        self._chunk_size = chunk_size
        self._matches: List[CorrelationMatch] = []

    def update_fingerprints(self, fingerprints: Dict[str, dict]):
        self._fingerprints.update(fingerprints)

    def correlate(
        self,
        file_events: List[FileEvent],
        network_events: List[NetworkEvent],
    ) -> List[CorrelationMatch]:
        self._matches = []

        read_events = [
            e for e in file_events
            if e.action in (FileAction.READ, FileAction.MODIFY, FileAction.CREATE)
            and e.size_bytes > 0
        ]

        outbound_events = [
            e for e in network_events
            if e.is_external and e.bytes_sent > 0
        ]

        if not read_events or not outbound_events:
            return self._matches

        for net_ev in outbound_events:
            for file_ev in read_events:
                match = self._check_correlation(file_ev, net_ev)
                if match:
                    self._matches.append(match)

        return self._matches

    def _check_correlation(
        self,
        file_ev: FileEvent,
        net_ev: NetworkEvent,
    ) -> Optional[CorrelationMatch]:
        methods = []
        confidence = 0.0

        # 1. temporal correlation
        time_gap = net_ev.timestamp - file_ev.timestamp
        if time_gap < 0 or time_gap > self._time_window:
            return None

        temporal_score = max(0, 1.0 - (time_gap / self._time_window))
        if temporal_score > 0.1:
            methods.append("temporal")
            confidence += temporal_score * 0.3

        # 2. same process correlation
        if file_ev.process_pid == net_ev.process_pid and file_ev.process_pid > 0:
            methods.append("same_process")
            confidence += 0.3

        # 3. size correlation
        size_score = self._size_correlation(file_ev.size_bytes, net_ev.bytes_sent)
        if size_score > 0:
            methods.append("size")
            confidence += size_score * 0.2

        # 4. chunk hash correlation
        chunk_score = self._chunk_correlation(file_ev.path)
        if chunk_score > 0:
            methods.append("chunk_hash")
            confidence += chunk_score * 0.2

        confidence = min(confidence, 1.0)

        if confidence < 0.3:
            return None

        risk = RiskLevel.MEDIUM
        if confidence >= 0.7:
            risk = RiskLevel.CRITICAL
        elif confidence >= 0.5:
            risk = RiskLevel.HIGH

        return CorrelationMatch(
            timestamp=time.time(),
            source_file=file_ev.path,
            source_hash=file_ev.file_hash,
            destination=net_ev.destination,
            destination_port=net_ev.port,
            method="+".join(methods),
            confidence=confidence,
            file_size=file_ev.size_bytes,
            outbound_size=net_ev.bytes_sent,
            time_gap_sec=time_gap,
            process_pid=net_ev.process_pid,
            risk=risk,
        )

    def _size_correlation(self, file_size: int, out_size: int) -> float:
        if file_size == 0 or out_size == 0:
            return 0.0

        ratio = out_size / file_size

        # check each encoding ratio
        best_score = 0.0
        for encoding, (low, high) in SIZE_RATIOS.items():
            if low <= ratio <= high:
                # closer to center of range = higher score
                center = (low + high) / 2
                spread = (high - low) / 2
                dist = abs(ratio - center) / spread
                score = 1.0 - dist
                best_score = max(best_score, score)

        return best_score

    def _chunk_correlation(self, filepath: str) -> float:
        fp = self._fingerprints.get(filepath)
        if not fp or not fp.get("chunks"):
            return 0.0
        # chunks exist = file is fingerprinted = correlation possible
        # actual outbound chunk matching would require payload inspection
        # return baseline score for having fingerprints ready
        return 0.1

    @property
    def matches(self) -> List[CorrelationMatch]:
        return list(self._matches)

    def has_matches(self) -> bool:
        return len(self._matches) > 0
