"""antguard observer. Watches process and network behavior patterns.

Pure system-level observation. No SDK. No code changes.
Detects known service endpoints, tool invocations, and
process behavior patterns by watching network destinations
and process trees.
"""

import time
import threading
from typing import List, Dict, Set, Optional
from dataclasses import dataclass, field, asdict

from .models import NetworkEvent, ProcessEvent, RiskLevel


# known service endpoints detected by network destination
KNOWN_ENDPOINTS = {
    "api.openai.com": "OpenAI",
    "api.anthropic.com": "Anthropic",
    "generativelanguage.googleapis.com": "Google",
    "aistudio.google.com": "Google",
    "api-inference.huggingface.co": "HuggingFace",
    "localhost:11434": "Ollama",
    "127.0.0.1:11434": "Ollama",
}

# patterns in destinations that indicate known services
ENDPOINT_PATTERNS = {
    ".openai.azure.com": "Azure OpenAI",
    ".anthropic.com": "Anthropic",
    ".googleapis.com": "Google",
}


@dataclass
class EndpointCall:
    """A detected call to a known service endpoint."""
    timestamp: float
    destination: str
    port: int
    service: str
    bytes_sent: int = 0
    bytes_recv: int = 0
    process_name: str = ""
    process_pid: int = 0
    latency_sec: float = 0.0

    def to_dict(self):
        return asdict(self)

    def to_log_line(self):
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp))
        return (
            f"[{ts}] ENDPOINT service={self.service} "
            f"dest={self.destination}:{self.port} "
            f"sent={self.bytes_sent} recv={self.bytes_recv} "
            f"proc={self.process_name}(pid {self.process_pid})"
        )


@dataclass
class FileToEndpointCorrelation:
    """Correlation between a file read and an endpoint call."""
    timestamp: float
    file_path: str
    file_size: int
    service: str
    destination: str
    time_gap_sec: float
    process_pid: int
    risk: RiskLevel = RiskLevel.HIGH

    def to_dict(self):
        d = asdict(self)
        d["risk"] = self.risk.name
        return d

    def to_log_line(self):
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp))
        return (
            f"[{ts}] FILE->ENDPOINT file={self.file_path} "
            f"-> {self.service}({self.destination}) "
            f"gap={self.time_gap_sec:.1f}s "
            f"risk={self.risk.name}"
        )


@dataclass
class ObserverSummary:
    """Summary of observed behavior."""
    total_endpoint_calls: int = 0
    services_contacted: List[str] = field(default_factory=list)
    calls_per_service: Dict[str, int] = field(default_factory=dict)
    total_bytes_sent: int = 0
    total_bytes_recv: int = 0
    file_to_endpoint_correlations: int = 0
    tool_processes_detected: int = 0
    framework_hint: str = ""

    def to_dict(self):
        return asdict(self)


class Observer:
    """System-level observer for process and network behavior.

    Detects known service endpoints, tracks call patterns,
    and correlates file access with endpoint calls.
    All observation is passive - no SDK, no code injection.

    Args:
        custom_endpoints: Extra endpoint mappings {destination: service_name}
        time_window_sec: Max gap between file read and endpoint call for correlation
    """

    def __init__(
        self,
        custom_endpoints: Optional[Dict[str, str]] = None,
        time_window_sec: float = 30.0,
    ):
        self._endpoints = dict(KNOWN_ENDPOINTS)
        if custom_endpoints:
            self._endpoints.update(custom_endpoints)

        self._time_window = time_window_sec
        self._calls: List[EndpointCall] = []
        self._file_correlations: List[FileToEndpointCorrelation] = []
        self._lock = threading.Lock()

    def _identify_service(self, destination: str, port: int) -> Optional[str]:
        """Identify service from network destination."""
        dest_port = f"{destination}:{port}"

        # exact match
        if dest_port in self._endpoints:
            return self._endpoints[dest_port]
        if destination in self._endpoints:
            return self._endpoints[destination]

        # pattern match
        for pattern, service in ENDPOINT_PATTERNS.items():
            if pattern in destination:
                return service

        return None

    def observe_network(self, event: NetworkEvent):
        """Check if a network event is a call to a known endpoint."""
        service = self._identify_service(event.destination, event.port)
        if not service:
            return

        call = EndpointCall(
            timestamp=event.timestamp,
            destination=event.destination,
            port=event.port,
            service=service,
            bytes_sent=event.bytes_sent,
            bytes_recv=event.bytes_recv,
            process_name=event.process_name,
            process_pid=event.process_pid,
        )

        with self._lock:
            self._calls.append(call)

    def correlate_files(self, file_events, network_events):
        """Correlate file reads with endpoint calls.

        Flags when a process reads a watched file and then
        contacts a known endpoint within the time window.
        """
        from .models import FileAction

        reads = [
            e for e in file_events
            if e.action in (FileAction.READ, FileAction.MODIFY)
            and e.size_bytes > 0
        ]

        for call in self._calls:
            for fev in reads:
                gap = call.timestamp - fev.timestamp
                if gap < 0 or gap > self._time_window:
                    continue
                if fev.process_pid != call.process_pid and call.process_pid > 0:
                    continue

                corr = FileToEndpointCorrelation(
                    timestamp=time.time(),
                    file_path=fev.path,
                    file_size=fev.size_bytes,
                    service=call.service,
                    destination=call.destination,
                    time_gap_sec=gap,
                    process_pid=call.process_pid,
                    risk=RiskLevel.HIGH,
                )
                with self._lock:
                    self._file_correlations.append(corr)

    @property
    def endpoint_calls(self) -> List[EndpointCall]:
        with self._lock:
            return list(self._calls)

    @property
    def file_to_endpoint(self) -> List[FileToEndpointCorrelation]:
        with self._lock:
            return list(self._file_correlations)

    def summarize(self) -> ObserverSummary:
        calls = self.endpoint_calls
        services = list(set(c.service for c in calls))
        calls_per = {}
        for c in calls:
            calls_per[c.service] = calls_per.get(c.service, 0) + 1

        return ObserverSummary(
            total_endpoint_calls=len(calls),
            services_contacted=services,
            calls_per_service=calls_per,
            total_bytes_sent=sum(c.bytes_sent for c in calls),
            total_bytes_recv=sum(c.bytes_recv for c in calls),
            file_to_endpoint_correlations=len(self._file_correlations),
        )
