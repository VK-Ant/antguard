"""antguard event models. All profiler events as lightweight dataclasses."""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional
import time


class RiskLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FileAction(Enum):
    READ = "READ"
    WRITE = "WRITE"
    CREATE = "CREATE"
    DELETE = "DELETE"
    MOVE = "MOVE"
    RENAME = "RENAME"
    MODIFY = "MODIFY"


class NetDirection(Enum):
    OUTBOUND = "OUTBOUND"
    INBOUND = "INBOUND"


class ProcessEventType(Enum):
    CREATED = "CREATED"
    TERMINATED = "TERMINATED"
    SHELL_EXEC = "SHELL_EXEC"
    SUSPICIOUS = "SUSPICIOUS"


@dataclass
class FileEvent:
    timestamp: float
    action: FileAction
    path: str
    size_bytes: int = 0
    file_hash: str = ""
    process_name: str = ""
    process_pid: int = 0
    parent_process: str = ""
    parent_pid: int = 0
    risk: RiskLevel = RiskLevel.LOW

    def to_dict(self):
        d = asdict(self)
        d["action"] = self.action.value
        d["risk"] = self.risk.value
        return d

    def to_log_line(self):
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp))
        return (
            f"[{ts}] FILE  action={self.action.value} "
            f"path={self.path} bytes={self.size_bytes} "
            f"hash={self.file_hash[:12]} pid={self.process_pid} "
            f"proc={self.process_name} risk={self.risk.value}"
        )


@dataclass
class NetworkEvent:
    timestamp: float
    direction: NetDirection
    destination: str
    port: int
    protocol: str = "TCP"
    bytes_sent: int = 0
    bytes_recv: int = 0
    process_name: str = ""
    process_pid: int = 0
    first_seen: bool = False
    is_external: bool = False
    risk: RiskLevel = RiskLevel.LOW

    def to_dict(self):
        d = asdict(self)
        d["direction"] = self.direction.value
        d["risk"] = self.risk.value
        return d

    def to_log_line(self):
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp))
        return (
            f"[{ts}] NET   dir={self.direction.value} "
            f"dest={self.destination}:{self.port} "
            f"sent={self.bytes_sent} recv={self.bytes_recv} "
            f"pid={self.process_pid} proc={self.process_name} "
            f"external={self.is_external} first_seen={self.first_seen} "
            f"risk={self.risk.value}"
        )


@dataclass
class ProcessEvent:
    timestamp: float
    event_type: ProcessEventType
    name: str
    pid: int
    parent_name: str = ""
    parent_pid: int = 0
    command: str = ""
    risk: RiskLevel = RiskLevel.LOW

    def to_dict(self):
        d = asdict(self)
        d["event_type"] = self.event_type.value
        d["risk"] = self.risk.value
        return d

    def to_log_line(self):
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp))
        return (
            f"[{ts}] PROC  event={self.event_type.value} "
            f"name={self.name} pid={self.pid} "
            f"parent={self.parent_name}({self.parent_pid}) "
            f"cmd={self.command[:80]} risk={self.risk.value}"
        )


@dataclass
class CorrelationMatch:
    timestamp: float
    source_file: str
    source_hash: str
    destination: str
    destination_port: int
    method: str  # chunk_hash, size, temporal
    confidence: float  # 0.0 to 1.0
    file_size: int = 0
    outbound_size: int = 0
    time_gap_sec: float = 0.0
    process_pid: int = 0
    risk: RiskLevel = RiskLevel.HIGH

    def to_dict(self):
        d = asdict(self)
        d["risk"] = self.risk.value
        return d

    def to_log_line(self):
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp))
        return (
            f"[{ts}] CORR  file={self.source_file} -> "
            f"{self.destination}:{self.destination_port} "
            f"method={self.method} confidence={self.confidence:.2f} "
            f"file_bytes={self.file_size} out_bytes={self.outbound_size} "
            f"gap={self.time_gap_sec:.1f}s risk={self.risk.value}"
        )


@dataclass
class RuntimeSnapshot:
    timestamp: float
    cpu_percent: float = 0.0
    cpu_per_core: list = field(default_factory=list)
    memory_used_bytes: int = 0
    memory_total_bytes: int = 0
    memory_percent: float = 0.0
    process_rss_bytes: int = 0
    disk_read_bytes: int = 0
    disk_write_bytes: int = 0
    gpu_utilization: float = -1.0  # -1 = not available
    gpu_memory_used_bytes: int = -1
    gpu_memory_total_bytes: int = -1
    gpu_temperature: float = -1.0

    def to_dict(self):
        return asdict(self)


@dataclass
class RuntimeSummary:
    duration_sec: float = 0.0
    cpu_avg: float = 0.0
    cpu_peak: float = 0.0
    cpu_peak_time: float = 0.0
    memory_avg_bytes: int = 0
    memory_peak_bytes: int = 0
    memory_peak_time: float = 0.0
    process_rss_avg: int = 0
    process_rss_peak: int = 0
    disk_total_read: int = 0
    disk_total_write: int = 0
    gpu_avg_util: float = -1.0
    gpu_peak_util: float = -1.0
    gpu_memory_avg: int = -1
    gpu_memory_peak: int = -1
    gpu_temperature_avg: float = -1.0
    gpu_temperature_peak: float = -1.0
    snapshot_count: int = 0
    anomalies: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)
