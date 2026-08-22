"""
antguard - Guard. Detect. Protect.

Pure system-level profiler for AI data privacy.
Like cProfile, but for data movement.

No AI. No API. No cloud. No regex.

Usage:
    from antguard import Guard

    with Guard(watch=["./data/"]) as g:
        # your code runs here unchanged
        agent.run("process files")

    print(g.did_data_leave())
    g.save("./logs/")
"""

__version__ = "0.1.0"
__author__ = "VK-Ant (Venkatkumar Rajan)"
__tagline__ = "Guard. Detect. Protect."

import os
import time
import uuid
from typing import List, Optional, Dict

from .models import (
    FileEvent,
    NetworkEvent,
    ProcessEvent,
    CorrelationMatch,
    RuntimeSnapshot,
    RuntimeSummary,
    RiskLevel,
)
from .file_profiler import FileProfiler
from .network_profiler import NetworkProfiler
from .process_profiler import ProcessProfiler
from .correlation import CorrelationEngine
from .runtime_profiler import RuntimeProfiler
from .audit_logger import AuditLogger


class Guard:
    """Main antguard profiler. Wraps your code like cProfile.

    Args:
        watch: List of directories/files to monitor.
        detect_outbound: Enable network boundary monitoring.
        track_processes: Enable process tree monitoring.
        correlate: Enable byte-flow correlation engine.
        runtime: Enable CPU/GPU/memory/disk metrics.
        gpu: Enable GPU monitoring (requires pynvml for NVIDIA).
        network_allow_list: Known-safe network destinations.
        log_path: Directory for log output.
        log_format: Output format (log, txt, json).
        stream_to_disk: Stream events to disk immediately.
        max_log_size_mb: Max log file size before rotation.
        chunk_size: Chunk size for file fingerprinting (bytes).
        runtime_interval: Metrics sampling interval (seconds).
        network_interval: Network polling interval (seconds).
        process_interval: Process polling interval (seconds).
        correlation_time_window: Max seconds between file read
            and network send for correlation.
    """

    def __init__(
        self,
        watch: Optional[List[str]] = None,
        detect_outbound: bool = True,
        track_processes: bool = True,
        correlate: bool = True,
        runtime: bool = True,
        gpu: bool = True,
        network_allow_list: Optional[List[str]] = None,
        log_path: str = "./antguard_logs",
        log_format: str = "log",
        stream_to_disk: bool = True,
        max_log_size_mb: int = 10,
        chunk_size: int = 4096,
        runtime_interval: float = 1.0,
        network_interval: float = 1.0,
        process_interval: float = 1.0,
        correlation_time_window: float = 30.0,
    ):
        self._watch = watch or []
        self._detect_outbound = detect_outbound
        self._track_processes = track_processes
        self._correlate = correlate
        self._runtime_enabled = runtime
        self._gpu = gpu

        self._session_id = str(uuid.uuid4())[:8]
        self._start_time: float = 0
        self._stop_time: float = 0
        self._running = False

        # profilers
        self._file_profiler: Optional[FileProfiler] = None
        self._net_profiler: Optional[NetworkProfiler] = None
        self._proc_profiler: Optional[ProcessProfiler] = None
        self._runtime_profiler: Optional[RuntimeProfiler] = None
        self._correlation_engine: Optional[CorrelationEngine] = None

        # logger
        self._logger = AuditLogger(
            log_path=log_path,
            log_format=log_format,
            max_log_size_mb=max_log_size_mb,
            stream_to_disk=stream_to_disk,
        )

        # config
        self._chunk_size = chunk_size
        self._network_allow_list = network_allow_list
        self._runtime_interval = runtime_interval
        self._network_interval = network_interval
        self._process_interval = process_interval
        self._correlation_time_window = correlation_time_window

        # cached results
        self._correlations: List[CorrelationMatch] = []
        self._overall_risk: RiskLevel = RiskLevel.LOW
        self._data_left: Optional[bool] = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False

    def start(self):
        """Start all profilers."""
        self._start_time = time.time()
        self._running = True
        self._data_left = None

        self._logger.start(self._session_id)

        # file profiler
        if self._watch:
            self._file_profiler = FileProfiler(
                watch_paths=self._watch,
                chunk_size=self._chunk_size,
                on_event=lambda e: self._logger.log_event(e),
            )
            self._file_profiler.start()

        # network profiler
        if self._detect_outbound:
            self._net_profiler = NetworkProfiler(
                allow_list=self._network_allow_list,
                interval=self._network_interval,
                on_event=lambda e: self._logger.log_event(e),
            )
            self._net_profiler.start()

        # process profiler
        if self._track_processes:
            self._proc_profiler = ProcessProfiler(
                interval=self._process_interval,
                on_event=lambda e: self._logger.log_event(e),
            )
            self._proc_profiler.start()

        # runtime profiler
        if self._runtime_enabled:
            self._runtime_profiler = RuntimeProfiler(
                interval=self._runtime_interval,
                track_gpu=self._gpu,
            )
            self._runtime_profiler.start()

        # correlation engine
        if self._correlate:
            self._correlation_engine = CorrelationEngine(
                time_window_sec=self._correlation_time_window,
                chunk_size=self._chunk_size,
            )

    def stop(self):
        """Stop all profilers and run correlation."""
        self._stop_time = time.time()
        self._running = False

        if self._file_profiler:
            self._file_profiler.stop()
        if self._net_profiler:
            self._net_profiler.stop()
        if self._proc_profiler:
            self._proc_profiler.stop()
        if self._runtime_profiler:
            self._runtime_profiler.stop()

        # run correlation
        if (
            self._correlation_engine
            and self._file_profiler
            and self._net_profiler
        ):
            self._correlation_engine.update_fingerprints(
                self._file_profiler.fingerprints
            )
            self._correlations = self._correlation_engine.correlate(
                self._file_profiler.events,
                self._net_profiler.events,
            )

        # compute overall risk
        self._compute_risk()

        self._logger.stop()

    def _compute_risk(self):
        risk = RiskLevel.LOW

        # correlations = highest priority
        if self._correlations:
            max_corr_risk = max(m.risk for m in self._correlations)
            if max_corr_risk.value in ("HIGH", "CRITICAL"):
                risk = max_corr_risk

        # external network with no correlation
        if self._net_profiler:
            ext = self._net_profiler.get_external()
            if ext and risk == RiskLevel.LOW:
                risk = RiskLevel.MEDIUM

            high_risk_net = self._net_profiler.get_high_risk()
            if high_risk_net and risk.value not in ("HIGH", "CRITICAL"):
                risk = RiskLevel.HIGH

        # suspicious processes
        if self._proc_profiler:
            suspicious = self._proc_profiler.get_suspicious()
            if suspicious and risk == RiskLevel.LOW:
                risk = RiskLevel.MEDIUM

        self._overall_risk = risk

    # --- Public Query API ---

    def did_data_leave(self) -> bool:
        """The one answer that matters: did any data leave this machine?"""
        if self._data_left is not None:
            return self._data_left

        # check network events for external connections
        if self._net_profiler:
            ext = self._net_profiler.get_external()
            if ext:
                self._data_left = True
                return True

        # check correlations
        if self._correlations:
            self._data_left = True
            return True

        self._data_left = False
        return False

    def file_events(self) -> List[FileEvent]:
        """All file events recorded during session."""
        if self._file_profiler:
            return self._file_profiler.events
        return []

    def net_events(self) -> List[NetworkEvent]:
        """All network events recorded during session."""
        if self._net_profiler:
            return self._net_profiler.events
        return []

    def proc_events(self) -> List[ProcessEvent]:
        """All process events recorded during session."""
        if self._proc_profiler:
            return self._proc_profiler.events
        return []

    def correlations(self) -> List[CorrelationMatch]:
        """Byte-flow correlation matches (file -> network)."""
        return list(self._correlations)

    def matched_files(self) -> List[str]:
        """Files whose data was detected in outbound connections."""
        return list(set(m.source_file for m in self._correlations))

    def runtime_metrics(self) -> Optional[RuntimeSummary]:
        """Runtime metrics summary (CPU, GPU, memory, disk)."""
        if self._runtime_profiler:
            return self._runtime_profiler.summarize()
        return None

    def risk_level(self) -> RiskLevel:
        """Overall risk level for the session."""
        return self._overall_risk

    def fingerprints(self) -> Dict[str, dict]:
        """File fingerprints (hash + chunk hashes)."""
        if self._file_profiler:
            return self._file_profiler.fingerprints
        return {}

    def data_flow_map(self) -> dict:
        """Summary of data flow: files in, data out."""
        files_in = {}
        if self._file_profiler:
            for ev in self._file_profiler.events:
                if ev.path not in files_in:
                    files_in[ev.path] = {
                        "size": ev.size_bytes,
                        "actions": [],
                        "hash": ev.file_hash,
                    }
                files_in[ev.path]["actions"].append(ev.action.value)

        data_out = []
        if self._net_profiler:
            for ev in self._net_profiler.get_external():
                data_out.append({
                    "destination": f"{ev.destination}:{ev.port}",
                    "bytes_sent": ev.bytes_sent,
                    "process": ev.process_name,
                })

        corr = []
        for m in self._correlations:
            corr.append({
                "file": m.source_file,
                "destination": f"{m.destination}:{m.destination_port}",
                "confidence": m.confidence,
                "method": m.method,
            })

        return {
            "files_accessed": files_in,
            "outbound": data_out,
            "correlations": corr,
            "data_left": self.did_data_leave(),
        }

    def anomalies(self) -> List[str]:
        """Detected runtime anomalies."""
        rs = self.runtime_metrics()
        if rs:
            return rs.anomalies
        return []

    def save(self, output_dir: Optional[str] = None) -> dict:
        """Save .log + .txt + .json reports.

        Returns dict with file paths: {"txt": ..., "json": ..., "log": ...}
        """
        return self._logger.save_report(
            file_events=self.file_events(),
            network_events=self.net_events(),
            process_events=self.proc_events(),
            correlations=self.correlations(),
            runtime_summary=self.runtime_metrics(),
            data_left=self.did_data_leave(),
            overall_risk=self._overall_risk,
            output_dir=output_dir,
        )

    def to_dict(self) -> dict:
        """Full session report as dict."""
        return {
            "session_id": self._session_id,
            "data_left_system": self.did_data_leave(),
            "risk_level": self._overall_risk.value,
            "file_events": len(self.file_events()),
            "network_events": len(self.net_events()),
            "process_events": len(self.proc_events()),
            "correlations": len(self.correlations()),
            "matched_files": self.matched_files(),
            "anomalies": self.anomalies(),
        }

    def summary(self) -> str:
        """One-line summary."""
        return (
            f"antguard: data_left={self.did_data_leave()} "
            f"risk={self._overall_risk.value} "
            f"files={len(self.file_events())} "
            f"net={len(self.net_events())} "
            f"proc={len(self.proc_events())} "
            f"correlations={len(self.correlations())}"
        )
