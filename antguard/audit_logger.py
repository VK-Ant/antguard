"""antguard audit logger. Lightweight log/txt/json output."""

import json
import os
import time
import threading
from typing import List, Optional, TextIO, Union

from .models import (
    FileEvent, NetworkEvent, ProcessEvent,
    CorrelationMatch, RuntimeSummary, RiskLevel,
)
from .utils import get_platform_info, format_bytes


class AuditLogger:

    def __init__(
        self,
        log_path: str = "./logs",
        log_format: str = "log",
        max_log_size_mb: int = 10,
        stream_to_disk: bool = True,
    ):
        self._log_path = log_path
        self._log_format = log_format
        self._max_log_size = max_log_size_mb * 1024 * 1024
        self._stream = stream_to_disk
        self._lock = threading.Lock()
        self._log_file: Optional[TextIO] = None
        self._log_filepath: str = ""
        self._session_id: str = ""
        self._start_time: float = 0
        self._bytes_written: int = 0

    def start(self, session_id: str):
        self._session_id = session_id
        self._start_time = time.time()
        os.makedirs(self._log_path, exist_ok=True)

        ts = time.strftime("%Y%m%d_%H%M%S")
        self._log_filepath = os.path.join(
            self._log_path, f"antguard_{ts}.{self._log_format}"
        )

        if self._stream:
            self._log_file = open(self._log_filepath, "a", encoding="utf-8")
            self._write_line(
                f"[{self._ts()}] START session={session_id} "
                f"platform={get_platform_info()['system']}"
            )

    def stop(self):
        if self._log_file:
            self._log_file.close()
            self._log_file = None

    def _ts(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S")

    def _write_line(self, line: str):
        if not self._log_file:
            return
        with self._lock:
            self._log_file.write(line + "\n")
            self._log_file.flush()
            self._bytes_written += len(line) + 1
            if self._bytes_written >= self._max_log_size:
                self._rotate()

    def _rotate(self):
        if self._log_file:
            self._log_file.close()
        ts = time.strftime("%Y%m%d_%H%M%S")
        self._log_filepath = os.path.join(
            self._log_path, f"antguard_{ts}.{self._log_format}"
        )
        self._log_file = open(self._log_filepath, "a", encoding="utf-8")
        self._bytes_written = 0

    def log_event(self, event: Union[FileEvent, NetworkEvent, ProcessEvent, CorrelationMatch]):
        if self._stream and self._log_file:
            self._write_line(event.to_log_line())

    def save_report(
        self,
        file_events: List[FileEvent],
        network_events: List[NetworkEvent],
        process_events: List[ProcessEvent],
        correlations: List[CorrelationMatch],
        runtime_summary: Optional[RuntimeSummary],
        data_left: bool,
        overall_risk: RiskLevel,
        output_dir: Optional[str] = None,
    ):
        out = output_dir or self._log_path
        os.makedirs(out, exist_ok=True)

        ts = time.strftime("%Y%m%d_%H%M%S")
        duration = time.time() - self._start_time if self._start_time else 0

        # save .txt summary
        txt_path = os.path.join(out, f"antguard_report_{ts}.txt")
        with open(txt_path, "w", encoding="utf-8") as f:
            self._write_txt_report(
                f, file_events, network_events, process_events,
                correlations, runtime_summary, data_left, overall_risk, duration,
            )

        # save .json
        json_path = os.path.join(out, f"antguard_report_{ts}.json")
        with open(json_path, "w", encoding="utf-8") as f:
            self._write_json_report(
                f, file_events, network_events, process_events,
                correlations, runtime_summary, data_left, overall_risk, duration,
            )

        # finalize .log
        if self._stream and self._log_file:
            self._write_line(
                f"[{self._ts()}] STOP  session={self._session_id} "
                f"duration={duration:.1f}s "
                f"file_events={len(file_events)} "
                f"net_events={len(network_events)} "
                f"proc_events={len(process_events)} "
                f"correlations={len(correlations)} "
                f"data_left={'YES' if data_left else 'NO'} "
                f"risk={overall_risk.name}"
            )

        return {"txt": txt_path, "json": json_path, "log": self._log_filepath}

    def _write_txt_report(
        self, f, file_events, network_events, process_events,
        correlations, runtime_summary, data_left, overall_risk, duration,
    ):
        plat = get_platform_info()
        f.write("antguard Profiler Report\n")
        f.write("=" * 50 + "\n")
        f.write(f"Session    : {self._session_id}\n")
        f.write(f"Platform   : {plat['system']} ({plat['release']})\n")
        f.write(f"Python     : {plat['python']}\n")
        f.write(f"Duration   : {duration:.1f} seconds\n")
        f.write(f"\n")
        f.write(f"DATA LEFT SYSTEM: {'YES' if data_left else 'NO'}")
        if data_left:
            f.write(" !!!\n")
        else:
            f.write("\n")
        f.write(f"\n")

        # file events
        f.write(f"-- FILE EVENTS ({len(file_events)}) --\n")
        if file_events:
            for ev in file_events:
                f.write(f"  [{ev.action.value:8s}] {ev.path}  "
                        f"{format_bytes(ev.size_bytes)}  "
                        f"{ev.process_name}(pid {ev.process_pid})  "
                        f"{ev.risk.name}\n")
        else:
            f.write("  None\n")
        f.write("\n")

        # network events
        f.write(f"-- NETWORK EVENTS ({len(network_events)}) --\n")
        if network_events:
            for ev in network_events:
                ext = "EXTERNAL" if ev.is_external else "LOCAL"
                f.write(f"  [{ext:8s}] {ev.destination}:{ev.port}  "
                        f"sent={format_bytes(ev.bytes_sent)}  "
                        f"{ev.process_name}(pid {ev.process_pid})  "
                        f"first_seen={ev.first_seen}  {ev.risk.name}\n")
        else:
            f.write("  None\n")
        f.write("\n")

        # process events
        suspicious = [e for e in process_events
                      if e.risk in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)]
        f.write(f"-- PROCESS EVENTS ({len(process_events)} total, {len(suspicious)} suspicious) --\n")
        if suspicious:
            for ev in suspicious:
                f.write(f"  [{ev.event_type.name:12s}] {ev.name}(pid {ev.pid})  "
                        f"parent={ev.parent_name}({ev.parent_pid})  "
                        f"cmd={ev.command[:60]}  {ev.risk.name}\n")
        elif process_events:
            f.write("  All processes normal\n")
        else:
            f.write("  None\n")
        f.write("\n")

        # correlations
        f.write(f"-- BYTE-FLOW CORRELATIONS ({len(correlations)}) --\n")
        if correlations:
            for m in correlations:
                f.write(f"  {os.path.basename(m.source_file)} -> "
                        f"{m.destination}:{m.destination_port}  "
                        f"method={m.method}  confidence={m.confidence:.2f}  "
                        f"file={format_bytes(m.file_size)} out={format_bytes(m.outbound_size)}  "
                        f"gap={m.time_gap_sec:.1f}s  {m.risk.name}\n")
        else:
            f.write("  No file-to-network correlations detected\n")
        f.write("\n")

        # runtime
        if runtime_summary and runtime_summary.snapshot_count > 0:
            rs = runtime_summary
            f.write(f"-- RUNTIME METRICS ({rs.snapshot_count} samples) --\n")
            f.write(f"  CPU avg/peak    : {rs.cpu_avg:.1f}% / {rs.cpu_peak:.1f}%\n")
            f.write(f"  Memory avg/peak : {format_bytes(rs.memory_avg_bytes)} / {format_bytes(rs.memory_peak_bytes)}\n")
            f.write(f"  Process RSS     : {format_bytes(rs.process_rss_avg)} avg, {format_bytes(rs.process_rss_peak)} peak\n")
            f.write(f"  Disk read       : {format_bytes(rs.disk_total_read)}\n")
            f.write(f"  Disk write      : {format_bytes(rs.disk_total_write)}\n")
            if rs.gpu_avg_util >= 0:
                f.write(f"  GPU util        : {rs.gpu_avg_util:.1f}% avg, {rs.gpu_peak_util:.1f}% peak\n")
                if rs.gpu_memory_avg >= 0:
                    f.write(f"  GPU memory      : {format_bytes(rs.gpu_memory_avg)} avg, {format_bytes(rs.gpu_memory_peak)} peak\n")
                if rs.gpu_temperature_avg >= 0:
                    f.write(f"  GPU temp        : {rs.gpu_temperature_avg:.0f}C avg, {rs.gpu_temperature_peak:.0f}C peak\n")
            else:
                f.write(f"  GPU             : not detected\n")

            if rs.anomalies:
                f.write(f"\n  ANOMALIES:\n")
                for a in rs.anomalies:
                    f.write(f"    {a}\n")
            f.write("\n")

        # overall
        f.write("=" * 50 + "\n")
        f.write(f"OVERALL RISK: {overall_risk.name}\n")
        if data_left:
            f.write("REASON: Data detected leaving system boundary\n")
        f.write("=" * 50 + "\n")

    def _write_json_report(
        self, f, file_events, network_events, process_events,
        correlations, runtime_summary, data_left, overall_risk, duration,
    ):
        plat = get_platform_info()
        report = {
            "antguard_version": "0.2.0",
            "session_id": self._session_id,
            "platform": plat,
            "start_time": time.strftime(
                "%Y-%m-%dT%H:%M:%S",
                time.localtime(self._start_time),
            ),
            "duration_sec": round(duration, 1),
            "data_left_system": data_left,
            "overall_risk": overall_risk.name,
            "summary": {
                "file_events": len(file_events),
                "network_events": len(network_events),
                "process_events": len(process_events),
                "correlations": len(correlations),
                "suspicious_processes": len([
                    e for e in process_events
                    if e.risk in (RiskLevel.HIGH, RiskLevel.CRITICAL)
                ]),
                "external_connections": len([
                    e for e in network_events if e.is_external
                ]),
            },
            "file_events": [e.to_dict() for e in file_events],
            "network_events": [e.to_dict() for e in network_events],
            "process_events": [e.to_dict() for e in process_events],
            "correlations": [m.to_dict() for m in correlations],
        }

        if runtime_summary and runtime_summary.snapshot_count > 0:
            report["runtime"] = runtime_summary.to_dict()

        json.dump(report, f, indent=2, default=str)
