"""antguard runtime profiler. CPU, GPU, memory, disk metrics."""

import time
import threading
from typing import List, Optional, Callable

import psutil

from .models import RuntimeSnapshot, RuntimeSummary


def _try_gpu_metrics() -> dict:
    """Attempt GPU metrics. Returns dict with gpu fields or empty."""
    # try NVIDIA via pynvml
    try:
        import pynvml
        pynvml.nvmlInit()
        handle = pynvml.nvmlDeviceGetHandleByIndex(0)
        util = pynvml.nvmlDeviceGetUtilizationRates(handle)
        mem = pynvml.nvmlDeviceGetMemoryInfo(handle)
        try:
            temp = pynvml.nvmlDeviceGetTemperature(
                handle, pynvml.NVML_TEMPERATURE_GPU
            )
        except Exception:
            temp = -1.0
        return {
            "gpu_utilization": float(util.gpu),
            "gpu_memory_used_bytes": int(mem.used),
            "gpu_memory_total_bytes": int(mem.total),
            "gpu_temperature": float(temp),
        }
    except Exception:
        pass

    return {
        "gpu_utilization": -1.0,
        "gpu_memory_used_bytes": -1,
        "gpu_memory_total_bytes": -1,
        "gpu_temperature": -1.0,
    }


class RuntimeProfiler:

    def __init__(
        self,
        interval: float = 1.0,
        track_gpu: bool = True,
        on_snapshot: Optional[Callable] = None,
    ):
        self._interval = interval
        self._track_gpu = track_gpu
        self._on_snapshot = on_snapshot
        self._snapshots: List[RuntimeSnapshot] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._process = psutil.Process()
        self._disk_start = None

    def _poll(self):
        # prime cpu_percent
        psutil.cpu_percent(interval=None)
        self._process.cpu_percent(interval=None)

        try:
            self._disk_start = psutil.disk_io_counters()
        except Exception:
            self._disk_start = None

        while self._running:
            try:
                self._take_snapshot()
            except Exception:
                pass
            time.sleep(self._interval)

    def _take_snapshot(self):
        now = time.time()

        # CPU
        cpu_pct = psutil.cpu_percent(interval=None)
        cpu_cores = psutil.cpu_percent(interval=None, percpu=True)

        # Memory
        vmem = psutil.virtual_memory()

        # Process memory
        try:
            proc_mem = self._process.memory_info()
            proc_rss = proc_mem.rss
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            proc_rss = 0

        # Disk I/O
        disk_read = 0
        disk_write = 0
        try:
            dio = psutil.disk_io_counters()
            if dio and self._disk_start:
                disk_read = dio.read_bytes
                disk_write = dio.write_bytes
        except Exception:
            pass

        # GPU
        gpu = {"gpu_utilization": -1.0, "gpu_memory_used_bytes": -1,
               "gpu_memory_total_bytes": -1, "gpu_temperature": -1.0}
        if self._track_gpu:
            gpu = _try_gpu_metrics()

        snap = RuntimeSnapshot(
            timestamp=now,
            cpu_percent=cpu_pct,
            cpu_per_core=cpu_cores,
            memory_used_bytes=vmem.used,
            memory_total_bytes=vmem.total,
            memory_percent=vmem.percent,
            process_rss_bytes=proc_rss,
            disk_read_bytes=disk_read,
            disk_write_bytes=disk_write,
            **gpu,
        )

        with self._lock:
            self._snapshots.append(snap)

        if self._on_snapshot:
            self._on_snapshot(snap)

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._poll, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    @property
    def snapshots(self) -> List[RuntimeSnapshot]:
        with self._lock:
            return list(self._snapshots)

    def summarize(self) -> RuntimeSummary:
        snaps = self.snapshots
        if not snaps:
            return RuntimeSummary()

        duration = snaps[-1].timestamp - snaps[0].timestamp if len(snaps) > 1 else 0

        # CPU
        cpu_vals = [s.cpu_percent for s in snaps]
        cpu_avg = sum(cpu_vals) / len(cpu_vals) if cpu_vals else 0
        cpu_peak = max(cpu_vals) if cpu_vals else 0
        cpu_peak_snap = max(snaps, key=lambda s: s.cpu_percent)

        # Memory
        mem_vals = [s.memory_used_bytes for s in snaps]
        mem_avg = int(sum(mem_vals) / len(mem_vals)) if mem_vals else 0
        mem_peak = max(mem_vals) if mem_vals else 0
        mem_peak_snap = max(snaps, key=lambda s: s.memory_used_bytes)

        # Process RSS
        rss_vals = [s.process_rss_bytes for s in snaps if s.process_rss_bytes > 0]
        rss_avg = int(sum(rss_vals) / len(rss_vals)) if rss_vals else 0
        rss_peak = max(rss_vals) if rss_vals else 0

        # Disk
        disk_read = snaps[-1].disk_read_bytes if snaps else 0
        disk_write = snaps[-1].disk_write_bytes if snaps else 0
        if self._disk_start:
            disk_read = max(0, disk_read - self._disk_start.read_bytes)
            disk_write = max(0, disk_write - self._disk_start.write_bytes)

        # GPU
        gpu_vals = [s.gpu_utilization for s in snaps if s.gpu_utilization >= 0]
        gpu_avg = sum(gpu_vals) / len(gpu_vals) if gpu_vals else -1.0
        gpu_peak = max(gpu_vals) if gpu_vals else -1.0

        gpu_mem_vals = [s.gpu_memory_used_bytes for s in snaps if s.gpu_memory_used_bytes >= 0]
        gpu_mem_avg = int(sum(gpu_mem_vals) / len(gpu_mem_vals)) if gpu_mem_vals else -1
        gpu_mem_peak = max(gpu_mem_vals) if gpu_mem_vals else -1

        gpu_temp_vals = [s.gpu_temperature for s in snaps if s.gpu_temperature >= 0]
        gpu_temp_avg = sum(gpu_temp_vals) / len(gpu_temp_vals) if gpu_temp_vals else -1.0
        gpu_temp_peak = max(gpu_temp_vals) if gpu_temp_vals else -1.0

        # anomaly detection (threshold-based)
        anomalies = []
        if cpu_peak > 90:
            anomalies.append(f"CPU spike: {cpu_peak:.0f}% at {time.strftime('%H:%M:%S', time.localtime(cpu_peak_snap.timestamp))}")
        if rss_peak > 0 and rss_avg > 0 and rss_peak > rss_avg * 2:
            anomalies.append(f"Memory spike: peak RSS {rss_peak} vs avg {rss_avg}")
        if gpu_peak > 95:
            anomalies.append(f"GPU utilization spike: {gpu_peak:.0f}%")

        return RuntimeSummary(
            duration_sec=duration,
            cpu_avg=cpu_avg,
            cpu_peak=cpu_peak,
            cpu_peak_time=cpu_peak_snap.timestamp,
            memory_avg_bytes=mem_avg,
            memory_peak_bytes=mem_peak,
            memory_peak_time=mem_peak_snap.timestamp,
            process_rss_avg=rss_avg,
            process_rss_peak=rss_peak,
            disk_total_read=disk_read,
            disk_total_write=disk_write,
            gpu_avg_util=gpu_avg,
            gpu_peak_util=gpu_peak,
            gpu_memory_avg=gpu_mem_avg,
            gpu_memory_peak=gpu_mem_peak,
            gpu_temperature_avg=gpu_temp_avg,
            gpu_temperature_peak=gpu_temp_peak,
            snapshot_count=len(snaps),
            anomalies=anomalies,
        )
