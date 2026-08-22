"""antguard process profiler. Monitors process tree for suspicious activity."""

import time
import threading
from typing import List, Set, Optional, Callable

import psutil

from .models import ProcessEvent, ProcessEventType, RiskLevel
from .utils import is_shell_process, is_suspicious_command


class ProcessProfiler:

    def __init__(
        self,
        interval: float = 1.0,
        on_event: Optional[Callable] = None,
    ):
        self._interval = interval
        self._on_event = on_event
        self._events: List[ProcessEvent] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._known_pids: Set[int] = set()
        self._root_pid: int = 0

    def _snapshot_existing(self):
        self._root_pid = psutil.Process().pid
        for proc in psutil.process_iter(["pid"]):
            self._known_pids.add(proc.info["pid"])

    def _poll(self):
        while self._running:
            try:
                self._check_processes()
            except Exception:
                pass
            time.sleep(self._interval)

    def _check_processes(self):
        current_pids = set()
        for proc in psutil.process_iter(["pid", "name", "ppid", "cmdline"]):
            try:
                info = proc.info
                pid = info["pid"]
                current_pids.add(pid)

                if pid in self._known_pids:
                    continue

                self._known_pids.add(pid)

                name = info.get("name", "") or ""
                ppid = info.get("ppid", 0) or 0
                cmdline = info.get("cmdline") or []
                cmd_str = " ".join(cmdline) if cmdline else name

                # get parent info
                parent_name = ""
                try:
                    if ppid:
                        parent = psutil.Process(ppid)
                        parent_name = parent.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

                # determine event type and risk
                event_type = ProcessEventType.CREATED
                risk = RiskLevel.LOW

                if is_shell_process(name):
                    event_type = ProcessEventType.SHELL_EXEC
                    risk = RiskLevel.MEDIUM
                    # shell from python = higher risk
                    if "python" in parent_name.lower():
                        risk = RiskLevel.HIGH

                elif is_suspicious_command(name):
                    event_type = ProcessEventType.SUSPICIOUS
                    risk = RiskLevel.HIGH

                event = ProcessEvent(
                    timestamp=time.time(),
                    event_type=event_type,
                    name=name,
                    pid=pid,
                    parent_name=parent_name,
                    parent_pid=ppid,
                    command=cmd_str[:200],
                    risk=risk,
                )

                with self._lock:
                    self._events.append(event)

                if self._on_event:
                    self._on_event(event)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def start(self):
        self._snapshot_existing()
        self._running = True
        self._thread = threading.Thread(target=self._poll, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    @property
    def events(self) -> List[ProcessEvent]:
        with self._lock:
            return list(self._events)

    def get_suspicious(self) -> List[ProcessEvent]:
        return [
            e for e in self.events
            if e.event_type in (ProcessEventType.SHELL_EXEC, ProcessEventType.SUSPICIOUS)
        ]
