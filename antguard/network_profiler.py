"""antguard network profiler. Monitors outbound network connections."""

import time
import threading
from typing import List, Set, Dict, Optional, Callable

import psutil

from .models import NetworkEvent, NetDirection, RiskLevel
from .utils import is_local_address


class NetworkProfiler:

    def __init__(
        self,
        allow_list: Optional[List[str]] = None,
        interval: float = 1.0,
        on_event: Optional[Callable] = None,
    ):
        self._allow_list: Set[str] = set(allow_list or [])
        self._interval = interval
        self._on_event = on_event
        self._events: List[NetworkEvent] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None

        # tracking
        self._seen_destinations: Set[str] = set()
        self._known_connections: Set[tuple] = set()
        self._process_bytes: Dict[int, dict] = {}

    def _poll(self):
        while self._running:
            try:
                self._check_connections()
            except Exception:
                pass
            time.sleep(self._interval)

    def _check_connections(self):
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError):
            try:
                proc = psutil.Process()
                connections = proc.net_connections(kind="inet")
            except Exception:
                return

        for conn in connections:
            if conn.status not in ("ESTABLISHED", "SYN_SENT", "SYN_RECV"):
                continue

            if not conn.raddr:
                continue

            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port
            conn_key = (conn.pid or 0, remote_ip, remote_port)

            if conn_key in self._known_connections:
                continue

            self._known_connections.add(conn_key)

            # get process info
            proc_name = ""
            if conn.pid:
                try:
                    p = psutil.Process(conn.pid)
                    proc_name = p.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            dest_str = f"{remote_ip}:{remote_port}"
            first_seen = dest_str not in self._seen_destinations
            self._seen_destinations.add(dest_str)

            is_ext = not is_local_address(remote_ip)
            in_allow = remote_ip in self._allow_list or dest_str in self._allow_list

            # risk scoring
            risk = RiskLevel.LOW
            if is_ext and first_seen and not in_allow:
                risk = RiskLevel.HIGH
            elif is_ext and not in_allow:
                risk = RiskLevel.MEDIUM
            elif is_ext and in_allow:
                risk = RiskLevel.LOW

            # estimate bytes via process IO
            bytes_sent = 0
            bytes_recv = 0
            if conn.pid:
                try:
                    p = psutil.Process(conn.pid)
                    io = p.io_counters()
                    prev = self._process_bytes.get(conn.pid)
                    if prev:
                        bytes_sent = max(0, io.write_bytes - prev.get("write", 0))
                        bytes_recv = max(0, io.read_bytes - prev.get("read", 0))
                    self._process_bytes[conn.pid] = {
                        "write": io.write_bytes,
                        "read": io.read_bytes,
                    }
                except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                    pass

            event = NetworkEvent(
                timestamp=time.time(),
                direction=NetDirection.OUTBOUND,
                destination=remote_ip,
                port=remote_port,
                protocol="TCP",
                bytes_sent=bytes_sent,
                bytes_recv=bytes_recv,
                process_name=proc_name,
                process_pid=conn.pid or 0,
                first_seen=first_seen,
                is_external=is_ext,
                risk=risk,
            )

            with self._lock:
                self._events.append(event)

            if self._on_event:
                self._on_event(event)

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
    def events(self) -> List[NetworkEvent]:
        with self._lock:
            return list(self._events)

    def get_external(self) -> List[NetworkEvent]:
        return [e for e in self.events if e.is_external]

    def get_high_risk(self) -> List[NetworkEvent]:
        return [e for e in self.events if e.risk in (RiskLevel.HIGH, RiskLevel.CRITICAL)]
