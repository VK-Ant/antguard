"""antguard policy engine. Declarative rules for allowed system behavior."""

import os
import fnmatch
import time
import threading
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field, asdict

from .models import FileEvent, NetworkEvent, ProcessEvent, RiskLevel, FileAction
from .utils import is_local_address


@dataclass
class PolicyViolation:
    timestamp: float
    category: str  # file, network, process, correlation
    rule: str
    action: str
    detail: str
    process_name: str = ""
    process_pid: int = 0
    severity: RiskLevel = RiskLevel.MEDIUM
    blocked: bool = False

    def to_dict(self):
        d = asdict(self)
        d["severity"] = self.severity.name
        return d

    def to_log_line(self):
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp))
        mode = "BLOCKED" if self.blocked else "DETECTED"
        return (
            f"[{ts}] POLICY {mode} category={self.category} "
            f"rule={self.rule} action={self.action} "
            f"detail={self.detail} pid={self.process_pid} "
            f"severity={self.severity.name}"
        )


class Policy:
    """Declarative security policy for antguard.

    Modes:
        audit   - silent logging, no alerts (baseline building)
        detect  - log + alert, don't block
        enforce - actively prevent violations
    """

    def __init__(self, rules: Optional[Dict[str, Any]] = None):
        rules = rules or {}
        self._mode = rules.get("mode", "detect")
        self._file_rules = rules.get("file", {})
        self._network_rules = rules.get("network", {})
        self._process_rules = rules.get("process", {})
        self._correlation_rules = rules.get("correlation", {})
        self._violations: List[PolicyViolation] = []
        self._lock = threading.Lock()

    @classmethod
    def from_yaml(cls, path: str) -> "Policy":
        """Load policy from YAML file."""
        try:
            import yaml
        except ImportError:
            raise ImportError(
                "PyYAML required for YAML policies: pip install pyyaml"
            )
        with open(path, "r") as f:
            rules = yaml.safe_load(f)
        return cls(rules)

    @classmethod
    def from_dict(cls, rules: Dict[str, Any]) -> "Policy":
        return cls(rules)

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def violations(self) -> List[PolicyViolation]:
        with self._lock:
            return list(self._violations)

    def _add_violation(self, v: PolicyViolation):
        if self._mode == "enforce":
            v.blocked = True
        with self._lock:
            self._violations.append(v)

    def check_file_event(self, event: FileEvent) -> Optional[PolicyViolation]:
        """Check a file event against file rules."""
        path = event.path

        # check deny_read
        if event.action in (FileAction.READ, FileAction.MODIFY):
            deny_patterns = self._file_rules.get("deny_read", [])
            for pattern in deny_patterns:
                expanded = os.path.expanduser(pattern)
                if fnmatch.fnmatch(path, expanded) or fnmatch.fnmatch(path, pattern):
                    v = PolicyViolation(
                        timestamp=time.time(),
                        category="file",
                        rule=f"deny_read {pattern}",
                        action=event.action.value,
                        detail=path,
                        process_name=event.process_name,
                        process_pid=event.process_pid,
                        severity=RiskLevel.HIGH,
                    )
                    self._add_violation(v)
                    return v

        # check deny_write
        if event.action in (FileAction.WRITE, FileAction.CREATE):
            deny_patterns = self._file_rules.get("deny_write", [])
            for pattern in deny_patterns:
                expanded = os.path.expanduser(pattern)
                if fnmatch.fnmatch(path, expanded) or fnmatch.fnmatch(path, pattern):
                    v = PolicyViolation(
                        timestamp=time.time(),
                        category="file",
                        rule=f"deny_write {pattern}",
                        action=event.action.value,
                        detail=path,
                        process_name=event.process_name,
                        process_pid=event.process_pid,
                        severity=RiskLevel.HIGH,
                    )
                    self._add_violation(v)
                    return v

        # check deny_copy_outside
        if event.action == FileAction.MOVE:
            deny_copy = self._file_rules.get("deny_copy_outside", [])
            for pattern in deny_copy:
                expanded = os.path.expanduser(pattern)
                if fnmatch.fnmatch(path, expanded) or fnmatch.fnmatch(path, pattern):
                    v = PolicyViolation(
                        timestamp=time.time(),
                        category="file",
                        rule=f"deny_copy_outside {pattern}",
                        action="COPY",
                        detail=path,
                        process_name=event.process_name,
                        process_pid=event.process_pid,
                        severity=RiskLevel.CRITICAL,
                    )
                    self._add_violation(v)
                    return v

        # check allow_read (whitelist mode)
        allow_patterns = self._file_rules.get("allow_read", [])
        if allow_patterns and event.action in (FileAction.READ, FileAction.MODIFY):
            matched = False
            for pattern in allow_patterns:
                expanded = os.path.expanduser(pattern)
                if fnmatch.fnmatch(path, expanded) or fnmatch.fnmatch(path, pattern):
                    matched = True
                    break
            if not matched:
                v = PolicyViolation(
                    timestamp=time.time(),
                    category="file",
                    rule="allow_read whitelist",
                    action=event.action.value,
                    detail=f"{path} not in allowed paths",
                    process_name=event.process_name,
                    process_pid=event.process_pid,
                    severity=RiskLevel.MEDIUM,
                )
                self._add_violation(v)
                return v

        return None

    def check_network_event(self, event: NetworkEvent) -> Optional[PolicyViolation]:
        """Check a network event against network rules."""
        dest = event.destination
        dest_port = f"{dest}:{event.port}"

        if is_local_address(dest):
            return None

        # check allow list + deny_all_other
        allow_list = self._network_rules.get("allow", [])
        deny_all = self._network_rules.get("deny_all_other", False)

        if deny_all and allow_list:
            in_allow = dest in allow_list or dest_port in allow_list
            if not in_allow:
                v = PolicyViolation(
                    timestamp=time.time(),
                    category="network",
                    rule="deny_all_other (not in allow list)",
                    action="OUTBOUND",
                    detail=dest_port,
                    process_name=event.process_name,
                    process_pid=event.process_pid,
                    severity=RiskLevel.HIGH,
                )
                self._add_violation(v)
                return v

        # check max_outbound_bytes
        max_bytes = self._network_rules.get("max_outbound_bytes", 0)
        if max_bytes > 0 and event.bytes_sent > max_bytes:
            v = PolicyViolation(
                timestamp=time.time(),
                category="network",
                rule=f"max_outbound_bytes ({max_bytes})",
                action="OUTBOUND",
                detail=f"{event.bytes_sent} bytes to {dest_port}",
                process_name=event.process_name,
                process_pid=event.process_pid,
                severity=RiskLevel.HIGH,
            )
            self._add_violation(v)
            return v

        return None

    def check_process_event(self, event: ProcessEvent) -> Optional[PolicyViolation]:
        """Check a process event against process rules."""
        name = event.name.lower()

        # deny_shell
        if self._process_rules.get("deny_shell", False):
            from .utils import is_shell_process
            if is_shell_process(event.name):
                v = PolicyViolation(
                    timestamp=time.time(),
                    category="process",
                    rule="deny_shell",
                    action="SHELL_EXEC",
                    detail=f"{event.name} (pid {event.pid})",
                    process_name=event.name,
                    process_pid=event.pid,
                    severity=RiskLevel.HIGH,
                )
                self._add_violation(v)
                return v

        # deny_commands
        deny_cmds = self._process_rules.get("deny_commands", [])
        if name in [c.lower() for c in deny_cmds]:
            v = PolicyViolation(
                timestamp=time.time(),
                category="process",
                rule=f"deny_commands ({event.name})",
                action="EXEC",
                detail=f"{event.command[:80]}",
                process_name=event.name,
                process_pid=event.pid,
                severity=RiskLevel.HIGH,
            )
            self._add_violation(v)
            return v

        return None

    def should_block_file(self, event: FileEvent) -> bool:
        """Returns True if this file event should be blocked (enforce mode)."""
        if self._mode != "enforce":
            return False
        violation = self.check_file_event(event)
        return violation is not None and violation.blocked

    def should_block_network(self, event: NetworkEvent) -> bool:
        """Returns True if this network event should be blocked (enforce mode)."""
        if self._mode != "enforce":
            return False
        violation = self.check_network_event(event)
        return violation is not None and violation.blocked

    def reset(self):
        """Clear all violations."""
        with self._lock:
            self._violations.clear()


class BaselineGenerator:
    """Generate a baseline policy from observed behavior."""

    def __init__(self):
        self._files_accessed: set = set()
        self._destinations: set = set()
        self._processes: set = set()
        self._cpu_samples: list = []
        self._mem_samples: list = []

    def observe_file(self, event: FileEvent):
        self._files_accessed.add(event.path)

    def observe_network(self, event: NetworkEvent):
        if not is_local_address(event.destination):
            self._destinations.add(event.destination)

    def observe_process(self, event: ProcessEvent):
        self._processes.add(event.name)

    def observe_runtime(self, cpu: float, mem_bytes: int):
        self._cpu_samples.append(cpu)
        self._mem_samples.append(mem_bytes)

    def generate(self) -> dict:
        """Generate baseline as a dict that can be used as Policy input."""
        cpu_avg = sum(self._cpu_samples) / len(self._cpu_samples) if self._cpu_samples else 0
        cpu_p95 = sorted(self._cpu_samples)[int(len(self._cpu_samples) * 0.95)] if self._cpu_samples else 0
        mem_avg = int(sum(self._mem_samples) / len(self._mem_samples)) if self._mem_samples else 0

        return {
            "file": {
                "allow_read": [f"{f}" for f in sorted(self._files_accessed)],
            },
            "network": {
                "allow": list(sorted(self._destinations)),
                "deny_all_other": True,
            },
            "process": {
                "allow": list(sorted(self._processes)),
            },
            "baseline_stats": {
                "sessions_observed": 1,
                "files_accessed": len(self._files_accessed),
                "destinations": len(self._destinations),
                "cpu_avg": round(cpu_avg, 1),
                "cpu_p95": round(cpu_p95, 1),
                "mem_avg_bytes": mem_avg,
            },
            "mode": "detect",
        }

    def save(self, path: str):
        """Save baseline to JSON file."""
        import json
        baseline = self.generate()
        with open(path, "w") as f:
            json.dump(baseline, f, indent=2)
