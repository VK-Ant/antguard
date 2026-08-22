"""antguard bridge. Optional integration with llmevalkit for combined reports.

Works without llmevalkit installed - antguard is fully standalone.
When llmevalkit is available, produces combined quality + privacy reports.
"""

import os
import time
import json
from typing import Optional, Any

from .models import RiskLevel

from .models import RiskLevel
from .utils import format_bytes, get_platform_info


class UnifiedAudit:
    """Combined antguard + llmevalkit audit report.

    Takes antguard Guard results and optionally llmevalkit
    evaluation results. Produces a unified report covering
    both system behavior and output quality.

    Works without llmevalkit - the system behavior section
    is always present, quality section added only when
    evaluation data is provided.

    Args:
        guard: antguard Guard instance (after stop)
        evaluation: llmevalkit evaluation result dict (optional)
    """

    def __init__(self, guard: Any, evaluation: Optional[dict] = None):
        self._guard = guard
        self._evaluation = evaluation

    def save(self, output_dir: str = "./reports") -> dict:
        """Save combined .txt + .json reports.

        Returns dict with file paths.
        """
        os.makedirs(output_dir, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")

        txt_path = os.path.join(output_dir, f"unified_audit_{ts}.txt")
        json_path = os.path.join(output_dir, f"unified_audit_{ts}.json")

        with open(txt_path, "w", encoding="utf-8") as f:
            self._write_txt(f)

        with open(json_path, "w", encoding="utf-8") as f:
            self._write_json(f)

        return {"txt": txt_path, "json": json_path}

    def _write_txt(self, f):
        plat = get_platform_info()
        g = self._guard

        f.write("UNIFIED AUDIT REPORT\n")
        f.write("=" * 50 + "\n")
        f.write(f"Generated : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Platform  : {plat['system']} ({plat['release']})\n")
        f.write("\n")

        # system behavior (antguard)
        f.write("-- SYSTEM BEHAVIOR (antguard) --\n\n")
        f.write(f"  Data left system    : {'YES' if g.did_data_leave() else 'NO'}\n")
        f.write(f"  Risk level          : {g.risk_level().name}\n")
        f.write(f"  File events         : {len(g.file_events())}\n")
        f.write(f"  Network events      : {len(g.net_events())}\n")
        f.write(f"  Process events      : {len(g.proc_events())}\n")
        f.write(f"  Correlations        : {len(g.correlations())}\n")

        # matched files
        matched = g.matched_files()
        if matched:
            f.write(f"\n  Files in outbound:\n")
            for mf in matched:
                f.write(f"    {os.path.basename(mf)}\n")

        # policy violations
        if hasattr(g, "policy_violations"):
            violations = g.policy_violations()
            if violations:
                f.write(f"\n  Policy violations: {len(violations)}\n")
                for v in violations:
                    f.write(f"    [{v.severity.name:8s}] {v.category}: {v.rule}\n")

        # observer data
        if hasattr(g, "endpoint_calls"):
            calls = g.endpoint_calls()
            if calls:
                f.write(f"\n  Endpoint calls: {len(calls)}\n")
                for c in calls:
                    f.write(f"    {c.service}: {c.destination}:{c.port}\n")

        # runtime
        metrics = g.runtime_metrics()
        if metrics and metrics.snapshot_count > 0:
            f.write(f"\n  Runtime:\n")
            f.write(f"    CPU avg/peak    : {metrics.cpu_avg:.1f}% / {metrics.cpu_peak:.1f}%\n")
            f.write(f"    Memory peak     : {format_bytes(metrics.memory_peak_bytes)}\n")
            f.write(f"    Process RSS     : {format_bytes(metrics.process_rss_peak)} peak\n")
            if metrics.gpu_avg_util >= 0:
                f.write(f"    GPU util        : {metrics.gpu_avg_util:.1f}%\n")

        f.write("\n")

        # output quality (llmevalkit) - only if evaluation provided
        if self._evaluation:
            f.write("-- OUTPUT QUALITY (llmevalkit) --\n\n")
            for key, value in self._evaluation.items():
                if isinstance(value, float):
                    f.write(f"  {key:20s}: {value:.4f}\n")
                else:
                    f.write(f"  {key:20s}: {value}\n")
            f.write("\n")

        # verdict
        f.write("=" * 50 + "\n")

        system_ok = not g.did_data_leave() and g.risk_level() == RiskLevel.LOW
        quality_ok = True
        if self._evaluation:
            hallucination = self._evaluation.get("hallucination", 0)
            if isinstance(hallucination, (int, float)) and hallucination > 0.1:
                quality_ok = False

        if system_ok and quality_ok:
            f.write("VERDICT: CLEAN\n")
            if self._evaluation:
                f.write("Output trustworthy. Data stayed local.\n")
            else:
                f.write("Data stayed local.\n")
        elif system_ok and not quality_ok:
            f.write("VERDICT: QUALITY CONCERN\n")
            f.write("Data stayed local but output quality flagged.\n")
        elif not system_ok and quality_ok:
            f.write("VERDICT: PRIVACY CONCERN\n")
            f.write("Data movement detected.\n")
        else:
            f.write("VERDICT: MULTIPLE CONCERNS\n")
            f.write("Data movement + quality issues detected.\n")

        f.write("=" * 50 + "\n")

    def _write_json(self, f):
        g = self._guard

        report = {
            "antguard_version": "0.2.0",
            "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "platform": get_platform_info(),
            "system_behavior": {
                "data_left_system": g.did_data_leave(),
                "risk_level": g.risk_level().name,
                "file_events": len(g.file_events()),
                "network_events": len(g.net_events()),
                "process_events": len(g.proc_events()),
                "correlations": len(g.correlations()),
                "matched_files": g.matched_files(),
            },
        }

        # policy
        if hasattr(g, "policy_violations"):
            violations = g.policy_violations()
            report["policy_violations"] = [v.to_dict() for v in violations]

        # observer
        if hasattr(g, "endpoint_calls"):
            calls = g.endpoint_calls()
            report["endpoint_calls"] = [c.to_dict() for c in calls]

        # runtime
        metrics = g.runtime_metrics()
        if metrics and metrics.snapshot_count > 0:
            report["runtime"] = metrics.to_dict()

        # quality
        if self._evaluation:
            report["output_quality"] = self._evaluation

        json.dump(report, f, indent=2, default=str)
