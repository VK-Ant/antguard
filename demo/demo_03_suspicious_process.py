"""
antguard Demo 3: Suspicious Process Detection
===============================================
Simulates an AI agent spawning shell commands and suspicious
processes. antguard detects unexpected process tree behavior.

Run: python demo_03_suspicious_process.py
"""

import os
import sys
import time
import tempfile
import subprocess
from antguard import Guard


def main():
    print("=" * 60)
    print("antguard Demo 3: Suspicious Process Detection")
    print("Guard. Detect. Protect.")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        data_dir = os.path.join(tmpdir, "data")
        log_dir = os.path.join(tmpdir, "logs")
        os.makedirs(data_dir)

        # create test file
        test_file = os.path.join(data_dir, "report.txt")
        with open(test_file, "w") as f:
            f.write("Confidential report content\n" * 50)

        print(f"\nCreated test file: report.txt")
        print("Starting antguard profiler...\n")

        with Guard(
            watch=[data_dir],
            detect_outbound=True,
            track_processes=True,
            correlate=True,
            runtime=True,
            gpu=False,
            log_path=log_dir,
            process_interval=0.5,
            runtime_interval=0.5,
        ) as g:
            print("--- Simulating Agent with Suspicious Behavior ---\n")

            # normal: read a file
            print("[Agent] Reading report.txt (normal)...")
            with open(test_file, "r") as f:
                content = f.read()
            time.sleep(1)

            # suspicious: spawn shell command
            print("[Agent] Running shell command (suspicious)...")
            try:
                result = subprocess.run(
                    ["echo", "listing files"],
                    capture_output=True, text=True, timeout=5,
                )
            except Exception:
                pass
            time.sleep(1)

            # suspicious: spawn python subprocess
            print("[Agent] Spawning Python subprocess (suspicious)...")
            try:
                result = subprocess.run(
                    [sys.executable, "-c", "import os; print(os.listdir('/tmp'))"],
                    capture_output=True, text=True, timeout=5,
                )
            except Exception:
                pass
            time.sleep(1)

            # suspicious: file copy to /tmp
            print("[Agent] Copying file to /tmp (suspicious)...")
            import shutil
            tmp_copy = os.path.join(tmpdir, "backup_report.txt")
            shutil.copy2(test_file, tmp_copy)
            time.sleep(1)

            print("\n--- Agent Finished ---\n")

        # results
        print("=" * 60)
        print("ANTGUARD DETECTION RESULTS")
        print("=" * 60)

        print(f"\nData left system: {g.did_data_leave()}")
        print(f"Risk level: {g.risk_level().value}")
        print(f"File events: {len(g.file_events())}")
        print(f"Network events: {len(g.net_events())}")
        print(f"Process events: {len(g.proc_events())}")

        # show all process events
        if g.proc_events():
            print(f"\nProcess Events Detected ({len(g.proc_events())}):")
            for ev in g.proc_events():
                risk_marker = ""
                if ev.risk.value == "HIGH":
                    risk_marker = " !!!"
                elif ev.risk.value == "MEDIUM":
                    risk_marker = " !"
                print(f"  [{ev.event_type.value:12s}] {ev.name} (pid {ev.pid}) "
                      f"parent={ev.parent_name} "
                      f"risk={ev.risk.value}{risk_marker}")
                if ev.command and ev.command != ev.name:
                    print(f"    cmd: {ev.command[:80]}")

        # show file events
        if g.file_events():
            print(f"\nFile Events ({len(g.file_events())}):")
            for ev in g.file_events():
                print(f"  [{ev.action.value:8s}] {os.path.basename(ev.path)} "
                      f"({ev.size_bytes} bytes) risk={ev.risk.value}")

        # runtime anomalies
        anomalies = g.anomalies()
        if anomalies:
            print(f"\nRuntime Anomalies:")
            for a in anomalies:
                print(f"  {a}")

        # save
        paths = g.save(log_dir)

        print("\n" + "=" * 60)
        print("FULL TEXT REPORT")
        print("=" * 60)
        with open(paths["txt"]) as f:
            print(f.read())


if __name__ == "__main__":
    main()
