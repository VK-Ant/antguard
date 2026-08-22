"""
antguard Demo 7: Policy Engine
================================
Define rules for allowed system behavior.
Detect or block policy violations.

Run: python demo/demo_07_policy_engine.py
"""

import os
import sys
import time
import tempfile
import subprocess
from antguard import Guard, Policy


def main():
    print("=" * 60)
    print("antguard Demo 7: Policy Engine")
    print("Guard. Detect. Protect.")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        # setup
        data_dir = os.path.join(tmpdir, "data")
        secrets_dir = os.path.join(tmpdir, "secrets")
        log_dir = os.path.join(tmpdir, "logs")
        os.makedirs(data_dir)
        os.makedirs(secrets_dir)

        # create files
        with open(os.path.join(data_dir, "report.txt"), "w") as f:
            f.write("Quarterly report data\n" * 20)

        with open(os.path.join(secrets_dir, "api_keys.env"), "w") as f:
            f.write("SECRET_KEY=abc123\nDB_PASS=hunter2\n")

        # define policy
        policy = Policy({
            "file": {
                "allow_read": [os.path.join(data_dir, "*")],
                "deny_read": [os.path.join(secrets_dir, "*")],
                "deny_write": [os.path.join(tmpdir, "tmp", "*")],
            },
            "network": {
                "allow": ["127.0.0.1", "localhost"],
                "deny_all_other": True,
            },
            "process": {
                "deny_shell": True,
                "deny_commands": ["curl", "wget"],
            },
            "mode": "detect",
        })

        print(f"\nPolicy mode: {policy.mode}")
        print("Rules:")
        print(f"  File: allow_read data/, deny_read secrets/")
        print(f"  Network: allow localhost only")
        print(f"  Process: deny shell commands")
        print(f"\nStarting profiler...\n")

        with Guard(
            watch=[data_dir, secrets_dir],
            policy=policy,
            runtime=True,
            gpu=False,
            log_path=log_dir,
            runtime_interval=0.5,
        ) as g:
            # allowed: read from data dir
            print("[Action] Reading report.txt (ALLOWED by policy)...")
            with open(os.path.join(data_dir, "report.txt"), "r") as f:
                _ = f.read()
            time.sleep(0.5)

            # violation: read from secrets dir
            print("[Action] Reading api_keys.env (DENIED by policy)...")
            with open(os.path.join(secrets_dir, "api_keys.env"), "r") as f:
                _ = f.read()
            time.sleep(0.5)

            # violation: shell command
            print("[Action] Running shell command (DENIED by policy)...")
            try:
                subprocess.run(
                    ["echo", "hello"],
                    capture_output=True, timeout=5,
                )
            except Exception:
                pass
            time.sleep(1)

            print("\n--- Done ---\n")

        # results
        print("=" * 60)
        print("POLICY VIOLATION REPORT")
        print("=" * 60)

        violations = g.policy_violations()
        print(f"\nViolations found: {len(violations)}")

        for i, v in enumerate(violations, 1):
            blocked = "BLOCKED" if v.blocked else "DETECTED"
            print(f"\n  Violation {i}:")
            print(f"    Category : {v.category}")
            print(f"    Rule     : {v.rule}")
            print(f"    Action   : {v.action}")
            print(f"    Detail   : {v.detail}")
            print(f"    Severity : {v.severity.name}")
            print(f"    Mode     : {blocked}")

        print(f"\nData left system: {g.did_data_leave()}")
        print(f"Risk level: {g.risk_level().name}")

        # baseline generation
        print(f"\n--- Baseline Generation ---")
        baseline = g.generate_baseline()
        bl_data = baseline.generate()
        print(f"  Files observed: {bl_data['baseline_stats']['files_accessed']}")
        print(f"  Destinations: {bl_data['baseline_stats']['destinations']}")

        bl_path = os.path.join(log_dir, "baseline.json")
        baseline.save(bl_path)
        print(f"  Saved to: {bl_path}")

        paths = g.save(log_dir)
        print(f"\n  Report: {paths['txt']}")


if __name__ == "__main__":
    main()
