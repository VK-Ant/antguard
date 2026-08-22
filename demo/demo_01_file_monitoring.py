"""
antguard Demo 1: Basic File Monitoring
=======================================
Monitors file read/write operations and generates audit report.

Run: python demo_01_file_monitoring.py
"""

import os
import time
import tempfile
from antguard import Guard


def main():
    print("=" * 60)
    print("antguard Demo 1: Basic File Monitoring")
    print("Guard. Detect. Protect.")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        data_dir = os.path.join(tmpdir, "confidential")
        output_dir = os.path.join(tmpdir, "output")
        log_dir = os.path.join(tmpdir, "logs")
        os.makedirs(data_dir)
        os.makedirs(output_dir)

        # create fake confidential files
        files = {
            "salary.csv": (
                "Employee,Salary,Department\n"
                "Alice,2500000,Engineering\n"
                "Bob,1800000,Marketing\n"
                "Charlie,3200000,Management\n"
            ),
            "project_plan.txt": (
                "PROJECT: Secret Project X\n"
                "STATUS: Confidential\n"
                "BUDGET: 50,00,000\n"
                "DEADLINE: 2026-12-31\n"
            ),
            "credentials.env": (
                "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n"
                "AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
                "DB_PASSWORD=super_secret_123\n"
            ),
        }

        for fname, content in files.items():
            with open(os.path.join(data_dir, fname), "w") as f:
                f.write(content)

        print(f"\nCreated {len(files)} confidential files in {data_dir}")
        print("Starting antguard profiler...\n")

        # start monitoring
        with Guard(
            watch=[data_dir],
            detect_outbound=True,
            track_processes=True,
            correlate=True,
            runtime=True,
            gpu=False,
            log_path=log_dir,
            runtime_interval=0.5,
        ) as g:
            print("--- Simulating AI Agent ---\n")

            # simulate: agent reads confidential files
            print("[Agent] Reading salary.csv...")
            with open(os.path.join(data_dir, "salary.csv"), "r") as f:
                salary_data = f.read()
            time.sleep(0.5)

            print("[Agent] Reading project_plan.txt...")
            with open(os.path.join(data_dir, "project_plan.txt"), "r") as f:
                plan_data = f.read()
            time.sleep(0.5)

            print("[Agent] Processing data...")
            summary = f"Summary: {len(salary_data.splitlines())} employees found."
            time.sleep(1)

            print("[Agent] Writing summary to output...")
            with open(os.path.join(output_dir, "summary.txt"), "w") as f:
                f.write(summary)
            time.sleep(0.5)

            print("[Agent] Done.\n")
            print("--- Agent Finished ---\n")

        # results
        print("=" * 60)
        print("RESULTS")
        print("=" * 60)
        print(f"\nData left system: {g.did_data_leave()}")
        print(f"Risk level: {g.risk_level().value}")
        print(f"File events: {len(g.file_events())}")
        print(f"Network events: {len(g.net_events())}")
        print(f"Process events: {len(g.proc_events())}")
        print(f"Correlations: {len(g.correlations())}")

        # runtime metrics
        metrics = g.runtime_metrics()
        if metrics:
            print(f"\nCPU avg/peak: {metrics.cpu_avg:.1f}% / {metrics.cpu_peak:.1f}%")
            print(f"Process RSS: {metrics.process_rss_peak / (1024*1024):.1f} MB peak")

        # file fingerprints
        fps = g.fingerprints()
        print(f"\nFile fingerprints ({len(fps)} files):")
        for path, info in fps.items():
            basename = os.path.basename(path)
            print(f"  {basename}: sha256:{info['hash'][:16]}... ({info['size']} bytes)")

        # save reports
        paths = g.save(log_dir)
        print(f"\nReports saved:")
        print(f"  TXT: {paths['txt']}")
        print(f"  JSON: {paths['json']}")
        print(f"  LOG: {paths['log']}")

        # print report content
        print("\n" + "=" * 60)
        print("FULL TEXT REPORT")
        print("=" * 60)
        with open(paths["txt"]) as f:
            print(f.read())


if __name__ == "__main__":
    main()
