"""
antguard Demo 8: Endpoint Observer
====================================
Watches network destinations and detects calls to known
service endpoints. Correlates file reads with endpoint calls.

Pure system-level observation. No SDK. No code changes.

Run: python demo/demo_08_endpoint_observer.py
"""

import os
import time
import tempfile
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from antguard import Guard


class _QuietHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"id":"resp-001","choices":[]}')
    def log_message(self, *args):
        pass


def start_server(port):
    srv = HTTPServer(("127.0.0.1", port), _QuietHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def main():
    print("=" * 60)
    print("antguard Demo 8: Endpoint Observer")
    print("Guard. Detect. Protect.")
    print("=" * 60)

    # simulate endpoints with local servers
    port_a = 18083
    port_b = 18084
    srv_a = start_server(port_a)
    srv_b = start_server(port_b)

    print(f"\nFake service endpoints running:")
    print(f"  ServiceA on 127.0.0.1:{port_a}")
    print(f"  ServiceB on 127.0.0.1:{port_b}")

    with tempfile.TemporaryDirectory() as tmpdir:
        data_dir = os.path.join(tmpdir, "data")
        log_dir = os.path.join(tmpdir, "logs")
        os.makedirs(data_dir)

        # create confidential file
        doc_file = os.path.join(data_dir, "confidential.txt")
        with open(doc_file, "w") as f:
            f.write("Confidential business data\n" * 50)

        print(f"  Confidential file: confidential.txt")

        # custom endpoint mapping (simulating known services via localhost)
        custom_endpoints = {
            f"127.0.0.1:{port_a}": "ServiceA",
            f"127.0.0.1:{port_b}": "ServiceB",
        }

        print(f"\nStarting profiler with endpoint observer...\n")

        with Guard(
            watch=[data_dir],
            observe_endpoints=True,
            custom_endpoints=custom_endpoints,
            runtime=True,
            gpu=False,
            log_path=log_dir,
            network_interval=0.5,
            runtime_interval=0.5,
        ) as g:
            # step 1: read confidential file
            print("[Process] Reading confidential.txt...")
            with open(doc_file, "r") as f:
                content = f.read()
            time.sleep(1)

            # step 2: call ServiceA
            print("[Process] Calling ServiceA...")
            try:
                import urllib.request
                import json
                payload = json.dumps({"prompt": content[:100]}).encode()
                req = urllib.request.Request(
                    f"http://127.0.0.1:{port_a}/v1/completions",
                    data=payload,
                    method="POST",
                    headers={"Content-Type": "application/json"},
                )
                urllib.request.urlopen(req, timeout=5)
                print("[Process] ServiceA responded")
            except Exception as e:
                print(f"[Process] ServiceA call: {e}")
            time.sleep(1)

            # step 3: call ServiceB
            print("[Process] Calling ServiceB...")
            try:
                payload = json.dumps({"data": "summary request"}).encode()
                req = urllib.request.Request(
                    f"http://127.0.0.1:{port_b}/v1/chat",
                    data=payload,
                    method="POST",
                    headers={"Content-Type": "application/json"},
                )
                urllib.request.urlopen(req, timeout=5)
                print("[Process] ServiceB responded")
            except Exception as e:
                print(f"[Process] ServiceB call: {e}")
            time.sleep(2)

            print("\n--- Done ---\n")

        # results
        print("=" * 60)
        print("OBSERVER RESULTS")
        print("=" * 60)

        # endpoint calls
        calls = g.endpoint_calls()
        print(f"\nEndpoint calls detected: {len(calls)}")
        for c in calls:
            print(f"  [{c.service:15s}] {c.destination}:{c.port}"
                  f"  sent={c.bytes_sent} bytes"
                  f"  proc={c.process_name}")

        # file-to-endpoint correlations
        f2e = g.file_to_endpoint()
        print(f"\nFile -> Endpoint correlations: {len(f2e)}")
        for corr in f2e:
            print(f"  {os.path.basename(corr.file_path)}"
                  f" -> {corr.service}({corr.destination})"
                  f"  gap={corr.time_gap_sec:.1f}s"
                  f"  risk={corr.risk.name}")

        # observer summary
        obs = g.observer_summary()
        if obs:
            print(f"\nObserver Summary:")
            print(f"  Total calls: {obs.total_endpoint_calls}")
            print(f"  Services: {', '.join(obs.services_contacted)}")
            print(f"  Bytes sent: {obs.total_bytes_sent}")
            print(f"  File correlations: {obs.file_to_endpoint_correlations}")

        # standard results
        print(f"\nData left system: {g.did_data_leave()}")
        print(f"Risk level: {g.risk_level().name}")

        paths = g.save(log_dir)
        print(f"\nReport: {paths['txt']}")

    srv_a.shutdown()
    srv_b.shutdown()


if __name__ == "__main__":
    main()
