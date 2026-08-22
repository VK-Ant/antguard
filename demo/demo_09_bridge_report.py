"""
antguard Demo 9: Combined Audit Report (Bridge)
=================================================
Shows how antguard combines with llmevalkit for a
unified system behavior + output quality report.

Works WITHOUT llmevalkit installed - simulates evaluation
data to show the combined report format.

Run: python demo/demo_09_bridge_report.py
"""

import os
import time
import tempfile
from antguard import Guard, Policy
from antguard.bridge import UnifiedAudit


def main():
    print("=" * 60)
    print("antguard Demo 9: Combined Audit Report")
    print("Guard. Detect. Protect.")
    print("=" * 60)
    print()
    print("antguard = system behavior (did data leave?)")
    print("llmevalkit = output quality (is output accurate?)")
    print("bridge = combined report")
    print()

    with tempfile.TemporaryDirectory() as tmpdir:
        data_dir = os.path.join(tmpdir, "data")
        log_dir = os.path.join(tmpdir, "logs")
        report_dir = os.path.join(tmpdir, "reports")
        os.makedirs(data_dir)

        # create test data
        with open(os.path.join(data_dir, "document.txt"), "w") as f:
            f.write("Company quarterly report\nRevenue: 12.5 Cr\n" * 20)

        # define policy
        policy = Policy({
            "file": {
                "allow_read": [os.path.join(data_dir, "*")],
            },
            "network": {
                "allow": ["localhost", "127.0.0.1"],
                "deny_all_other": True,
            },
            "mode": "detect",
        })

        print("--- Running System Profiler ---\n")

        with Guard(
            watch=[data_dir],
            policy=policy,
            observe_endpoints=True,
            runtime=True,
            gpu=False,
            log_path=log_dir,
            runtime_interval=0.5,
        ) as g:
            # simulate processing
            print("[Process] Reading document...")
            with open(os.path.join(data_dir, "document.txt"), "r") as f:
                content = f.read()
            time.sleep(1)

            print("[Process] Generating summary...")
            summary = f"Revenue is 12.5 Cr. Total lines: {len(content.splitlines())}"
            time.sleep(1)

            output_file = os.path.join(data_dir, "output.txt")
            with open(output_file, "w") as f:
                f.write(summary)
            print("[Process] Summary saved locally")
            time.sleep(1)

        print("\n--- System Profiling Complete ---")
        print(f"  Data left: {g.did_data_leave()}")
        print(f"  Risk: {g.risk_level().name}")

        # simulate llmevalkit evaluation results
        # (in real use, this comes from llmevalkit.Evaluator)
        print("\n--- Simulated Quality Evaluation ---")
        evaluation = {
            "faithfulness": 0.94,
            "relevance": 0.91,
            "hallucination": 0.03,
            "answer_correctness": 0.89,
            "context_precision": 0.92,
            "toxicity": 0.00,
        }
        for key, val in evaluation.items():
            print(f"  {key}: {val}")

        # create combined report
        print("\n--- Generating Combined Report ---\n")

        audit = UnifiedAudit(guard=g, evaluation=evaluation)
        paths = audit.save(report_dir)

        # display report
        print("=" * 60)
        print("UNIFIED AUDIT REPORT")
        print("=" * 60)
        with open(paths["txt"]) as f:
            print(f.read())

        print(f"Reports saved:")
        print(f"  TXT:  {paths['txt']}")
        print(f"  JSON: {paths['json']}")

        # also show antguard-only report (without llmevalkit)
        print("\n" + "=" * 60)
        print("ANTGUARD-ONLY REPORT (no llmevalkit)")
        print("=" * 60 + "\n")

        audit_standalone = UnifiedAudit(guard=g)
        standalone_paths = audit_standalone.save(
            os.path.join(report_dir, "standalone")
        )
        with open(standalone_paths["txt"]) as f:
            print(f.read())

        print("antguard works fully standalone.")
        print("llmevalkit bridge adds quality metrics when available.")

        # show how real integration would work
        print("\n" + "-" * 60)
        print("REAL USAGE (with llmevalkit installed):")
        print("-" * 60)
        print("""
  from antguard import Guard
  from antguard.bridge import UnifiedAudit
  from llmevalkit import Evaluator

  with Guard(watch=["./data/"]) as g:
      response = your_code()

  quality = Evaluator().evaluate(response)

  audit = UnifiedAudit(guard=g, evaluation=quality)
  audit.save("./reports/")
""")


if __name__ == "__main__":
    main()
