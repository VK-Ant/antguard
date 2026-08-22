"""
antguard Demo 6: Wrap Any Library
==================================
Shows that antguard wraps ANY code without modification.
No SDK, no decorators, no config changes to your libraries.

Like cProfile - your code is unchanged inside the profiler.

Run: python demo_06_wrap_any_library.py
"""

import os
import time
import json
import tempfile
from antguard import Guard


# === Fake libraries to demonstrate wrapping ===

class FakeImageRAG:
    """Simulates SightRAG or any image RAG library."""
    def query(self, text, image_path):
        with open(image_path, "rb") as f:
            data = f.read()
        return {"result": f"Found {len(data)} bytes of image data", "score": 0.92}


class FakeDocExtractor:
    """Simulates docqwise or any document extraction library."""
    def extract(self, doc_path):
        with open(doc_path, "r") as f:
            content = f.read()
        return {"pages": 1, "text": content[:100], "tables": 0}


class FakeLLMAgent:
    """Simulates LangChain or any LLM agent."""
    def run(self, prompt, context_file=None):
        if context_file:
            with open(context_file, "r") as f:
                ctx = f.read()
        return f"Agent response based on {len(prompt)} char prompt"


# === Demo ===

def main():
    print("=" * 60)
    print("antguard Demo 6: Wrap Any Library")
    print("Guard. Detect. Protect.")
    print("=" * 60)
    print()
    print("antguard sits OUTSIDE your code. Zero changes needed.")
    print("Just like cProfile - wrap and profile.\n")

    with tempfile.TemporaryDirectory() as tmpdir:
        data_dir = os.path.join(tmpdir, "data")
        log_dir = os.path.join(tmpdir, "logs")
        os.makedirs(data_dir)

        # create fake files
        img_file = os.path.join(data_dir, "photo.jpg")
        with open(img_file, "wb") as f:
            f.write(b"\xff\xd8\xff\xe0" + b"\x00" * 5000)  # fake JPEG

        doc_file = os.path.join(data_dir, "invoice.txt")
        with open(doc_file, "w") as f:
            f.write("Invoice #2026-001\nAmount: 50,000\nClient: Acme Corp\n")

        report_file = os.path.join(data_dir, "quarterly.txt")
        with open(report_file, "w") as f:
            f.write("Q3 Revenue: 12.5 Cr\nExpenses: 8.3 Cr\nProfit: 4.2 Cr\n")

        # === Example 1: Wrap a single library ===
        print("-" * 40)
        print("Example 1: Wrap SightRAG")
        print("-" * 40)
        print()
        print("  # WITHOUT antguard:")
        print("  rag = ImageRAG()")
        print("  result = rag.query('find similar', image='photo.jpg')")
        print()
        print("  # WITH antguard:")
        print("  with Guard(watch=['./data/']) as g:")
        print("      rag = ImageRAG()")
        print("      result = rag.query('find similar', image='photo.jpg')")
        print()

        with Guard(watch=[data_dir], runtime=True, gpu=False, log_path=log_dir) as g:
            rag = FakeImageRAG()
            result = rag.query("find similar images", img_file)
            time.sleep(1)

        print(f"  Result: {result}")
        print(f"  Data left: {g.did_data_leave()}")
        print(f"  Risk: {g.risk_level().value}")
        print(f"  File events: {len(g.file_events())}")
        print()

        # === Example 2: Wrap multiple libraries together ===
        print("-" * 40)
        print("Example 2: Wrap Multiple Libraries")
        print("-" * 40)
        print()

        with Guard(watch=[data_dir], runtime=True, gpu=False, log_path=log_dir) as g:
            # library 1
            rag = FakeImageRAG()
            img_result = rag.query("search", img_file)

            # library 2
            extractor = FakeDocExtractor()
            doc_result = extractor.extract(doc_file)

            # library 3
            agent = FakeLLMAgent()
            agent_result = agent.run("summarize this", context_file=report_file)

            time.sleep(1)

        print(f"  Three libraries wrapped in one Guard session:")
        print(f"  - ImageRAG: {img_result['result'][:40]}")
        print(f"  - DocExtractor: {doc_result['pages']} page(s)")
        print(f"  - LLMAgent: {agent_result[:40]}")
        print(f"\n  Data left: {g.did_data_leave()}")
        print(f"  Risk: {g.risk_level().value}")
        print(f"  Total file events: {len(g.file_events())}")
        print()

        # === Example 3: Start/stop style ===
        print("-" * 40)
        print("Example 3: Start/Stop (non-context-manager)")
        print("-" * 40)
        print()

        guard = Guard(watch=[data_dir], runtime=True, gpu=False, log_path=log_dir)
        guard.start()

        extractor = FakeDocExtractor()
        result = extractor.extract(doc_file)
        time.sleep(1)

        guard.stop()

        print(f"  guard.start()")
        print(f"  # ... your code ...")
        print(f"  guard.stop()")
        print(f"\n  Data left: {guard.did_data_leave()}")
        print(f"  Risk: {guard.risk_level().value}")
        print()

        # === Example 4: Compare with cProfile ===
        print("-" * 40)
        print("Example 4: Same Pattern as cProfile")
        print("-" * 40)
        print()
        print("  import cProfile")
        print("  with cProfile.Profile() as pr:")
        print("      your_code()        # unchanged")
        print("  pr.dump_stats('out.prof')")
        print()
        print("  from antguard import Guard")
        print("  with Guard(watch=['./data/']) as g:")
        print("      your_code()        # unchanged")
        print("  g.save('./logs/')")
        print()
        print("  Same philosophy. Profile locally. Report locally.")
        print("  No network. No API. No AI.")

        # save final report
        paths = g.save(log_dir)
        print(f"\n  Report: {os.path.basename(paths['txt'])}")
        print()
        print("=" * 60)
        print("Your libraries don't know antguard exists.")
        print("antguard doesn't know your libraries exist.")
        print("It watches the machine, not the code.")
        print("=" * 60)


if __name__ == "__main__":
    main()
