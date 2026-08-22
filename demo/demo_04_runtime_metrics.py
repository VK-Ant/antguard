"""
antguard Demo 4: Runtime Metrics Profiling
===========================================
Profiles CPU, GPU, memory, disk during heavy computation.
Shows anomaly detection when spikes occur.

Run: python demo_04_runtime_metrics.py
"""

import os
import time
import tempfile
import math
from antguard import Guard


def heavy_cpu_task():
    """Simulate heavy CPU computation (like model inference)."""
    result = 0
    for i in range(500_000):
        result += math.sin(i) * math.cos(i) * math.tan(i % 1000 + 1)
    return result


def heavy_memory_task():
    """Simulate memory-heavy operation."""
    data = []
    for i in range(50):
        data.append([0] * 100_000)
    time.sleep(0.5)
    return len(data)


def main():
    print("=" * 60)
    print("antguard Demo 4: Runtime Metrics Profiling")
    print("Guard. Detect. Protect.")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        data_dir = os.path.join(tmpdir, "data")
        log_dir = os.path.join(tmpdir, "logs")
        os.makedirs(data_dir)

        # create test data file
        test_file = os.path.join(data_dir, "dataset.csv")
        with open(test_file, "w") as f:
            f.write("id,value\n")
            for i in range(10_000):
                f.write(f"{i},{math.sin(i) * 100:.2f}\n")

        print(f"\nCreated test dataset: dataset.csv")
        print("Starting antguard profiler (sampling every 0.5s)...\n")

        with Guard(
            watch=[data_dir],
            detect_outbound=True,
            track_processes=True,
            runtime=True,
            gpu=True,
            log_path=log_dir,
            runtime_interval=0.5,
        ) as g:
            print("--- Phase 1: File I/O ---")
            with open(test_file, "r") as f:
                lines = f.readlines()
            print(f"  Read {len(lines)} lines")
            time.sleep(1)

            print("--- Phase 2: Heavy CPU (simulating inference) ---")
            t0 = time.time()
            result = heavy_cpu_task()
            cpu_time = time.time() - t0
            print(f"  Completed in {cpu_time:.1f}s")
            time.sleep(1)

            print("--- Phase 3: Heavy Memory ---")
            t0 = time.time()
            mem_result = heavy_memory_task()
            mem_time = time.time() - t0
            print(f"  Allocated {mem_result} blocks in {mem_time:.1f}s")
            time.sleep(1)

            print("--- Phase 4: Write Results ---")
            output_file = os.path.join(data_dir, "result.txt")
            with open(output_file, "w") as f:
                f.write(f"CPU result: {result}\n")
                f.write(f"Memory blocks: {mem_result}\n")
            print("  Results saved")
            time.sleep(1)

            print("\n--- Workload Finished ---\n")

        # results
        print("=" * 60)
        print("RUNTIME PROFILING RESULTS")
        print("=" * 60)

        metrics = g.runtime_metrics()
        if metrics:
            print(f"\nDuration: {metrics.duration_sec:.1f}s")
            print(f"Samples collected: {metrics.snapshot_count}")

            print(f"\nCPU:")
            print(f"  Average: {metrics.cpu_avg:.1f}%")
            print(f"  Peak: {metrics.cpu_peak:.1f}%")

            print(f"\nSystem Memory:")
            print(f"  Average: {metrics.memory_avg_bytes / (1024**3):.2f} GB")
            print(f"  Peak: {metrics.memory_peak_bytes / (1024**3):.2f} GB")

            print(f"\nProcess Memory (RSS):")
            print(f"  Average: {metrics.process_rss_avg / (1024**2):.1f} MB")
            print(f"  Peak: {metrics.process_rss_peak / (1024**2):.1f} MB")

            print(f"\nDisk I/O:")
            print(f"  Read: {metrics.disk_total_read / (1024**2):.1f} MB")
            print(f"  Write: {metrics.disk_total_write / (1024**2):.1f} MB")

            if metrics.gpu_avg_util >= 0:
                print(f"\nGPU:")
                print(f"  Utilization: {metrics.gpu_avg_util:.1f}% avg / {metrics.gpu_peak_util:.1f}% peak")
                print(f"  Memory: {metrics.gpu_memory_avg / (1024**3):.2f} GB avg")
                if metrics.gpu_temperature_avg >= 0:
                    print(f"  Temperature: {metrics.gpu_temperature_avg:.0f}C avg / {metrics.gpu_temperature_peak:.0f}C peak")
            else:
                print(f"\nGPU: not detected (install antguard[gpu] for NVIDIA)")

            if metrics.anomalies:
                print(f"\nANOMALIES DETECTED:")
                for a in metrics.anomalies:
                    print(f"  {a}")
            else:
                print(f"\nNo anomalies detected")

        print(f"\nData left system: {g.did_data_leave()}")
        print(f"Risk level: {g.risk_level().name}")

        paths = g.save(log_dir)

        print("\n" + "=" * 60)
        print("FULL TEXT REPORT")
        print("=" * 60)
        with open(paths["txt"]) as f:
            print(f.read())


if __name__ == "__main__":
    main()
