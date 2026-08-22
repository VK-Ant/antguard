"""Basic tests for antguard."""

import os
import time
import tempfile
import shutil

from antguard import Guard, __version__
from antguard.models import RiskLevel


def test_version():
    assert __version__ == "0.1.0"


def test_guard_basic():
    """Test basic Guard with file monitoring."""
    with tempfile.TemporaryDirectory() as tmpdir:
        data_dir = os.path.join(tmpdir, "data")
        log_dir = os.path.join(tmpdir, "logs")
        os.makedirs(data_dir)

        # create test file
        test_file = os.path.join(data_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("confidential data here")

        guard = Guard(
            watch=[data_dir],
            detect_outbound=True,
            track_processes=True,
            correlate=True,
            runtime=True,
            gpu=False,
            log_path=log_dir,
            runtime_interval=0.5,
        )

        guard.start()
        time.sleep(1)

        # simulate file operations
        with open(test_file, "r") as f:
            content = f.read()

        new_file = os.path.join(data_dir, "output.txt")
        with open(new_file, "w") as f:
            f.write("summary: " + content[:10])

        time.sleep(2)
        guard.stop()

        # verify results
        assert guard.did_data_leave() is False
        assert guard.risk_level() == RiskLevel.LOW
        assert isinstance(guard.summary(), str)
        assert "data_left=False" in guard.summary()

        # verify runtime metrics
        metrics = guard.runtime_metrics()
        assert metrics is not None
        assert metrics.snapshot_count > 0
        assert metrics.cpu_avg >= 0

        # verify fingerprints
        fps = guard.fingerprints()
        assert len(fps) > 0

        # verify data flow map
        dfm = guard.data_flow_map()
        assert dfm["data_left"] is False

        # save reports
        paths = guard.save(log_dir)
        assert os.path.exists(paths["txt"])
        assert os.path.exists(paths["json"])

        # read and verify txt report
        with open(paths["txt"]) as f:
            report = f.read()
        assert "DATA LEFT SYSTEM: NO" in report
        assert "OVERALL RISK: LOW" in report

        print("txt report:")
        print(report)
        print()
        print("summary:", guard.summary())
        print("to_dict:", guard.to_dict())


def test_context_manager():
    """Test Guard as context manager."""
    with tempfile.TemporaryDirectory() as tmpdir:
        data_dir = os.path.join(tmpdir, "data")
        log_dir = os.path.join(tmpdir, "logs")
        os.makedirs(data_dir)

        test_file = os.path.join(data_dir, "secret.pdf")
        with open(test_file, "wb") as f:
            f.write(b"fake pdf content " * 100)

        with Guard(
            watch=[data_dir],
            runtime=True,
            gpu=False,
            log_path=log_dir,
        ) as g:
            time.sleep(1)
            with open(test_file, "rb") as f:
                _ = f.read()
            time.sleep(1)

        assert g.did_data_leave() is False
        print("context manager test passed")


if __name__ == "__main__":
    print("=" * 60)
    print("antguard v0.1.0 — Test Suite")
    print("=" * 60)
    print()

    test_version()
    print("[PASS] version check")

    test_guard_basic()
    print("[PASS] basic guard")

    test_context_manager()
    print("[PASS] context manager")

    print()
    print("=" * 60)
    print("All tests passed")
    print("=" * 60)
