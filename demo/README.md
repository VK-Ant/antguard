# antguard Demos

**Guard. Detect. Protect.**

## Quick Start (Google Colab)

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/VK-Ant/antguard/blob/main/demo/antguard_quickstart.ipynb)

Open `antguard_quickstart.ipynb` — runs in 2 minutes, no setup needed.

## Local Demos

```bash
pip install antguard
```

| Demo | What it shows | Run |
|------|--------------|-----|
| `demo_01_file_monitoring.py` | File read/write tracking + fingerprinting | `python demo/demo_01_file_monitoring.py` |
| `demo_02_exfiltration_detection.py` | Data sent to external server — antguard catches it | `python demo/demo_02_exfiltration_detection.py` |
| `demo_03_suspicious_process.py` | Shell commands and subprocess spawning detection | `python demo/demo_03_suspicious_process.py` |
| `demo_04_runtime_metrics.py` | CPU, GPU, memory profiling during heavy computation | `python demo/demo_04_runtime_metrics.py` |
| `demo_05_full_audit.py` | All features combined — the showcase demo | `python demo/demo_05_full_audit.py` |
| `demo_06_wrap_any_library.py` | Shows antguard wrapping any code without changes | `python demo/demo_06_wrap_any_library.py` |

## Recommended Order

1. `demo_05_full_audit.py` — start here, see everything
2. `demo_02_exfiltration_detection.py` — the strongest demo for privacy
3. `demo_06_wrap_any_library.py` — understand the cProfile pattern
4. Run the rest as needed

## All Demos Are Safe

No real data leaves your machine. Exfiltration demos use `127.0.0.1` local test servers. Everything runs in temp directories and cleans up after itself.
