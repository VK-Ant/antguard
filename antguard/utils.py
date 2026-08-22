"""antguard utilities. Hashing, platform detection, helpers."""

import hashlib
import os
import platform
import sys
from typing import List, Optional


def get_platform_info() -> dict:
    return {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": sys.version.split()[0],
        "platform_string": platform.platform(),
    }


def file_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return ""


def chunk_hashes(filepath: str, chunk_size: int = 4096) -> List[str]:
    hashes = []
    try:
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hashes.append(hashlib.sha256(chunk).hexdigest())
    except (OSError, PermissionError):
        pass
    return hashes


def file_size(filepath: str) -> int:
    try:
        return os.path.getsize(filepath)
    except OSError:
        return 0


def is_local_address(addr: str) -> bool:
    local = {
        "127.0.0.1", "localhost", "::1", "0.0.0.0",
        "127.0.1.1", "localhost.localdomain",
    }
    if addr in local:
        return True
    if addr.startswith("127."):
        return True
    if addr.startswith("192.168."):
        return True
    if addr.startswith("10."):
        return True
    if addr.startswith("172.") and 16 <= int(addr.split(".")[1]) <= 31:
        return True
    return False


SUSPICIOUS_COMMANDS = {
    "curl", "wget", "scp", "nc", "netcat", "ncat",
    "ftp", "sftp", "rsync", "powershell", "cmd",
    "bash", "sh", "zsh", "csh",
}


SHELL_NAMES = {
    "bash", "sh", "zsh", "csh", "ksh", "fish",
    "cmd.exe", "powershell.exe", "pwsh.exe", "pwsh",
    "cmd", "powershell", "conhost.exe",
}


def is_shell_process(name: str) -> bool:
    return name.lower() in SHELL_NAMES


def is_suspicious_command(name: str) -> bool:
    return name.lower() in SUSPICIOUS_COMMANDS


def format_bytes(b: int) -> str:
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 * 1024 * 1024:
        return f"{b / (1024 * 1024):.1f} MB"
    else:
        return f"{b / (1024 * 1024 * 1024):.2f} GB"
