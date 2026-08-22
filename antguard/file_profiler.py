"""antguard file profiler. Watches directories for file events."""

import os
import time
import threading
from typing import List, Dict, Optional, Callable

from watchdog.observers import Observer
from watchdog.events import (
    FileSystemEventHandler,
    FileCreatedEvent,
    FileModifiedEvent,
    FileDeletedEvent,
    FileMovedEvent,
)

from .models import FileEvent, FileAction, RiskLevel
from .utils import file_sha256, chunk_hashes, file_size


class _FileEventHandler(FileSystemEventHandler):

    def __init__(self, profiler: "FileProfiler"):
        super().__init__()
        self._profiler = profiler

    def on_created(self, event):
        if event.is_directory:
            return
        self._profiler._record(FileAction.CREATE, event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        self._profiler._record(FileAction.MODIFY, event.src_path)

    def on_deleted(self, event):
        if event.is_directory:
            return
        self._profiler._record(FileAction.DELETE, event.src_path)

    def on_moved(self, event):
        if event.is_directory:
            return
        self._profiler._record(FileAction.MOVE, event.src_path, dest=event.dest_path)


class FileProfiler:

    def __init__(
        self,
        watch_paths: List[str],
        chunk_size: int = 4096,
        on_event: Optional[Callable] = None,
    ):
        self._watch_paths = [os.path.abspath(p) for p in watch_paths]
        self._chunk_size = chunk_size
        self._on_event = on_event
        self._observer: Optional[Observer] = None
        self._events: List[FileEvent] = []
        self._lock = threading.Lock()

        # file fingerprints: path -> {hash, chunks, size}
        self._fingerprints: Dict[str, dict] = {}

    def _build_fingerprints(self):
        for watch_path in self._watch_paths:
            if not os.path.exists(watch_path):
                continue
            if os.path.isfile(watch_path):
                self._fingerprint_file(watch_path)
            else:
                for root, _, files in os.walk(watch_path):
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        self._fingerprint_file(fpath)

    def _fingerprint_file(self, path: str):
        abs_path = os.path.abspath(path)
        fhash = file_sha256(abs_path)
        fchunks = chunk_hashes(abs_path, self._chunk_size)
        fsize = file_size(abs_path)
        if fhash:
            self._fingerprints[abs_path] = {
                "hash": fhash,
                "chunks": fchunks,
                "size": fsize,
            }

    def _get_process_info(self):
        try:
            import psutil
            proc = psutil.Process()
            parent = proc.parent()
            return {
                "name": proc.name(),
                "pid": proc.pid,
                "parent_name": parent.name() if parent else "",
                "parent_pid": parent.pid if parent else 0,
            }
        except Exception:
            return {"name": "", "pid": 0, "parent_name": "", "parent_pid": 0}

    def _record(self, action: FileAction, path: str, dest: str = ""):
        abs_path = os.path.abspath(path)
        sz = file_size(abs_path) if action != FileAction.DELETE else 0
        fhash = ""

        if action in (FileAction.CREATE, FileAction.MODIFY):
            fhash = file_sha256(abs_path)
            if fhash:
                self._fingerprint_file(abs_path)
        elif action == FileAction.DELETE:
            self._fingerprints.pop(abs_path, None)
        elif action == FileAction.MOVE and dest:
            old_fp = self._fingerprints.pop(abs_path, None)
            if old_fp:
                abs_dest = os.path.abspath(dest)
                self._fingerprints[abs_dest] = old_fp
                fhash = old_fp.get("hash", "")
        else:
            fp = self._fingerprints.get(abs_path, {})
            fhash = fp.get("hash", "")

        proc = self._get_process_info()

        event = FileEvent(
            timestamp=time.time(),
            action=action,
            path=abs_path,
            size_bytes=sz,
            file_hash=fhash,
            process_name=proc["name"],
            process_pid=proc["pid"],
            parent_process=proc["parent_name"],
            parent_pid=proc["parent_pid"],
            risk=RiskLevel.LOW,
        )

        with self._lock:
            self._events.append(event)

        if self._on_event:
            self._on_event(event)

    def start(self):
        self._build_fingerprints()
        self._observer = Observer()
        handler = _FileEventHandler(self)
        for wpath in self._watch_paths:
            if os.path.exists(wpath):
                is_dir = os.path.isdir(wpath)
                self._observer.schedule(
                    handler,
                    wpath if is_dir else os.path.dirname(wpath),
                    recursive=is_dir,
                )
        self._observer.start()

    def stop(self):
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._observer = None

    @property
    def events(self) -> List[FileEvent]:
        with self._lock:
            return list(self._events)

    @property
    def fingerprints(self) -> Dict[str, dict]:
        return dict(self._fingerprints)

    def get_reads(self) -> List[FileEvent]:
        return [e for e in self.events if e.action in (FileAction.READ, FileAction.MODIFY)]

    def get_writes(self) -> List[FileEvent]:
        return [e for e in self.events if e.action in (FileAction.WRITE, FileAction.CREATE)]
