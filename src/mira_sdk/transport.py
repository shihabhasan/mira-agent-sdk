"""Shipping records to the control plane, off the agent's critical path.

The asymmetry here is deliberate and worth stating to anyone deploying this:

    refusing an action is synchronous and fails CLOSED
    recording  an action is asynchronous and fails OPEN

Anything else either stalls the agent behind the network or lets it act with
no evidence. So the gate never touches this class, and this class never blocks
the caller: records go onto a bounded queue and a daemon thread drains it.

The queue is bounded on purpose. An unbounded buffer in someone else's agent
is a memory leak with our name on it; when it overflows we drop the OLDEST
record and count it, because the newest evidence is the evidence you most
likely still need.
"""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

log = logging.getLogger("mira.transport")


@dataclass
class TransportStats:
    queued: int = 0
    sent: int = 0
    dropped: int = 0
    failed_batches: int = 0

    def as_dict(self) -> dict:
        return {
            "queued": self.queued, "sent": self.sent,
            "dropped": self.dropped, "failed_batches": self.failed_batches,
        }


class RecordTransport:
    """Batched, retrying, non-blocking sender for signed step records."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        max_queue: int = 10_000,
        batch_size: int = 50,
        flush_interval_s: float = 1.0,
        timeout_s: float = 10.0,
        max_retries: int = 3,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.batch_size = batch_size
        self.flush_interval_s = flush_interval_s
        self.timeout_s = timeout_s
        self.max_retries = max_retries
        self.stats = TransportStats()

        self._q: queue.Queue[dict] = queue.Queue(maxsize=max_queue)
        self._stop = threading.Event()
        self._flushed = threading.Event()
        self._lock = threading.Lock()
        self._worker = threading.Thread(
            target=self._drain, daemon=True, name="mira-transport"
        )
        self._worker.start()

    # ------------------------------------------------------------ enqueue

    def submit(self, record: dict) -> None:
        """Never blocks, never raises. Drops the oldest on overflow."""
        with self._lock:
            self.stats.queued += 1
        while True:
            try:
                self._q.put_nowait(record)
                self._flushed.clear()
                return
            except queue.Full:
                try:
                    self._q.get_nowait()
                    with self._lock:
                        self.stats.dropped += 1
                except queue.Empty:
                    return

    # -------------------------------------------------------------- drain

    def _drain(self) -> None:
        batch: list[dict] = []
        last = time.monotonic()
        while not self._stop.is_set():
            timeout = max(0.05, self.flush_interval_s - (time.monotonic() - last))
            try:
                batch.append(self._q.get(timeout=timeout))
            except queue.Empty:
                pass
            due = (
                len(batch) >= self.batch_size
                or (batch and time.monotonic() - last >= self.flush_interval_s)
            )
            if due:
                self._send(batch)
                batch, last = [], time.monotonic()
            if not batch and self._q.empty():
                self._flushed.set()
        if batch:
            self._send(batch)
        self._flushed.set()

    def _send(self, batch: list[dict]) -> None:
        body = json.dumps({"records": batch}).encode()
        delay = 0.25
        for attempt in range(self.max_retries):
            try:
                req = urllib.request.Request(
                    f"{self.base_url}/api/v1/records",
                    data=body,
                    method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {self.api_key}",
                    },
                )
                with urllib.request.urlopen(req, timeout=self.timeout_s) as r:
                    if 200 <= r.status < 300:
                        with self._lock:
                            self.stats.sent += len(batch)
                        return
            except urllib.error.HTTPError as e:
                # 4xx other than 429 will never succeed on retry
                if e.code != 429 and 400 <= e.code < 500:
                    log.warning("mira: records rejected (%s) — dropping batch", e.code)
                    with self._lock:
                        self.stats.failed_batches += 1
                        self.stats.dropped += len(batch)
                    return
            except Exception:  # network, DNS, timeout
                pass
            time.sleep(delay)
            delay *= 2
        log.warning("mira: could not ship %d record(s) after %d attempts",
                    len(batch), self.max_retries)
        with self._lock:
            self.stats.failed_batches += 1
            self.stats.dropped += len(batch)

    # ------------------------------------------------------------ control

    def flush(self, timeout: float = 10.0) -> bool:
        """Block until the queue drains. Returns False on timeout."""
        return self._flushed.wait(timeout)

    def close(self, timeout: float = 10.0) -> None:
        self.flush(timeout)
        self._stop.set()
        self._worker.join(timeout=2.0)
