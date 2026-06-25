"""Async bridge from BCC ring buffers to an :class:`asyncio.Queue`.

BCC delivers ring-buffer records through a synchronous callback invoked from
``ring_buffer_poll()``, which blocks. This reader runs that polling on a worker
thread (via :func:`asyncio.to_thread`) and hands each parsed event to the event
loop with :meth:`asyncio.AbstractEventLoop.call_soon_threadsafe`, so nothing
blocks the loop and back-pressure is handled by dropping (and counting) events
when the queue is full rather than stalling the kernel-side producer.

This module deliberately does not import ``bcc``: it operates on whatever BPF
objects it is handed, so it imports and unit-tests on any platform.
"""

from __future__ import annotations

import asyncio
from typing import Any, Callable, Dict, Optional

# A parser turns a raw ring-buffer record (ctx, data, size) into an event object.
ParserFn = Callable[[Any, Any, int], Any]


class RingBufferReader:
    """Polls one or more BCC ring buffers and feeds parsed events to a queue."""

    def __init__(
        self,
        bpf_objects: Dict[str, Any],
        queue: "asyncio.Queue[Any]",
        poll_interval_ms: int = 100,
    ) -> None:
        self._bpf_objects = bpf_objects
        self._queue = queue
        self.poll_interval_ms = poll_interval_ms

        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._stop_event = asyncio.Event()
        self._task: Optional["asyncio.Future[None]"] = None
        self.dropped_events = 0

    def register(self, bpf_key: str, table_name: str, parser_fn: ParserFn) -> None:
        """Open ``table_name`` on the named BPF object with a parsing callback.

        Args:
            bpf_key: Key into ``bpf_objects`` identifying the BPF program.
            table_name: The ``BPF_RINGBUF_OUTPUT`` table to subscribe to.
            parser_fn: Converts ``(ctx, data, size)`` into an event object.
        """
        bpf = self._bpf_objects[bpf_key]
        bpf[table_name].open_ring_buffer(self._make_callback(parser_fn))

    def _make_callback(self, parser_fn: ParserFn) -> Callable[[Any, Any, int], None]:
        """Wrap a parser so its output is enqueued thread-safely and non-blocking."""

        def callback(ctx: Any, data: Any, size: int) -> None:
            try:
                event = parser_fn(ctx, data, size)
            except Exception:  # noqa: BLE001 - a bad record must not kill polling
                return
            if event is None or self._loop is None:
                return
            self._loop.call_soon_threadsafe(self._enqueue, event)

        return callback

    def _enqueue(self, event: Any) -> None:
        """Runs on the event loop thread; drop-and-count if the queue is full."""
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            self.dropped_events += 1

    async def start(self, loop: asyncio.AbstractEventLoop) -> None:
        """Begin polling in the background. Idempotent per reader instance."""
        self._loop = loop
        self._stop_event.clear()
        self._task = asyncio.ensure_future(self._poll_loop())

    async def stop(self) -> None:
        """Signal the poll loop to finish and wait for it to unwind."""
        self._stop_event.set()
        if self._task is not None:
            await self._task
            self._task = None

    async def _poll_loop(self) -> None:
        """Repeatedly poll every ring buffer on a worker thread until stopped."""
        while not self._stop_event.is_set():
            await asyncio.to_thread(self._poll_once)
            # Yield control so cancellation / other tasks get a turn.
            await asyncio.sleep(0)

    def _poll_once(self) -> None:
        """Blocking poll of all BPF ring buffers (runs in a worker thread)."""
        for bpf in self._bpf_objects.values():
            try:
                bpf.ring_buffer_poll(self.poll_interval_ms)
            except Exception:  # noqa: BLE001 - keep polling the other buffers
                continue
