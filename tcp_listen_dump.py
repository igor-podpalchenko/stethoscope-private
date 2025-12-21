#!/usr/bin/env python3
r"""
tcp_listen_dump.py

Like: nc -lk 127.0.0.1 33030
…but prints incoming bytes with:
  - printable ASCII (plus \t \r \n) shown as-is
  - everything else encoded as uppercase hex (no \x), e.g. C001AFA4...
  - each chunk is printed as:

        \n{23323}\n<DATA>\n

    (the {port} line is colorized per session when stdout is a TTY)

Key behavior (async buffering):
  - Receive path NEVER prints.
  - Each received chunk is put into an unbounded in-memory queue immediately (no maxsize).
  - A separate sink task drains the queue and prints to stdout at its own pace.
    This absorbs spikes without back-pressuring the sender.

Shutdown behavior:
  - On Ctrl+C / SIGTERM: begin graceful shutdown
  - Also schedules a hard self-terminate: send SIGKILL to own PID after N seconds
    (to avoid any “stuck” async shutdown cases)

Usage:
  python3 tcp_listen_dump.py
  python3 tcp_listen_dump.py --host 127.0.0.1 --port 33030
  python3 tcp_listen_dump.py --status
"""

from __future__ import annotations

import argparse
import asyncio
import os
import signal
import sys
from dataclasses import dataclass
from typing import Dict, Optional, Set, Tuple


def escape_bytes_ascii_or_hex(data: bytes) -> str:
    """
    Printable ASCII and whitespace (\t\r\n) are emitted as characters.
    Everything else is emitted as two uppercase hex chars (no prefix).
    """
    out_parts: list[str] = []
    for b in data:
        if b in (9, 10, 13) or (32 <= b <= 126):
            out_parts.append(chr(b))
        else:
            out_parts.append(f"{b:02X}")
    return "".join(out_parts)


def _use_color() -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    return sys.stdout.isatty()


def colorize(s: str, code: str) -> str:
    if not _use_color():
        return s
    return f"\x1b[{code}m{s}\x1b[0m"


def peer_port(writer: asyncio.StreamWriter) -> str:
    peer = writer.get_extra_info("peername")
    if isinstance(peer, tuple) and len(peer) >= 2:
        return str(peer[1])
    return "?"


def peer_key(writer: asyncio.StreamWriter) -> str:
    return repr(writer.get_extra_info("peername"))


async def close_writer(writer: asyncio.StreamWriter, timeout: float = 0.25) -> None:
    try:
        writer.close()
    except Exception:
        return
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=timeout)
    except (asyncio.TimeoutError, Exception):
        pass


@dataclass
class ColorManager:
    palette: Tuple[str, ...] = (
        "31", "32", "33", "34", "35", "36",
        "91", "92", "93", "94", "95", "96",
    )
    _next: int = 0
    _map: Dict[str, str] = None  # session_key -> ansi_code

    def __post_init__(self) -> None:
        if self._map is None:
            self._map = {}

    def code_for_session(self, session_key: str) -> str:
        code = self._map.get(session_key)
        if code is not None:
            return code
        code = self.palette[self._next % len(self.palette)]
        self._next += 1
        self._map[session_key] = code
        return code


@dataclass(frozen=True)
class QueueItem:
    kind: str  # "data" | "status"
    port_tag: str = ""          # for kind=="data"
    data: bytes = b""           # for kind=="data"
    msg: str = ""               # for kind=="status"


async def sink_printer(
    q: asyncio.Queue[Optional[QueueItem]],
) -> None:
    """
    Single consumer responsible for ALL stdout writes.
    Drains the queue and prints items sequentially.
    """
    try:
        while True:
            item = await q.get()
            if item is None:
                return

            if item.kind == "data":
                payload = escape_bytes_ascii_or_hex(item.data)
                sys.stdout.write(f"\n{item.port_tag}\n{payload}\n")
            elif item.kind == "status":
                sys.stdout.write(item.msg)
                if not item.msg.endswith("\n"):
                    sys.stdout.write("\n")
            else:
                sys.stdout.write(f"[!] unknown queue item kind={item.kind!r}\n")

            sys.stdout.flush()
    except asyncio.CancelledError:
        # Best-effort: if we're cancelled during shutdown, just stop.
        pass


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    chunk_size: int,
    status: bool,
    stop_event: asyncio.Event,
    colors: ColorManager,
    active_writers: Set[asyncio.StreamWriter],
    writers_lock: asyncio.Lock,
    out_q: asyncio.Queue[Optional[QueueItem]],
) -> None:
    peer = writer.get_extra_info("peername")
    port = peer_port(writer)
    session = peer_key(writer)
    port_tag = colorize(f"{{{port}}}", colors.code_for_session(session))

    async with writers_lock:
        active_writers.add(writer)

    try:
        if status:
            out_q.put_nowait(QueueItem(kind="status", msg=f"\n[+] connected: {peer}\n"))

        while not stop_event.is_set():
            data = await reader.read(chunk_size)
            if not data:
                break

            # Receive path: do NOT print, do NOT do heavy transforms.
            # Just enqueue raw bytes for the sink to format/print later.
            out_q.put_nowait(QueueItem(kind="data", port_tag=port_tag, data=data))

    except asyncio.CancelledError:
        pass
    except Exception as e:
        if status:
            out_q.put_nowait(QueueItem(kind="status", msg=f"\n[!] error from {peer}: {e}\n"))
    finally:
        async with writers_lock:
            active_writers.discard(writer)

        await close_writer(writer)

        if status:
            out_q.put_nowait(QueueItem(kind="status", msg=f"\n[-] disconnected: {peer}\n"))


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=33030)
    ap.add_argument("--chunk-size", type=int, default=65536)
    ap.add_argument("--status", action="store_true", help="Print connect/disconnect lines")
    ap.add_argument("--kill-after", type=float, default=1.0,
                    help="Seconds after Ctrl+C to SIGKILL self (default: 1.0)")
    args = ap.parse_args()

    stop_event = asyncio.Event()
    client_tasks: Set[asyncio.Task[None]] = set()
    colors = ColorManager()

    active_writers: Set[asyncio.StreamWriter] = set()
    writers_lock = asyncio.Lock()

    # Unbounded queue (no maxsize) to absorb spikes.
    out_q: asyncio.Queue[Optional[QueueItem]] = asyncio.Queue()
    sink_task = asyncio.create_task(sink_printer(out_q))

    loop = asyncio.get_running_loop()
    pid = os.getpid()

    kill_handle: Optional[asyncio.Handle] = None
    stopping = False

    def schedule_self_kill() -> None:
        nonlocal kill_handle
        if kill_handle is not None:
            return

        def _kill() -> None:
            try:
                os.kill(pid, signal.SIGKILL)
            except Exception:
                pass

        kill_handle = loop.call_later(max(0.0, args.kill_after), _kill)

    def request_stop() -> None:
        nonlocal stopping
        if stopping:
            return
        stopping = True
        stop_event.set()
        schedule_self_kill()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, request_stop)
        except NotImplementedError:
            signal.signal(sig, lambda *_: request_stop())

    async def _on_connect(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        t = asyncio.create_task(
            handle_client(
                reader,
                writer,
                chunk_size=args.chunk_size,
                status=args.status,
                stop_event=stop_event,
                colors=colors,
                active_writers=active_writers,
                writers_lock=writers_lock,
                out_q=out_q,
            )
        )
        client_tasks.add(t)
        t.add_done_callback(lambda task: client_tasks.discard(task))

    server = await asyncio.start_server(_on_connect, host=args.host, port=args.port)

    if args.status:
        addrs = ", ".join(str(sock.getsockname()) for sock in (server.sockets or []))
        out_q.put_nowait(QueueItem(kind="status", msg=f"[*] listening on {addrs}\n"))

    try:
        async with server:
            await stop_event.wait()
    finally:
        # Stop accepting new connections.
        server.close()
        try:
            await asyncio.wait_for(server.wait_closed(), timeout=0.5)
        except (asyncio.TimeoutError, Exception):
            pass

        # Force-close all active writers to unblock reader.read().
        async with writers_lock:
            writers = list(active_writers)

        for w in writers:
            await close_writer(w)

        # Cancel handlers.
        for t in list(client_tasks):
            t.cancel()

        if client_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*client_tasks, return_exceptions=True),
                    timeout=0.5,
                )
            except (asyncio.TimeoutError, Exception):
                pass

        if args.status:
            out_q.put_nowait(QueueItem(kind="status", msg="\n[*] shut down\n"))

        # Tell sink to stop. (If the queue is huge, draining may take long; SIGKILL remains the backstop.)
        out_q.put_nowait(None)
        try:
            await asyncio.wait_for(sink_task, timeout=0.75)
        except (asyncio.TimeoutError, Exception):
            sink_task.cancel()

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except KeyboardInterrupt:
        # Best-effort hard stop if we're outside the main signal flow.
        try:
            import time
            time.sleep(1.0)
            os.kill(os.getpid(), signal.SIGKILL)
        except Exception:
            raise SystemExit(0)
