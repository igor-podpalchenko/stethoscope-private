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

Shutdown behavior:
  - On Ctrl+C / SIGTERM: begin graceful shutdown
  - Also schedules a hard self-terminate: send SIGKILL to own PID after 1 second
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
from typing import Dict, Set, Tuple


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


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    chunk_size: int,
    out_lock: asyncio.Lock,
    status: bool,
    stop_event: asyncio.Event,
    colors: ColorManager,
    active_writers: Set[asyncio.StreamWriter],
    writers_lock: asyncio.Lock,
) -> None:
    peer = writer.get_extra_info("peername")
    port = peer_port(writer)
    session = peer_key(writer)
    port_tag = colorize(f"{{{port}}}", colors.code_for_session(session))

    async with writers_lock:
        active_writers.add(writer)

    try:
        if status:
            async with out_lock:
                sys.stdout.write(f"\n[+] connected: {peer}\n")
                sys.stdout.flush()

        while not stop_event.is_set():
            data = await reader.read(chunk_size)
            if not data:
                break

            payload = escape_bytes_ascii_or_hex(data)

            # Required format: "\n{23323}\n" + payload + "\n"
            async with out_lock:
                sys.stdout.write(f"\n{port_tag}\n{payload}\n")
                sys.stdout.flush()

    except asyncio.CancelledError:
        pass
    except Exception as e:
        if status:
            async with out_lock:
                sys.stdout.write(f"\n[!] error from {peer}: {e}\n")
                sys.stdout.flush()
    finally:
        async with writers_lock:
            active_writers.discard(writer)

        await close_writer(writer)

        if status:
            async with out_lock:
                sys.stdout.write(f"\n[-] disconnected: {peer}\n")
                sys.stdout.flush()


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=33030)
    ap.add_argument("--chunk-size", type=int, default=65536)
    ap.add_argument("--status", action="store_true", help="Print connect/disconnect lines")
    ap.add_argument("--kill-after", type=float, default=1.0, help="Seconds after Ctrl+C to SIGKILL self (default: 1.0)")
    args = ap.parse_args()

    out_lock = asyncio.Lock()
    stop_event = asyncio.Event()
    client_tasks: Set[asyncio.Task[None]] = set()
    colors = ColorManager()

    active_writers: Set[asyncio.StreamWriter] = set()
    writers_lock = asyncio.Lock()

    loop = asyncio.get_running_loop()
    pid = os.getpid()

    kill_handle: asyncio.Handle | None = None
    stopping = False

    def schedule_self_kill() -> None:
        nonlocal kill_handle
        if kill_handle is not None:
            return
        # Fire-and-forget: hard kill after N seconds.
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
                out_lock=out_lock,
                status=args.status,
                stop_event=stop_event,
                colors=colors,
                active_writers=active_writers,
                writers_lock=writers_lock,
            )
        )
        client_tasks.add(t)
        t.add_done_callback(lambda task: client_tasks.discard(task))

    server = await asyncio.start_server(_on_connect, host=args.host, port=args.port)

    if args.status:
        addrs = ", ".join(str(sock.getsockname()) for sock in (server.sockets or []))
        sys.stdout.write(f"[*] listening on {addrs}\n")
        sys.stdout.flush()

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
        sys.stdout.write("\n[*] shut down\n")
        sys.stdout.flush()

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except KeyboardInterrupt:
        # If we ever get here (some environments), mimic the same behavior:
        try:
            pid = os.getpid()
            loop = None
            # best-effort delayed SIGKILL without an event loop:
            import time
            time.sleep(1.0)
            os.kill(pid, signal.SIGKILL)
        except Exception:
            raise SystemExit(0)
