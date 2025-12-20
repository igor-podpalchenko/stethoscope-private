#!/usr/bin/env python3
"""
stethoscope.py

BPF/pcap capture + TCP reassembly + forwarding, with sane control-plane event routing.

Key behavior:
- Control plane is NOT a firehose.
- Events are categorized: session/ports/output/control/flow/debug/stats
- CP receives only subscribed categories (control.default_cats) by default.
- flow events (tcp_note) are emitted to CP only when tcp_flow_enable is set (global or per-session).
- Periodic stats are LOCAL logs only by default.

Requested changes implemented:
- flow.tcp_note (including ack_stall) is DEBUG.
- output.connector_disconnected is sent to CP ONLY if that connector stream was connected before.
  Otherwise, it logs output.connector_connection_reattempt / output.connector_reconnect locally only.
- Ctrl+C clean shutdown under sudo: timed sniff loop + explicit signal handlers + task cancellation + joins.

Restored vs your reference source:
- io.input.capture.local_port filtering support.
- TCP option parsing: MSS/WScale/SAckOK.
- Derived metrics tracked per direction: max_rwnd_bytes (scaled window), max_inflight_est.
- runtime.workers == 0 => auto (CPU count).
- CLI --log-level override (optional), while still supporting config-based logging.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import queue
import re
import signal
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple, List, Set, DefaultDict
from collections import defaultdict

# -----------------------------------------------------------------------------
# Child-process registry (for emergency shutdown)
# -----------------------------------------------------------------------------
_CHILD_PROCS = []

def register_child_process(p):
    """Register a subprocess.Popen created by this program."""
    try:
        _CHILD_PROCS.append(p)
    except Exception:
        pass

def terminate_child_processes(grace_sec: float = 0.4) -> None:
    """Terminate only children we spawned. Never touch parent shells/terminals."""
    # First: SIGTERM
    for p in list(_CHILD_PROCS):
        try:
            if p.poll() is None:
                p.terminate()
        except Exception:
            pass
    # Wait a bit
    try:
        import time
        time.sleep(max(0.0, float(grace_sec)))
    except Exception:
        pass
    # Then: SIGKILL if still running
    for p in list(_CHILD_PROCS):
        try:
            if p.poll() is None:
                p.kill()
        except Exception:
            pass

def hard_exit(exit_code: int = 0) -> None:
    """Emergency exit: kill our own children (if any) and exit immediately."""
    try:
        terminate_child_processes()
    finally:
        os._exit(int(exit_code))

# --- Scapy / libpcap ----------------------------------------------------------
try:
    from scapy.all import conf, sniff  # type: ignore
    from scapy.layers.inet import IP, TCP  # type: ignore

    try:
        from scapy.layers.l2 import Ether  # type: ignore
    except Exception:  # pragma: no cover
        Ether = None  # type: ignore

    # --- Scapy PCAP writers (optional) ---------------------------------------
    try:
        from scapy.utils import PcapWriter  # type: ignore
    except Exception:  # pragma: no cover
        PcapWriter = None  # type: ignore

    try:
        from scapy.utils import PcapNgWriter  # type: ignore
    except Exception:  # pragma: no cover
        PcapNgWriter = None  # type: ignore
except Exception as e:  # pragma: no cover
    raise SystemExit(
        "Missing scapy. Install with:\n"
        "  pip install scapy\n"
        f"Original error: {e!r}"
    ) from e


# =============================================================================
# Small utilities
# =============================================================================

def monotime() -> float:
    return time.monotonic()


def utc_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def clamp_int(v: Any, default: int, lo: int, hi: int) -> int:
    try:
        iv = int(v)
    except Exception:
        return default
    if iv < lo:
        return lo
    if iv > hi:
        return hi
    return iv


def json_line(obj: Any) -> bytes:
    return (json.dumps(obj, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def ensure_int(d: Dict[str, Any], key: str, default: int) -> int:
    v = d.get(key, default)
    try:
        return int(v)
    except Exception:
        return default


def get_path(d: Dict[str, Any], path: str, default: Any = None) -> Any:
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict):
            return default
        if part not in cur:
            return default
        cur = cur[part]
    return cur


def parse_level(s: Any, default: int) -> int:
    if not s:
        return default
    name = str(s).strip().upper()
    return getattr(logging, name, default)


# =============================================================================
# “json-ish” loader (unquoted keys, comments, trailing commas)
# =============================================================================

_KEY_RE = re.compile(r'(?m)(^|\s|[{,])([A-Za-z_][A-Za-z0-9_-]*)(\s*):')
_TRAILING_COMMA_RE = re.compile(r",(\s*[}\]])")
_LINE_COMMENT_RE = re.compile(r"(?m)^\s*(//|#).*$")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)


def _jsonish_to_json(text: str) -> str:
    text = _BLOCK_COMMENT_RE.sub("", text)
    text = _LINE_COMMENT_RE.sub("", text)

    def _repl(m: re.Match) -> str:
        prefix, key, suffix = m.group(1), m.group(2), m.group(3)
        return f'{prefix}"{key}"{suffix}:'

    text = _KEY_RE.sub(_repl, text)
    text = _TRAILING_COMMA_RE.sub(r"\1", text)
    return text


def load_config(path: str) -> Dict[str, Any]:
    raw = open(path, "r", encoding="utf-8").read()
    try:
        return json.loads(raw)
    except Exception:
        norm = _jsonish_to_json(raw)
        try:
            return json.loads(norm)
        except Exception as e:
            raise SystemExit(f"Config parse error for {path}:\n{e}\n\nNormalized text:\n{norm}") from e


# =============================================================================
# TCP reassembly (interval merge, overlap/retransmit safe)
# =============================================================================

MAX_OOO_SEGMENTS = 4096


@dataclass
class TCPReassembler:
    """
    Interval-merging TCP reassembler with overlap/retransmit handling.
    Conflict-safe: older bytes win; new overlapping bytes are ignored if different.
    """
    next_seq: Optional[int] = None
    segments: Dict[int, bytes] = field(default_factory=dict)
    emitted_bytes: int = 0

    retransmit_drop: int = 0
    retransmit_dup: int = 0
    overlap_trim: int = 0
    overlap_drop: int = 0
    overlap_conflict: int = 0
    ooo_buffer_evictions: int = 0

    def _recompute_next_seq_pre_emit(self) -> None:
        if self.emitted_bytes != 0 or not self.segments:
            return
        mn = min(self.segments.keys())
        if self.next_seq is None or mn < self.next_seq:
            self.next_seq = mn

    def _merge_union_conflict_safe(self, seq: int, data: bytes) -> None:
        union0 = seq
        union1 = seq + len(data)
        parts: List[Tuple[int, bytes, str]] = [(seq, data, "new")]

        changed = True
        while changed:
            changed = False
            for k, v in list(self.segments.items()):
                k0, k1 = k, k + len(v)
                if not (union1 < k0 or k1 < union0) and not (union1 == k0 or k1 == union0):
                    parts.append((k, v, "old"))
                    del self.segments[k]
                    union0 = min(union0, k0)
                    union1 = max(union1, k1)
                    changed = True
                elif union1 == k0 or k1 == union0:
                    parts.append((k, v, "old"))
                    del self.segments[k]
                    union0 = min(union0, k0)
                    union1 = max(union1, k1)
                    changed = True

        if len(parts) == 1:
            self.segments[seq] = data
            return

        buf = bytearray(union1 - union0)
        filled = bytearray(union1 - union0)

        parts_sorted = sorted(parts, key=lambda x: 0 if x[2] == "old" else 1)  # old first
        conflict = 0
        for p0, pv, tag in parts_sorted:
            off = p0 - union0
            for i, b in enumerate(pv):
                idx = off + i
                if filled[idx]:
                    if tag == "new" and buf[idx] != b:
                        conflict += 1
                    continue
                buf[idx] = b
                filled[idx] = 1

        if conflict:
            self.overlap_conflict += conflict

        self.segments[union0] = bytes(buf)

    def add(self, seq: int, data: bytes) -> None:
        if not data:
            return

        if self.next_seq is None:
            self.next_seq = seq

        if self.emitted_bytes > 0 and self.next_seq is not None:
            if (seq + len(data)) <= self.next_seq:
                self.retransmit_drop += 1
                return

            if seq < self.next_seq:
                overlap = self.next_seq - seq
                if overlap >= len(data):
                    self.overlap_drop += 1
                    return
                self.overlap_trim += 1
                data = data[overlap:]
                seq = self.next_seq

        prev = self.segments.get(seq)
        if prev is not None:
            if prev == data:
                self.retransmit_dup += 1
                return
            if len(prev) >= len(data) and prev.startswith(data):
                self.retransmit_dup += 1
                return

        self._merge_union_conflict_safe(seq, data)

        if len(self.segments) > MAX_OOO_SEGMENTS:
            for k in sorted(self.segments.keys(), reverse=True)[: len(self.segments) - MAX_OOO_SEGMENTS]:
                del self.segments[k]
                self.ooo_buffer_evictions += 1

        self._recompute_next_seq_pre_emit()

    def pop_contiguous(self) -> bytes:
        if not self.segments:
            return b""
        if self.next_seq is None:
            self.next_seq = min(self.segments.keys())
        if self.emitted_bytes == 0:
            self._recompute_next_seq_pre_emit()

        out = bytearray()
        while self.next_seq in self.segments:
            chunk = self.segments.pop(self.next_seq)
            out += chunk
            self.next_seq += len(chunk)
            self.emitted_bytes += len(chunk)
        return bytes(out)


# =============================================================================
# Session model
# =============================================================================

@dataclass(frozen=True)
class FlowKey:
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int

    @property
    def session_id(self) -> int:
        return self.local_port

    def to_dict(self) -> Dict[str, Any]:
        return {
            "local_ip": self.local_ip,
            "local_port": self.local_port,
            "remote_ip": self.remote_ip,
            "remote_port": self.remote_port,
            "session_id": self.session_id,
        }


@dataclass
class PacketInfo:
    ts: float
    flow: FlowKey
    from_local: bool
    seq: int
    ack: int
    flags: int
    win: int
    payload: bytes
    mss_opt: Optional[int] = None
    wscale_opt: Optional[int] = None
    sack_ok: Optional[bool] = None


@dataclass
class DirState:
    reasm: TCPReassembler = field(default_factory=TCPReassembler)
    last_ts: float = field(default_factory=monotime)

    pkts: int = 0
    bytes_payload: int = 0
    max_payload: int = 0

    last_ack: Optional[int] = None
    last_ack_ts: float = field(default_factory=monotime)

    # restored metrics
    max_rwnd_bytes: int = 0
    wscale: Optional[int] = None
    highest_seq_sent: int = 0
    max_inflight_est: int = 0

    _last_reasm_snapshot: Tuple[int, int, int, int, int, int] = (0, 0, 0, 0, 0, 0)

    def note_packet(self, p: PacketInfo) -> None:
        self.last_ts = p.ts
        self.pkts += 1
        plen = len(p.payload)
        self.bytes_payload += plen
        if plen > self.max_payload:
            self.max_payload = plen

        if p.ack:
            if self.last_ack is None or p.ack > self.last_ack:
                self.last_ack = p.ack
                self.last_ack_ts = p.ts

        if p.wscale_opt is not None:
            self.wscale = p.wscale_opt

        # advertised receive window scaled
        scale = self.wscale or 0
        rwnd = int(p.win) << int(scale)
        if rwnd > self.max_rwnd_bytes:
            self.max_rwnd_bytes = rwnd

    def reasm_deltas(self) -> Dict[str, int]:
        r = self.reasm
        snap = (
            r.retransmit_drop,
            r.retransmit_dup,
            r.overlap_trim,
            r.overlap_drop,
            r.overlap_conflict,
            r.ooo_buffer_evictions,
        )
        prev = self._last_reasm_snapshot
        self._last_reasm_snapshot = snap
        keys = ["retransmit_drop", "retransmit_dup", "overlap_trim", "overlap_drop", "overlap_conflict", "ooo_evictions"]
        out: Dict[str, int] = {}
        for k, a, b in zip(keys, snap, prev):
            if a != b:
                out[k] = a - b
        return out


@dataclass
class SessionState:
    flow: FlowKey
    created_ts: float
    last_ts: float
    c2s: DirState = field(default_factory=DirState)
    s2c: DirState = field(default_factory=DirState)
    closed: bool = False
    close_reason: Optional[str] = None

    def touch(self, ts: float) -> None:
        self.last_ts = ts


# =============================================================================
# Worker -> asyncio queues
# =============================================================================

@dataclass
class SessionEvent:
    kind: str  # open|close|note
    flow: FlowKey
    ts: float
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ForwardChunk:
    flow: FlowKey
    ts: float
    direction: str  # c2s|s2c
    data: bytes


# =============================================================================
# Control plane
# =============================================================================

class ControlPlane:
    def __init__(self, *, bind_ip: str, port: int, log: logging.Logger, default_cats: Set[str]) -> None:
        self.bind_ip = bind_ip
        self.port = port
        self.log = log
        self._server: Optional[asyncio.base_events.Server] = None

        self._client_lock = asyncio.Lock()
        self._client_writer: Optional[asyncio.StreamWriter] = None
        self._client_task: Optional[asyncio.Task] = None

        self._events: "asyncio.Queue[Dict[str, Any]]" = asyncio.Queue(maxsize=10000)

        self.bytes_out = 0
        self.events_dropped = 0

        self._default_cats = set(default_cats)
        self._cats = set(default_cats)

        self._flow_global = False
        self._flow_sessions: Set[int] = set()

        self._get_stats_cb = None  # type: ignore
        self._list_sessions_cb = None  # type: ignore
        self._get_session_cb = None  # type: ignore
        self._close_session_cb = None  # type: ignore

    def set_callbacks(self, *, get_stats, list_sessions, get_session, close_session) -> None:
        self._get_stats_cb = get_stats
        self._list_sessions_cb = list_sessions
        self._get_session_cb = get_session
        self._close_session_cb = close_session

    def cp_enabled(self) -> bool:
        w = self._client_writer
        return bool(w and w.transport and not w.transport.is_closing())

    def cats(self) -> Set[str]:
        return set(self._cats)

    def reset_subscribe(self) -> None:
        self._cats = set(self._default_cats)

    def subscribe(self, cats: List[str]) -> None:
        self._cats = {str(x).strip() for x in cats if str(x).strip()}

    def flow_enabled_for(self, session_id: Optional[int]) -> bool:
        if self._flow_global:
            return True
        if session_id is None:
            return False
        return session_id in self._flow_sessions

    def set_flow(self, *, enable: bool, session_id: Optional[int]) -> None:
        if session_id is None:
            self._flow_global = enable
            if not enable:
                self._flow_sessions.clear()
            return
        if enable:
            self._flow_sessions.add(session_id)
        else:
            self._flow_sessions.discard(session_id)

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle_client, host=self.bind_ip, port=self.port)
        self.log.info("control plane listening on %s:%d", self.bind_ip, self.port)
        asyncio.create_task(self._event_pump(), name="cp.event_pump")

    async def close(self) -> None:
        if self._server:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass

        async with self._client_lock:
            if self._client_writer:
                try:
                    self._client_writer.close()
                except Exception:
                    pass
                self._client_writer = None
            if self._client_task:
                self._client_task.cancel()

    async def emit_raw(self, ev: Dict[str, Any]) -> None:
        try:
            self._events.put_nowait(ev)
        except asyncio.QueueFull:
            self.events_dropped += 1

    async def _event_pump(self) -> None:
        while True:
            ev = await self._events.get()
            async with self._client_lock:
                w = self._client_writer
                if not w or not w.transport or w.transport.is_closing():
                    continue
                try:
                    line = json_line(ev)
                    w.write(line)
                    self.bytes_out += len(line)
                except Exception:
                    try:
                        w.close()
                    except Exception:
                        pass
                    self._client_writer = None

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        async with self._client_lock:
            if self._client_writer and self._client_writer.transport and not self._client_writer.transport.is_closing():
                try:
                    self._client_writer.close()
                except Exception:
                    pass
            self._client_writer = writer

        await self.emit_raw({"ts": utc_iso(), "cat": "control", "event": "control_connected", "peer": str(peer)})

        async def _cmd_loop() -> None:
            while True:
                line = await reader.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    cmd = json.loads(line.decode("utf-8"))
                except Exception:
                    await self.emit_raw({"ts": utc_iso(), "cat": "control", "event": "control_error", "error": "bad_json"})
                    continue
                await self._handle_cmd(cmd)

        self._client_task = asyncio.create_task(_cmd_loop(), name="cp.cmd_loop")
        try:
            await self._client_task
        except asyncio.CancelledError:
            pass
        finally:
            async with self._client_lock:
                if self._client_writer is writer:
                    self._client_writer = None
            try:
                writer.close()
            except Exception:
                pass
            await self.emit_raw({"ts": utc_iso(), "cat": "control", "event": "control_disconnected", "peer": str(peer)})

    async def _reply(self, reply_to: str, payload: Dict[str, Any]) -> None:
        ev = {"ts": utc_iso(), "cat": "control", "event": "control_reply", "reply_to": reply_to, **payload}
        await self.emit_raw(ev)

    async def _handle_cmd(self, cmd: Dict[str, Any]) -> None:
        c = str(cmd.get("cmd", "")).lower().strip()

        if c in ("ping", "hello"):
            await self._reply(c, {"ok": True})
            return

        if c in ("stats", "get_stats"):
            s = self._get_stats_cb() if self._get_stats_cb else {}
            await self._reply(c, {"ok": True, "stats": s})
            return

        if c == "subscribe":
            cats = cmd.get("cats", [])
            if not isinstance(cats, list):
                await self._reply(c, {"ok": False, "error": "cats must be list"})
                return
            self.subscribe([str(x) for x in cats])
            await self._reply(c, {"ok": True, "cats": sorted(self._cats)})
            return

        if c == "subscribe_default":
            self.reset_subscribe()
            await self._reply(c, {"ok": True, "cats": sorted(self._cats)})
            return

        if c in ("tcp_flow_enable", "tcp_flow_disable"):
            enable = (c == "tcp_flow_enable")
            sid = cmd.get("session_id", None)
            session_id = int(sid) if sid is not None else None
            self.set_flow(enable=enable, session_id=session_id)
            await self._reply(c, {"ok": True, "flow_global": self._flow_global, "flow_sessions": sorted(self._flow_sessions)})
            return

        if c == "list_sessions":
            lst = self._list_sessions_cb() if self._list_sessions_cb else []
            await self._reply(c, {"ok": True, "sessions": lst})
            return

        if c == "get_session":
            sid = cmd.get("session_id", None)
            if sid is None:
                await self._reply(c, {"ok": False, "error": "missing_session_id"})
                return
            s = self._get_session_cb(int(sid)) if self._get_session_cb else None
            if not s:
                await self._reply(c, {"ok": False, "error": "not_found"})
                return
            await self._reply(c, {"ok": True, "session": s})
            return

        if c in ("close_session", "close"):
            sid = cmd.get("session_id", None)
            if sid is None:
                await self._reply(c, {"ok": False, "error": "missing_session_id"})
                return
            ok = await self._close_session_cb(int(sid), reason="control_close") if self._close_session_cb else False
            await self._reply(c, {"ok": bool(ok), "session_id": int(sid)})
            return

        await self._reply(c, {"ok": False, "error": "unknown_cmd"})


# =============================================================================
# Event router: local logs vs CP, with cp flag
# =============================================================================

class EventRouter:
    """
    Local logs: always (subject to handler levels).
    CP: only when cp=True, category subscribed, and flow gating passes.
    """
    def __init__(self, *, log: logging.Logger, cp: ControlPlane) -> None:
        self.log = log
        self.cp = cp

    def _log(self, level: str, msg: str, extra: Dict[str, Any]) -> None:
        if level == "debug":
            self.log.debug("%s %s", msg, extra)
        elif level == "warning":
            self.log.warning("%s %s", msg, extra)
        elif level == "error":
            self.log.error("%s %s", msg, extra)
        else:
            self.log.info("%s %s", msg, extra)

    async def emit(self, *, cat: str, event: str, level: str, payload: Dict[str, Any], cp: bool = True) -> None:
        self._log(level, f"{cat}.{event}", payload)

        if not cp:
            return
        if not self.cp.cp_enabled():
            return

        session_id = None
        flow = payload.get("flow")
        if isinstance(flow, dict):
            try:
                session_id = int(flow.get("session_id")) if flow.get("session_id") is not None else None
            except Exception:
                session_id = None

        if cat == "flow" and not self.cp.flow_enabled_for(session_id):
            return

        if cat not in self.cp.cats():
            return

        out = {"ts": utc_iso(), "cat": cat, "event": event, **payload}
        await self.cp.emit_raw(out)


# =============================================================================
# Reassembly worker threads
# =============================================================================

class ReassemblyWorker(threading.Thread):
    daemon = True

    def __init__(
        self,
        *,
        wid: int,
        inq: "queue.Queue[PacketInfo]",
        loop: asyncio.AbstractEventLoop,
        outq: "asyncio.Queue[ForwardChunk]",
        evq: "asyncio.Queue[SessionEvent]",
        session_idle_sec: float,
        ack_stall_sec: Optional[float],
    ) -> None:
        super().__init__(name=f"reasm-{wid}")
        self.wid = wid
        self.inq = inq
        self.loop = loop
        self.outq = outq
        self.evq = evq
        self.session_idle_sec = session_idle_sec
        self.ack_stall_sec = ack_stall_sec
        self._stop = threading.Event()
        self.sessions: Dict[FlowKey, SessionState] = {}
        self._last_gc = monotime()

    def stop(self) -> None:
        self._stop.set()

    def _emit_event(self, ev: SessionEvent) -> None:
        self.loop.call_soon_threadsafe(self.evq.put_nowait, ev)

    def _emit_chunk(self, ch: ForwardChunk) -> None:
        self.loop.call_soon_threadsafe(self.outq.put_nowait, ch)

    def _session_open(self, flow: FlowKey, ts: float) -> SessionState:
        st = SessionState(flow=flow, created_ts=ts, last_ts=ts)
        self.sessions[flow] = st
        self._emit_event(SessionEvent(kind="open", flow=flow, ts=ts, data={}))
        return st

    def _session_close(self, st: SessionState, ts: float, reason: str) -> None:
        if st.closed:
            return
        st.closed = True
        st.close_reason = reason
        self._emit_event(SessionEvent(kind="close", flow=st.flow, ts=ts, data={"reason": reason}))
        self.sessions.pop(st.flow, None)

    def _gc(self, now: float) -> None:
        if now - self._last_gc < 1.0:
            return
        self._last_gc = now
        idle = self.session_idle_sec
        for st in list(self.sessions.values()):
            if now - st.last_ts > idle:
                self._session_close(st, now, f"idle_timeout_{idle:.0f}s")
            elif self.ack_stall_sec:
                stall = self.ack_stall_sec
                if st.c2s.last_ack is not None and (now - st.c2s.last_ack_ts) > stall:
                    self._emit_event(SessionEvent(
                        kind="note", flow=st.flow, ts=now,
                        data={"note": "ack_stall", "direction": "c2s", "stall_sec": stall, "last_ack": st.c2s.last_ack}
                    ))
                    st.c2s.last_ack_ts = now
                if st.s2c.last_ack is not None and (now - st.s2c.last_ack_ts) > stall:
                    self._emit_event(SessionEvent(
                        kind="note", flow=st.flow, ts=now,
                        data={"note": "ack_stall", "direction": "s2c", "stall_sec": stall, "last_ack": st.s2c.last_ack}
                    ))
                    st.s2c.last_ack_ts = now

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                p = self.inq.get(timeout=0.25)
            except queue.Empty:
                self._gc(monotime())
                continue

            ts = p.ts
            st = self.sessions.get(p.flow)
            if st is None:
                st = self._session_open(p.flow, ts)

            st.touch(ts)

            if p.flags & 0x04:  # RST
                self._session_close(st, ts, "rst")
                continue
            if p.flags & 0x01:  # FIN
                self._session_close(st, ts, "fin")
                continue

            dir_state = st.c2s if p.from_local else st.s2c
            dir_state.note_packet(p)

            # restored: highest seq sent + inflight estimate from peer ACK
            if p.payload:
                end_seq = p.seq + len(p.payload)
                if end_seq > dir_state.highest_seq_sent:
                    dir_state.highest_seq_sent = end_seq

            if p.from_local:
                peer = st.s2c
                if p.ack and peer.highest_seq_sent:
                    inflight = max(0, peer.highest_seq_sent - p.ack)
                    if inflight > peer.max_inflight_est:
                        peer.max_inflight_est = inflight
            else:
                peer = st.c2s
                if p.ack and peer.highest_seq_sent:
                    inflight = max(0, peer.highest_seq_sent - p.ack)
                    if inflight > peer.max_inflight_est:
                        peer.max_inflight_est = inflight

            if p.payload:
                dir_state.reasm.add(p.seq, p.payload)
                deltas = dir_state.reasm_deltas()
                if deltas:
                    self._emit_event(SessionEvent(
                        kind="note",
                        flow=st.flow,
                        ts=ts,
                        data={"note": "tcp_reassembly", "direction": ("c2s" if p.from_local else "s2c"), "deltas": deltas},
                    ))

                out = dir_state.reasm.pop_contiguous()
                if out:
                    self._emit_chunk(ForwardChunk(
                        flow=p.flow,
                        ts=ts,
                        direction=("c2s" if p.from_local else "s2c"),
                        data=out,
                    ))

            self._gc(monotime())


# =============================================================================
# Packet capture thread (timed sniff loop => clean stop)
# =============================================================================

def _parse_tcp_opts(tcp) -> Tuple[Optional[int], Optional[int], Optional[bool]]:
    mss = None
    wscale = None
    sack_ok = None
    try:
        opts = getattr(tcp, "options", None) or []
        for k, v in opts:
            if k == "MSS":
                try:
                    mss = int(v)
                except Exception:
                    pass
            elif k == "WScale":
                try:
                    wscale = int(v)
                except Exception:
                    pass
            elif k == "SAckOK":
                sack_ok = True
    except Exception:
        pass
    return mss, wscale, sack_ok


class CaptureThread(threading.Thread):
    daemon = True

    def __init__(
        self,
        *,
        iface: str,
        bpf: str,
        local_ip: str,
        remote_ip: str,
        q_by_worker: List["queue.Queue[PacketInfo]"],
        log: logging.Logger,
        pcap_sink: Optional["PcapSink"] = None,
    ) -> None:
        super().__init__(name="pcap")
        self.iface = iface
        self.bpf = bpf
        self.local_ip = local_ip
        self.remote_ip = remote_ip
        self.q_by_worker = q_by_worker
        self.log = log
        self.pcap_sink = pcap_sink
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def _dispatch(self, p: PacketInfo) -> None:
        sid = p.flow.session_id
        idx = sid % len(self.q_by_worker) if self.q_by_worker else 0
        try:
            self.q_by_worker[idx].put_nowait(p)
        except queue.Full:
            return

    def run(self) -> None:
        self.log.info("capture starting iface=%s bpf=%s", self.iface, self.bpf)

        def _cb(pkt) -> None:
            try:
                ip = pkt.getlayer(IP)
                tcp = pkt.getlayer(TCP)
                if ip is None or tcp is None:
                    return

                src = str(ip.src)
                dst = str(ip.dst)

                if src == self.local_ip and dst == self.remote_ip:
                    local_port = int(tcp.sport)
                    remote_port = int(tcp.dport)
                    from_local = True
                elif src == self.remote_ip and dst == self.local_ip:
                    local_port = int(tcp.dport)
                    remote_port = int(tcp.sport)
                    from_local = False
                else:
                    return

                flow = FlowKey(self.local_ip, local_port, self.remote_ip, remote_port)
                payload = bytes(tcp.payload) if tcp.payload else b""
                if self.pcap_sink is not None:
                    try:
                        self.pcap_sink.enqueue(pkt, flow=flow, ts_epoch=float(getattr(pkt, 'time', time.time())))
                    except Exception:
                        pass
                mss, wscale, sack_ok = _parse_tcp_opts(tcp)

                pi = PacketInfo(
                    ts=monotime(),
                    flow=flow,
                    from_local=from_local,
                    seq=int(tcp.seq),
                    ack=int(tcp.ack),
                    flags=int(tcp.flags),
                    win=int(tcp.window),
                    payload=payload,
                    mss_opt=mss,
                    wscale_opt=wscale,
                    sack_ok=sack_ok,
                )
                self._dispatch(pi)
            except Exception:
                return

        try:
            while not self._stop.is_set():
                sniff(
                    iface=self.iface,
                    filter=self.bpf,
                    prn=_cb,
                    store=False,
                    timeout=1,  # crucial for clean shutdown
                )
        finally:
            self.log.info("capture stopped")


# =============================================================================
# Output plumbing
# =============================================================================

@dataclass
class TargetWriter:
    name: str
    writer: asyncio.StreamWriter
    kind: str  # listener|connector

    def is_closing(self) -> bool:
        tr = self.writer.transport
        return tr.is_closing() if tr else True

    def buffer_size(self) -> int:
        tr = self.writer.transport
        return tr.get_write_buffer_size() if tr else 0


@dataclass
class ConnectorState:
    ever_connected: bool = False
    currently_connected: bool = False


@dataclass
class SessionOutputs:
    flow: FlowKey
    listener_ports: Optional[Tuple[int, int]] = None
    listeners: Dict[str, Optional[TargetWriter]] = field(default_factory=lambda: {"requests": None, "responses": None})
    connectors: Dict[str, Optional[TargetWriter]] = field(default_factory=lambda: {"requests": None, "responses": None})
    connector_state: Dict[str, ConnectorState] = field(default_factory=lambda: {"requests": ConnectorState(), "responses": ConnectorState()})
    servers: List[asyncio.base_events.Server] = field(default_factory=list)
    tasks: List[asyncio.Task] = field(default_factory=list)

    def all_targets_for(self, stream: str) -> List[TargetWriter]:
        out: List[TargetWriter] = []
        lw = self.listeners.get(stream)
        if lw is not None:
            out.append(lw)
        cw = self.connectors.get(stream)
        if cw is not None:
            out.append(cw)
        return out

# =============================================================================
# PCAP / PCAPNG sink (raw packet recording)
# =============================================================================

class PcapSink:
    """Non-blocking PCAP/PCAPNG writer.

    - Receives raw captured scapy packets via enqueue()
    - Writes to a single file or per-session files
    - Never blocks the capture thread: if the queue is full, packets are dropped.
    """

    def __init__(
        self,
        *,
        enabled: bool,
        out_dir: str,
        fmt: str,
        per_session: bool,
        queue_size: int,
        sync: bool = False,
        local_ip: str,
        remote_ip: str,
        remote_port: int,
        idle_close_sec: float,
        close_on_fin: bool = True,
        fin_close_grace_sec: float = 1.0,
        log: logging.Logger,
        linktype: Optional[Any] = None,
        pcap_sink: Optional['PcapSink'] = None,
    ) -> None:
        self.enabled = bool(enabled)
        self.out_dir = str(out_dir or "").strip()
        self.fmt = (fmt or "").strip().lower()
        if self.fmt in ("pcap-ng", "pcapng", "ng"):
            self.fmt = "pcapng"
        elif self.fmt in ("pcap", ""):
            self.fmt = "pcap"
        else:
            # Unknown => default
            self.fmt = "pcapng"

        self.per_session = bool(per_session)
        self.sync = bool(sync)
        self.queue_size = clamp_int(queue_size, default=20000, lo=1000, hi=5_000_000)

        self.local_ip = local_ip
        self.remote_ip = remote_ip
        self.remote_port = int(remote_port or 0)

        self.idle_close_sec = float(idle_close_sec or 0.0)

        self.close_on_fin = bool(close_on_fin) if self.per_session else False
        self.fin_close_grace_sec = float(fin_close_grace_sec or 0.0)

        # Optional: force pcap linktype (DLT) to avoid wrong decoding in tools like Zeek.
        # Accepts int DLT number or strings: ethernet|en10mb|raw|ip|null|loopback|linux_sll|sll
        self._force_linktype: Optional[int] = None
        if linktype is not None:
            try:
                if isinstance(linktype, int):
                    self._force_linktype = int(linktype)
                else:
                    s = str(linktype).strip().lower()
                    _map = {
                        "ether": 1, "ethernet": 1, "en10mb": 1, "dlt_en10mb": 1,
                        "raw": 12, "ip": 12, "dlt_raw": 12,
                        "null": 0, "loop": 0, "loopback": 0, "dlt_null": 0,
                        "linux_sll": 113, "sll": 113, "dlt_linux_sll": 113,
                    }
                    if s in _map:
                        self._force_linktype = int(_map[s])
                    elif s.isdigit():
                        self._force_linktype = int(s)
            except Exception:
                self._force_linktype = None
        self.log = log

        self._q: "queue.Queue[Tuple[float, FlowKey, Any]]" = queue.Queue(maxsize=self.queue_size)
        self._stop = threading.Event()
        self._thr = threading.Thread(target=self._run, name="pcap.sink", daemon=True)

        # Stats
        self._pkts_written = 0
        self._bytes_written = 0
        self._pkts_dropped = 0
        self._pkts_failed = 0
        self._files_opened = 0
        self._files_closed = 0

        # Writers keyed by flow or global
        self._writers: Dict[Any, Dict[str, Any]] = {}

        # Determine writer class
        self._writer_kind = "pcap"
        self._writer_cls = PcapWriter
        if self.fmt == "pcapng" and PcapNgWriter is not None:
            self._writer_kind = "pcapng"
            self._writer_cls = PcapNgWriter
        elif self.fmt == "pcapng" and PcapNgWriter is None:
            self._writer_kind = "pcap"
            self._writer_cls = PcapWriter
            self.log.warning("pcapng requested but scapy PcapNgWriter not available; falling back to pcap")

        if self._writer_cls is None:
            self.enabled = False
            self.log.warning("pcap output disabled: scapy PcapWriter/PcapNgWriter not available")

    @staticmethod
    def from_cfg(cfg: Dict[str, Any], *, local_ip: str, remote_ip: str, remote_port: int, idle_close_sec: float, log: logging.Logger) -> "PcapSink":
        pc = get_path(cfg, "io.output.pcap", None)
        if not isinstance(pc, dict):
            return PcapSink(enabled=False, out_dir="", fmt="pcap", per_session=False, queue_size=1,
                            local_ip=local_ip, remote_ip=remote_ip, remote_port=remote_port,
                            idle_close_sec=idle_close_sec, log=log)

        enabled = bool(pc.get("enabled", False))
        out_dir = pc.get("dir", None) or pc.get("path", None) or ""
        fmt = pc.get("format", "pcapng")
        per_session = bool(pc.get("per_session", True))
        queue_size = pc.get("queue_size", 20000)
        sync = bool(pc.get("sync", False))
        close_on_fin = bool(pc.get("close_on_fin", True))
        fin_grace = pc.get("fin_close_grace_sec", 1.0)
        idle = pc.get("idle_close_sec", None)
        if idle is None:
            idle = idle_close_sec

        return PcapSink(
            enabled=enabled,
            out_dir=str(out_dir),
            fmt=str(fmt),
            per_session=per_session,
            queue_size=int(queue_size or 20000),
            sync=sync,
            local_ip=local_ip,
            remote_ip=remote_ip,
            remote_port=remote_port,
            idle_close_sec=float(idle or 0.0),
            linktype=pc.get("linktype", pc.get("dlt", None)),
            log=log,
        )

    def start(self) -> None:
        if not self.enabled:
            return
        if not self.out_dir:
            self.enabled = False
            self.log.warning("pcap output disabled: missing dir/path")
            return
        try:
            os.makedirs(self.out_dir, exist_ok=True)
        except Exception as e:
            self.enabled = False
            self.log.warning("pcap output disabled: cannot create dir=%s err=%r", self.out_dir, e)
            return

        self.log.info("pcap output enabled format=%s per_session=%s dir=%s queue=%d",
                      self._writer_kind, self.per_session, self.out_dir, self.queue_size)
        self._thr.start()

    def stop(self) -> None:
        if not self.enabled:
            return
        self._stop.set()

    def join(self, timeout: float = 2.0) -> None:
        if not self.enabled:
            return
        self._thr.join(timeout=timeout)

    def enqueue(self, pkt: Any, *, flow: FlowKey, ts_epoch: float) -> None:
        if not self.enabled:
            return
        try:
            self._q.put_nowait((float(ts_epoch), flow, pkt))
        except queue.Full:
            self._pkts_dropped += 1
    def drop_detail_snapshot(self, top_n: int = 8) -> Dict[str, Any]:
        # Aggregate drops across sessions/streams/reasons, keeping output small.
        if not self._drop_count:
            return {"by_reason": {}, "by_stream": {}}

        by_reason_cnt: Dict[str, int] = defaultdict(int)
        by_reason_bytes: Dict[str, int] = defaultdict(int)
        by_stream_cnt: Dict[str, int] = defaultdict(int)
        by_stream_bytes: Dict[str, int] = defaultdict(int)

        for (sid, stream, reason), cnt in self._drop_count.items():
            by_reason_cnt[reason] += int(cnt)
            by_reason_bytes[reason] += int(self._drop_bytes.get((sid, stream, reason), 0))
            by_stream_cnt[stream] += int(cnt)
            by_stream_bytes[stream] += int(self._drop_bytes.get((sid, stream, reason), 0))

        # Top reasons by bytes
        top = sorted(by_reason_bytes.items(), key=lambda kv: kv[1], reverse=True)[: max(1, int(top_n))]

        by_reason = {}
        for reason, b in top:
            by_reason[reason] = {"chunks": by_reason_cnt.get(reason, 0), "bytes": b}

        by_stream = {}
        for stream, b in sorted(by_stream_bytes.items(), key=lambda kv: kv[1], reverse=True):
            by_stream[stream] = {"chunks": by_stream_cnt.get(stream, 0), "bytes": b}

        return {"by_reason": by_reason, "by_stream": by_stream}


    def stats_snapshot(self) -> Dict[str, Any]:
        return {
            "enabled": bool(self.enabled),
            "format": self._writer_kind if self.enabled else None,
            "per_session": bool(self.per_session) if self.enabled else None,
            "dir": self.out_dir if self.enabled else None,
            "pkts_written": self._pkts_written,
            "bytes_written": self._bytes_written,
            "pkts_dropped": self._pkts_dropped,
            "pkts_failed": self._pkts_failed,
            "files_opened": self._files_opened,
            "files_closed": self._files_closed,
        }

    # ---- internals -----------------------------------------------------------

    
    def _pick_linktype(self, pkt: Any) -> int:
        """Best-effort linktype detection for pcap header.

        Zeek/Zui (and tshark) need the pcap header's linktype (DLT_*) to match the bytes written.
        On macOS, captures on utun/lo can be RAW IP or NULL/LOOP, while en* is usually Ethernet.

        Common libpcap DLT values:
          1   = EN10MB (Ethernet)
          12  = RAW (raw IP)
          0   = NULL/LOOP (BSD loopback)
          113 = LINUX_SLL (Linux cooked capture v1)
        """
        try:
            b = bytes(pkt)
        except Exception:
            b = b""  # type: ignore[assignment]

        # 1) BSD NULL/LOOP: 4-byte address family, then IP.
        # AF_INET=2, AF_INET6 is commonly 24 or 30 depending on platform.
        if len(b) >= 8:
            if b[:4] in (b"\x02\x00\x00\x00", b"\x00\x00\x00\x02",
                         b"\x18\x00\x00\x00", b"\x00\x00\x00\x18",
                         b"\x1e\x00\x00\x00", b"\x00\x00\x00\x1e"):
                ver = b[4] >> 4
                if ver in (4, 6):
                    return 0

        # 2) RAW IP: first nibble is version (4 or 6)
        if len(b) >= 1:
            ver = b[0] >> 4
            if ver in (4, 6):
                return 12

        # 3) Ethernet: Ethertype at bytes 12..14 (or VLAN tagged)
        if len(b) >= 14:
            et = b[12:14]
            # VLAN tag (0x8100 or 0x88a8): actual ethertype at 16..18
            if et in (b"\x81\x00", b"\x88\xa8") and len(b) >= 18:
                et2 = b[16:18]
                if et2 in (b"\x08\x00", b"\x86\xdd"):
                    return 1
                return 1
            if et in (b"\x08\x00", b"\x86\xdd", b"\x81\x00", b"\x88\xa8"):
                return 1

        # 4) Linux cooked capture v1 (SLL): protocol/ethertype at 14..16
        if len(b) >= 16:
            proto = b[14:16]
            if proto in (b"\x08\x00", b"\x86\xdd"):
                # Packet type field is first 2 bytes, usually 0..4
                if b[0] == 0 and b[1] in (0, 1, 2, 3, 4):
                    return 113

        # 5) Fall back to scapy's top-level class when available
        top = getattr(pkt, "__class__", type("x", (), {})).__name__
        if top == "Ether":
            return 1
        if top in ("CookedLinux", "LinuxCooked", "SLL", "SLL2"):
            return 113
        if top in ("Null", "Loopback"):
            return 0
        return 1


    def _flow_file_base(self, flow: FlowKey) -> str:
        def _clean(s: str) -> str:
            return s.replace(":", "_")
        return f"{_clean(flow.local_ip)}_{flow.local_port}__{_clean(flow.remote_ip)}_{flow.remote_port}"

    def _open_writer(self, key: Any, flow: FlowKey, pkt: Any, ts_epoch: float) -> Optional[Dict[str, Any]]:
        ext = "pcapng" if self._writer_kind == "pcapng" else "pcap"
        base = self._flow_file_base(flow) if self.per_session else "capture"
        start_ms = int(ts_epoch * 1000.0)
        fname = f"{base}__{start_ms}__open.{ext}"
        path = os.path.join(self.out_dir, fname)

        linktype = self._force_linktype if getattr(self, '_force_linktype', None) is not None else self._pick_linktype(pkt)

        try:
            # scapy writers have some version variance; keep it simple.
            cls = self._writer_cls
            if cls is None:
                return None

            # Prefer append=False: create new file
            try:
                w = cls(path, append=False, sync=self.sync, linktype=linktype)  # type: ignore[arg-type]
            except TypeError:
                try:
                    w = cls(path, append=False, sync=self.sync)  # type: ignore[arg-type]
                    try:
                        setattr(w, "linktype", linktype)
                    except Exception:
                        pass
                except TypeError:
                    w = cls(path)  # type: ignore[call-arg]

            self._files_opened += 1
            return {
                "writer": w,
                "path": path,
                "base": base,
                "start_ms": start_ms,
                "last_ts": ts_epoch,
                "linktype": linktype,
                "flow": flow,
            }
        except Exception as e:
            self._pkts_failed += 1
            self.log.warning("pcap open failed path=%s err=%r", path, e)
            return None

    def _close_writer(self, key: Any, meta: Dict[str, Any], *, reason: str, ts_epoch: float) -> None:
        try:
            w = meta.get("writer", None)
            if w is not None:
                try:
                    w.flush()
                except Exception:
                    pass
                try:
                    w.close()
                except Exception:
                    pass
        finally:
            self._files_closed += 1

        # Rename open -> closed with end timestamp + reason
        try:
            ext = "pcapng" if self._writer_kind == "pcapng" else "pcap"
            end_ms = int(ts_epoch * 1000.0)
            base = meta.get("base", "capture")
            start_ms = meta.get("start_ms", 0)
            old = meta.get("path", "")
            new = os.path.join(self.out_dir, f"{base}__{start_ms}__{end_ms}__{reason}.{ext}")
            if old and old != new and os.path.exists(old):
                os.replace(old, new)
        except Exception:
            pass

    def _write_one(self, meta: Dict[str, Any], pkt: Any, ts_epoch: float) -> bool:
        w = meta.get("writer", None)
        if w is None:
            return False

        # Ensure epoch timestamp is used
        try:
            pkt.time = float(ts_epoch)
        except Exception:
            pass

        try:
            w.write(pkt)
            b = bytes(pkt)
            self._pkts_written += 1
            self._bytes_written += len(b)

            # Optional early close handling (FIN/RST) for per-session files.
            if self.close_on_fin and self.per_session:
                try:
                    if pkt is not None and pkt.haslayer(TCP):  # type: ignore[attr-defined]
                        flags = int(pkt[TCP].flags)  # type: ignore[index]
                        # RST closes immediately
                        if flags & 0x04:
                            meta["close_now"] = ("rst", float(ts_epoch))
                        # FIN closes after both sides seen (with small grace)
                        if flags & 0x01:
                            src = None
                            try:
                                if pkt.haslayer(IP):  # type: ignore[attr-defined]
                                    src = str(pkt[IP].src)  # type: ignore[index]
                            except Exception:
                                src = None
                            if src == self.local_ip:
                                meta["fin_local"] = True
                            else:
                                meta["fin_remote"] = True
                            if meta.get("fin_local") and meta.get("fin_remote"):
                                meta["close_reason"] = "fin"
                                meta["close_after"] = float(ts_epoch) + max(0.0, float(self.fin_close_grace_sec))
                except Exception:
                    # Never let close-detection break writing
                    pass
            meta["last_ts"] = ts_epoch
            return True
        except Exception as e:
            self._pkts_failed += 1
            # Throttle: warn at most every ~5s per file
            last_warn = meta.get("_last_warn", 0.0)
            if ts_epoch - float(last_warn) >= 5.0:
                meta["_last_warn"] = ts_epoch
                self.log.warning("pcap write failed path=%s err=%r", meta.get("path", ""), e)
            return False

    def _run(self) -> None:
        # Opportunistic cleanup cadence
        next_gc = time.time() + 1.0

        while not self._stop.is_set():
            now = time.time()
            try:
                ts_epoch, flow, pkt = self._q.get(timeout=0.2)
            except queue.Empty:
                ts_epoch, flow, pkt = None, None, None

            if pkt is not None and flow is not None and ts_epoch is not None:
                key: Any = flow if self.per_session else "global"
                meta = self._writers.get(key)
                if meta is None:
                    meta = self._open_writer(key, flow, pkt, ts_epoch)
                    if meta is not None:
                        self._writers[key] = meta

                if meta is not None:
                    # Detect linktype flip (shouldn't happen on a single iface)
                    lt = self._pick_linktype(pkt)
                    if int(meta.get("linktype", lt)) != int(lt):
                        # Close current writer and open a new one with a different base suffix
                        self._close_writer(key, meta, reason="linktype_change", ts_epoch=ts_epoch)
                        self._writers.pop(key, None)
                        # Re-open with updated base
                        try:
                            meta2 = self._open_writer(key, flow, pkt, ts_epoch)
                            if meta2 is not None:
                                self._writers[key] = meta2
                                meta = meta2
                        except Exception:
                            meta = None

                if meta is not None:
                    self._write_one(meta, pkt, ts_epoch)

                    # If per-session writer observed FIN/RST, close promptly (after grace).
                    if self.per_session:
                        try:
                            cn = meta.get("close_now", None)
                            ca = meta.get("close_after", None)
                            if cn is not None:
                                reason, tclose = cn
                                meta2 = self._writers.pop(key, None)
                                if meta2 is not None:
                                    self._close_writer(key, meta2, reason=str(reason), ts_epoch=float(tclose))
                            elif ca is not None and float(now) >= float(ca):
                                reason = meta.get("close_reason", "fin")
                                meta2 = self._writers.pop(key, None)
                                if meta2 is not None:
                                    self._close_writer(key, meta2, reason=str(reason), ts_epoch=float(ca))
                        except Exception:
                            pass

            # Periodic idle close
            if now >= next_gc:
                next_gc = now + 1.0
                if self.idle_close_sec and self.idle_close_sec > 0:
                    to_close: List[Any] = []
                    for key, meta in list(self._writers.items()):
                        last_ts = float(meta.get("last_ts", 0.0))
                        if now - last_ts >= self.idle_close_sec:
                            to_close.append(key)
                    for key in to_close:
                        meta = self._writers.pop(key, None)
                        if meta is not None:
                            self._close_writer(key, meta, reason=f"idle_timeout_{int(self.idle_close_sec)}s", ts_epoch=now)

        # Final close
        now = time.time()
        for key, meta in list(self._writers.items()):
            try:
                self._close_writer(key, meta, reason="service_stop", ts_epoch=now)
            except Exception:
                pass
        self._writers.clear()



class PortAllocator:
    def __init__(self, start: int, end: int, first_req: Optional[int], first_resp: Optional[int]) -> None:
        self.start = start
        self.end = end
        self.first_req = first_req
        self.first_resp = first_resp
        self._did_first = False
        self.used: set[int] = set()
        self._next = start

    def _alloc_one(self) -> int:
        for _ in range(self.start, self.end + 1):
            p = self._next
            self._next += 1
            if self._next > self.end:
                self._next = self.start
            if p in self.used:
                continue
            self.used.add(p)
            return p
        raise RuntimeError("listener port range exhausted")

    def allocate_pair(self) -> Tuple[int, int]:
        if not self._did_first and self.first_req and self.first_resp:
            self._did_first = True
            if self.first_req not in self.used and self.first_resp not in self.used:
                self.used.add(self.first_req)
                self.used.add(self.first_resp)
                return (self.first_req, self.first_resp)
        return (self._alloc_one(), self._alloc_one())

    def free_pair(self, pair: Tuple[int, int]) -> None:
        a, b = pair
        self.used.discard(a)
        self.used.discard(b)


class OutputManager:
    def __init__(self, *, cfg: Dict[str, Any], router: EventRouter) -> None:
        self.cfg = cfg
        self.router = router

        self.role = str(get_path(cfg, "io.mapping.role", "client")).lower().strip()
        if self.role not in ("client", "server"):
            self.role = "client"

        rt = get_path(cfg, "runtime", {}) or {}
        self.max_output_buffer = ensure_int(rt, "max_output_buffer_bytes", 1_000_000)
        self.drain_timeout_ms = ensure_int(rt, "drain_timeout_ms", 0)

        # listener mode
        self.listener_cfg: Dict[str, Any] = get_path(cfg, "io.output.listner", {}) or {}
        self.listener_enabled = bool(self.listener_cfg.get("enabled", False))
        self.listener_bind_ip = str(self.listener_cfg.get("bind_ip", "0.0.0.0"))
        self.listener_range_start = int(self.listener_cfg.get("port_range_start", 0) or 0)
        self.listener_range_end = int(self.listener_cfg.get("port_range_end", 0) or 0)
        first_req = self.listener_cfg.get("first_requests_port")
        first_resp = self.listener_cfg.get("first_responses_port")
        self.port_alloc: Optional[PortAllocator] = None
        if self.listener_enabled:
            if self.listener_range_start <= 0 or self.listener_range_end <= 0 or self.listener_range_end < self.listener_range_start:
                raise SystemExit("listener enabled, but port_range_start/end invalid in config")
            self.port_alloc = PortAllocator(self.listener_range_start, self.listener_range_end, first_req, first_resp)

        # connector mode
        self.conn_cfg: Dict[str, Any] = get_path(cfg, "io.output.remote-host", {}) or {}
        self.connector_enabled = bool(self.conn_cfg.get("enabled", False))
        self.conn_host = str(self.conn_cfg.get("host", "127.0.0.1"))
        self.conn_req_port = int(self.conn_cfg.get("requests_port", 0) or 0)
        self.conn_resp_port = int(self.conn_cfg.get("responses_port", 0) or 0)
        self.conn_connect_timeout = float(get_path(self.conn_cfg, "timeouts.connect", 5) or 5)
        self.conn_retry_every = float(get_path(self.conn_cfg, "timeouts.retry-every", 30) or 30)

        self.sessions: Dict[FlowKey, SessionOutputs] = {}
        self._lock = asyncio.Lock()

    def map_stream(self, direction: str) -> str:
        if self.role == "client":
            return "requests" if direction == "c2s" else "responses"
        return "responses" if direction == "c2s" else "requests"

    async def ensure_session(self, flow: FlowKey) -> SessionOutputs:
        async with self._lock:
            so = self.sessions.get(flow)
            if so is not None:
                return so
            so = SessionOutputs(flow=flow)
            self.sessions[flow] = so

            if self.listener_enabled and self.port_alloc:
                req_p, resp_p = self.port_alloc.allocate_pair()
                so.listener_ports = (req_p, resp_p)
                await self._start_listener_servers(so, req_p, resp_p)
                await self.router.emit(
                    cat="ports",
                    event="listener_ports",
                    level="info",
                    payload={"flow": flow.to_dict(), "requests_port": req_p, "responses_port": resp_p},
                    cp=True,
                )

            if self.connector_enabled and self.conn_req_port > 0 and self.conn_resp_port > 0:
                so.tasks.append(asyncio.create_task(self._connector_loop(so, "requests"), name=f"connector:{flow.session_id}:requests"))
                so.tasks.append(asyncio.create_task(self._connector_loop(so, "responses"), name=f"connector:{flow.session_id}:responses"))

            return so

    async def close_session(self, flow: FlowKey, reason: str) -> None:
        async with self._lock:
            so = self.sessions.pop(flow, None)
        if not so:
            return

        for srv in so.servers:
            srv.close()
            try:
                await srv.wait_closed()
            except Exception:
                pass

        for t in so.tasks:
            t.cancel()

        for d in (so.listeners, so.connectors):
            for k, tw in list(d.items()):
                if tw is None:
                    continue
                try:
                    tw.writer.close()
                except Exception:
                    pass
                d[k] = None

        if so.listener_ports and self.port_alloc:
            self.port_alloc.free_pair(so.listener_ports)

        await self.router.emit(
            cat="debug",
            event="session_close_outputs",
            level="debug",
            payload={"flow": flow.to_dict(), "reason": reason},
            cp=False,
        )

    async def _start_listener_servers(self, so: SessionOutputs, req_port: int, resp_port: int) -> None:
        async def _handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, stream: str) -> None:
            peer = writer.get_extra_info("peername")
            tw = TargetWriter(name=f"listener:{stream}:{so.flow.session_id}", writer=writer, kind="listener")
            so.listeners[stream] = tw
            await self.router.emit(
                cat="output",
                event="listener_connected",
                level="info",
                payload={"flow": so.flow.to_dict(), "stream": stream, "peer": str(peer)},
                cp=True,
            )
            try:
                # listener sockets are sinks in this prototype
                while True:
                    buf = await reader.read(65536)
                    if not buf:
                        break
            except Exception:
                pass
            if so.listeners.get(stream) is tw:
                so.listeners[stream] = None
            try:
                writer.close()
            except Exception:
                pass
            await self.router.emit(
                cat="output",
                event="listener_disconnected",
                level="info",
                payload={"flow": so.flow.to_dict(), "stream": stream, "peer": str(peer)},
                cp=True,
            )

        srv_req = await asyncio.start_server(lambda r, w: _handler(r, w, "requests"), host=self.listener_bind_ip, port=req_port, start_serving=True)
        srv_resp = await asyncio.start_server(lambda r, w: _handler(r, w, "responses"), host=self.listener_bind_ip, port=resp_port, start_serving=True)
        so.servers.extend([srv_req, srv_resp])

    async def _connector_loop(self, so: SessionOutputs, stream: str) -> None:
        host = self.conn_host
        port = self.conn_req_port if stream == "requests" else self.conn_resp_port
        st = so.connector_state[stream]

        while True:
            try:
                # local logs only: connection attempt categorization
                if st.ever_connected:
                    await self.router.emit(
                        cat="output",
                        event="connector_reconnect",
                        level="info",
                        payload={"flow": so.flow.to_dict(), "stream": stream, "host": host, "port": port, "retry_every_sec": self.conn_retry_every},
                        cp=False,
                    )
                else:
                    await self.router.emit(
                        cat="output",
                        event="connector_connection_reattempt",
                        level="debug",
                        payload={"flow": so.flow.to_dict(), "stream": stream, "host": host, "port": port, "retry_every_sec": self.conn_retry_every},
                        cp=False,
                    )

                reader, writer = await asyncio.wait_for(asyncio.open_connection(host=host, port=port), timeout=self.conn_connect_timeout)
                tw = TargetWriter(name=f"connector:{stream}:{so.flow.session_id}", writer=writer, kind="connector")
                so.connectors[stream] = tw

                was_connected = st.currently_connected
                st.currently_connected = True
                st.ever_connected = True

                if not was_connected:
                    await self.router.emit(
                        cat="output",
                        event="connector_connected",
                        level="info",
                        payload={"flow": so.flow.to_dict(), "stream": stream, "peer": str(writer.get_extra_info("peername"))},
                        cp=True,
                    )

                while True:
                    buf = await reader.read(65536)
                    if not buf:
                        break

            except asyncio.CancelledError:
                raise
            except Exception as e:
                await self.router.emit(
                    cat="debug",
                    event="connector_error",
                    level="debug",
                    payload={"flow": so.flow.to_dict(), "stream": stream, "error": repr(e)},
                    cp=False,
                )

            tw = so.connectors.get(stream)
            so.connectors[stream] = None
            if tw:
                try:
                    tw.writer.close()
                except Exception:
                    pass

            # Requested: CP event only if it *was* connected before.
            if st.currently_connected:
                st.currently_connected = False
                await self.router.emit(
                    cat="output",
                    event="connector_disconnected",
                    level="warning",
                    payload={"flow": so.flow.to_dict(), "stream": stream, "retry_every_sec": self.conn_retry_every},
                    cp=True,
                )
            else:
                await self.router.emit(
                    cat="output",
                    event="connector_disconnect_suppressed",
                    level="debug",
                    payload={"flow": so.flow.to_dict(), "stream": stream},
                    cp=False,
                )

            await asyncio.sleep(self.conn_retry_every)

    async def write_chunk(self, flow: FlowKey, direction: str, data: bytes) -> Tuple[int, int, str, int]:
        """
        Forward reassembled stream bytes to all configured targets for mapped stream.
        Drops if no targets or backpressure.
        """
        if not data:
            return (0, 0, "empty", 0)

        so = await self.ensure_session(flow)
        stream = self.map_stream(direction)
        targets = so.all_targets_for(stream)

        if not targets:
            return (0, len(data), "no_targets", 0)

        sent = 0
        dropped = 0
        reason = "ok"

        sent_targets = 0
        dropped_targets = 0
        drop_reasons = set()

        for tw in targets:
            if tw.is_closing():
                dropped += len(data)
                dropped_targets += 1
                drop_reasons.add("closing")
                continue
            if tw.buffer_size() > self.max_output_buffer:
                dropped += len(data)
                dropped_targets += 1
                drop_reasons.add("backpressure")
                continue
            try:
                tw.writer.write(data)
                if self.drain_timeout_ms > 0:
                    try:
                        await asyncio.wait_for(tw.writer.drain(), timeout=self.drain_timeout_ms / 1000.0)
                    except asyncio.TimeoutError:
                        # Intentionally do not block indefinitely.
                        pass
                sent += len(data)
                sent_targets += 1
            except Exception:
                dropped += len(data)
                dropped_targets += 1
                drop_reasons.add("write_error")
                try:
                    tw.writer.close()
                except Exception:
                    pass

        if dropped:
            # If at least one target got the chunk, this is a *partial* drop.
            # Make that visible in stats to reduce confusion ("my listener got everything, why drops?").
            if sent_targets:
                reason = "partial:" + ",".join(sorted(drop_reasons)) if drop_reasons else "partial:drop"
            else:
                reason = ",".join(sorted(drop_reasons)) if drop_reasons else "drop"

        return (sent, dropped, reason, len(targets))



# =============================================================================
# Service
# =============================================================================

class Service:
    def __init__(self, cfg: Dict[str, Any], log: logging.Logger) -> None:
        self.cfg = cfg
        self.log = log

        cap = get_path(cfg, "io.input.capture", {}) or {}
        self.iface = str(cap.get("iface", "")).strip()
        self.local_ip = str(cap.get("local_ip", "")).strip()
        self.remote_ip = str(cap.get("remote_ip", "")).strip()
        self.remote_port = int(cap.get("remote_port", 0) or 0)
        self.local_port_filter = cap.get("local_port", None)

        if not self.iface or not self.local_ip or not self.remote_ip or not self.remote_port:
            raise SystemExit("Missing io.input.capture fields: iface/local_ip/remote_ip/remote_port")

        bpf_tpl = str(cap.get("bpf-filter", "")).strip()
        if not bpf_tpl:
            bpf_tpl = (
                "tcp and ("
                "((src host {local_ip} and dst host {remote_ip} and dst port {remote_port})"
                " or "
                "(src host {remote_ip} and src port {remote_port} and dst host {local_ip}))"
                ")"
            )

        fmt = {
            "local_ip": self.local_ip,
            "remote_ip": self.remote_ip,
            "remote_port": self.remote_port,
            "local_port": self.local_port_filter if self.local_port_filter is not None else "",
        }
        try:
            self.bpf = bpf_tpl.format_map(fmt)
        except Exception:
            self.bpf = bpf_tpl

        # restored: if local_port is specified but template doesn't use it, append a cheap filter
        if self.local_port_filter is not None and "{local_port}" not in bpf_tpl:
            try:
                lp = int(self.local_port_filter)
                self.bpf = f"({self.bpf}) and (tcp port {lp})"
            except Exception:
                pass

        if cap.get("scapy_bufsize") is not None:
            try:
                conf.bufsize = int(cap["scapy_bufsize"])
                self.log.info("scapy conf.bufsize=%d", int(conf.bufsize))
            except Exception:
                pass

        rt = get_path(cfg, "runtime", {}) or {}
        raw_workers = rt.get("workers", os.cpu_count() or 4)
        try:
            if int(raw_workers or 0) == 0:
                raw_workers = os.cpu_count() or 4
        except Exception:
            pass
        self.workers = clamp_int(raw_workers, default=4, lo=1, hi=256)

        self.capture_queue_size = clamp_int(rt.get("capture_queue_size", 50000), default=50000, lo=1000, hi=5_000_000)

        self.session_idle_sec = float(cap.get("session_idle_sec", 120) or 120)
        ack_stall_sec = get_path(cfg, "io.output.listner.timeouts.ack_stall_sec", None)
        self.ack_stall_sec = float(ack_stall_sec) if ack_stall_sec is not None else None

        ctrl = get_path(cfg, "control", {}) or {}
        self.control_bind_ip = str(ctrl.get("bind_ip", "0.0.0.0"))
        self.control_port = int(ctrl.get("listen_port", 50005) or 50005)

        default_cats = get_path(ctrl, "default_cats", None)
        if isinstance(default_cats, list):
            cp_default_cats = {str(x).strip() for x in default_cats if str(x).strip()}
        else:
            cp_default_cats = {"session", "ports", "output", "control"}

        self.control = ControlPlane(bind_ip=self.control_bind_ip, port=self.control_port, log=log, default_cats=cp_default_cats)
        self.router = EventRouter(log=log, cp=self.control)
        self.outputs = OutputManager(cfg=cfg, router=self.router)

        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.forward_q: "asyncio.Queue[ForwardChunk]" = asyncio.Queue(maxsize=20000)
        self.event_q: "asyncio.Queue[SessionEvent]" = asyncio.Queue(maxsize=20000)

        self.worker_inqs: List["queue.Queue[PacketInfo]"] = []
        self.workers_threads: List[ReassemblyWorker] = []
        self.capture: Optional[CaptureThread] = None
        self.pcap_sink: PcapSink = PcapSink.from_cfg(cfg, local_ip=self.local_ip, remote_ip=self.remote_ip, remote_port=self.remote_port,
                                                     idle_close_sec=self.session_idle_sec, log=log)

        # bookkeeping
        self._sessions: Dict[int, Dict[str, Any]] = {}
        self._session_bytes_out: DefaultDict[int, int] = defaultdict(int)
        self._session_bytes_drop: DefaultDict[int, int] = defaultdict(int)

        self._drop_count: DefaultDict[Tuple[int, str, str], int] = defaultdict(int)
        self._drop_bytes: DefaultDict[Tuple[int, str, str], int] = defaultdict(int)

        self._bytes_forwarded = 0
        self._bytes_dropped = 0
        self._chunks_forwarded = 0
        self._chunks_dropped = 0

        self.stats_interval_sec = float(get_path(cfg, "runtime.stats_interval_sec", 5) or 5)
        self._tasks: List[asyncio.Task] = []

    def stats_snapshot(self) -> Dict[str, Any]:
        return {
            "ts": utc_iso(),
            "workers": self.workers,
            "sessions": len(self._sessions),
            "bytes_forwarded": self._bytes_forwarded,
            "bytes_dropped": self._bytes_dropped,
            "chunks_forwarded": self._chunks_forwarded,
            "chunks_dropped": self._chunks_dropped,
            "drop_detail": self.drop_detail_snapshot(),
            "control_bytes_out": self.control.bytes_out,
            "control_events_dropped": self.control.events_dropped,
            "pcap": self.pcap_sink.stats_snapshot() if self.pcap_sink is not None else {
                "enabled": False,
                "format": None,
                "per_session": None,
                "dir": None,
                "pkts_written": 0,
                "bytes_written": 0,
                "pkts_dropped": 0,
                "pkts_failed": 0,
                "files_opened": 0,
                "files_closed": 0,
            },
        }

    def list_sessions(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for sid, meta in self._sessions.items():
            out.append({
                "session_id": sid,
                "flow": meta["flow"],
                "open_ts": meta["open_ts"],
                "last_ts": meta["last_ts"],
                "bytes_forwarded": self._session_bytes_out.get(sid, 0),
                "bytes_dropped": self._session_bytes_drop.get(sid, 0),
            })
        return out

    def get_session(self, session_id: int) -> Optional[Dict[str, Any]]:
        meta = self._sessions.get(session_id)
        if not meta:
            return None

        drops: Dict[str, Dict[str, Dict[str, int]]] = {}
        for (sid, stream, reason), cnt in self._drop_count.items():
            if sid != session_id:
                continue
            drops.setdefault(stream, {})
            drops[stream][reason] = {"count": cnt, "bytes": self._drop_bytes[(sid, stream, reason)]}

        return {
            "session_id": session_id,
            "flow": meta["flow"],
            "open_ts": meta["open_ts"],
            "last_ts": meta["last_ts"],
            "bytes_forwarded": self._session_bytes_out.get(session_id, 0),
            "bytes_dropped": self._session_bytes_drop.get(session_id, 0),
            "drops": drops,
        }

    async def close_session_by_id(self, session_id: int, reason: str) -> bool:
        flow = None
        for fk in list(self.outputs.sessions.keys()):
            if fk.session_id == session_id:
                flow = fk
                break
        if not flow:
            return False
        await self.outputs.close_session(flow, reason=reason)
        return True

    async def start(self) -> None:
        self.loop = asyncio.get_running_loop()
        self.control.set_callbacks(
            get_stats=self.stats_snapshot,
            list_sessions=self.list_sessions,
            get_session=self.get_session,
            close_session=self.close_session_by_id,
        )
        await self.control.start()

        self._tasks.append(asyncio.create_task(self._consume_events(), name="svc.consume_events"))
        self._tasks.append(asyncio.create_task(self._consume_forward(), name="svc.consume_forward"))
        self._tasks.append(asyncio.create_task(self._periodic_stats_local(), name="svc.stats_local"))

        self.worker_inqs = [queue.Queue(maxsize=self.capture_queue_size) for _ in range(self.workers)]
        for wid in range(self.workers):
            w = ReassemblyWorker(
                wid=wid,
                inq=self.worker_inqs[wid],
                loop=self.loop,
                outq=self.forward_q,
                evq=self.event_q,
                session_idle_sec=self.session_idle_sec,
                ack_stall_sec=self.ack_stall_sec,
            )
            w.start()
            self.workers_threads.append(w)

        # Start PCAP sink (raw packet recorder)
        try:
            self.pcap_sink.start()
        except Exception:
            pass

        self.capture = CaptureThread(
            iface=self.iface,
            bpf=self.bpf,
            local_ip=self.local_ip,
            remote_ip=self.remote_ip,
            q_by_worker=self.worker_inqs,
            log=self.log,
            pcap_sink=self.pcap_sink if self.pcap_sink.enabled else None,
        )
        self.capture.start()

        await self.router.emit(
            cat="control",
            event="service_started",
            level="info",
            payload={"iface": self.iface, "bpf": self.bpf, "workers": self.workers},
            cp=True,
        )

    async def stop(self) -> None:
        await self.router.emit(cat="control", event="service_stopping", level="info", payload={}, cp=True)

        if self.capture:
            self.capture.stop()
        try:
            self.pcap_sink.stop()
        except Exception:
            pass
        for w in self.workers_threads:
            w.stop()

        for t in self._tasks:
            t.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

        for fk in list(self.outputs.sessions.keys()):
            try:
                await self.outputs.close_session(fk, reason="service_stop")
            except Exception:
                pass

        await self.control.close()

        if self.capture:
            self.capture.join(timeout=2.0)
        try:
            self.pcap_sink.join(timeout=2.0)
        except Exception:
            pass
        for w in self.workers_threads:
            w.join(timeout=1.0)

    async def _periodic_stats_local(self) -> None:
        while True:
            await asyncio.sleep(self.stats_interval_sec)
            await self.router.emit(cat="stats", event="stats", level="info", payload=self.stats_snapshot(), cp=False)

    async def _consume_events(self) -> None:
        while True:
            ev = await self.event_q.get()
            sid = ev.flow.session_id

            if ev.kind == "open":
                self._sessions[sid] = {"flow": ev.flow.to_dict(), "open_ts": utc_iso(), "last_ts": utc_iso()}
                await self.outputs.ensure_session(ev.flow)
                await self.router.emit(cat="session", event="tcp_open", level="info", payload={"flow": ev.flow.to_dict()}, cp=True)

            elif ev.kind == "close":
                meta = self._sessions.get(sid)
                if meta:
                    meta["last_ts"] = utc_iso()

                summary = self.get_session(sid) or {"session_id": sid, "flow": ev.flow.to_dict()}
                summary["reason"] = ev.data.get("reason")

                await self.router.emit(cat="session", event="session_summary", level="info", payload=summary, cp=True)

                await self.outputs.close_session(ev.flow, reason=ev.data.get("reason", "close"))
                await self.router.emit(
                    cat="session",
                    event="tcp_close",
                    level="info",
                    payload={"flow": ev.flow.to_dict(), "reason": ev.data.get("reason")},
                    cp=True,
                )

                self._sessions.pop(sid, None)
                self._session_bytes_out.pop(sid, None)
                self._session_bytes_drop.pop(sid, None)
                for key in list(self._drop_count.keys()):
                    if key[0] == sid:
                        self._drop_count.pop(key, None)
                        self._drop_bytes.pop(key, None)

            else:
                # Requested: always DEBUG, including ack_stall
                await self.router.emit(
                    cat="flow",
                    event="tcp_note",
                    level="debug",
                    payload={"flow": ev.flow.to_dict(), **ev.data},
                    cp=True,
                )

    async def _consume_forward(self) -> None:
        while True:
            ch = await self.forward_q.get()
            sid = ch.flow.session_id
            stream = self.outputs.map_stream(ch.direction)

            sent, dropped, reason, _targets = await self.outputs.write_chunk(ch.flow, ch.direction, ch.data)

            if sent:
                self._bytes_forwarded += sent
                self._chunks_forwarded += 1
                self._session_bytes_out[sid] += sent

            if dropped:
                self._bytes_dropped += dropped
                self._chunks_dropped += 1
                self._session_bytes_drop[sid] += dropped
                key = (sid, stream, reason)
                self._drop_count[key] += 1
                self._drop_bytes[key] += dropped


# =============================================================================
# Logging setup from config (+ optional CLI override)
# =============================================================================

def setup_logging_from_config(cfg: Dict[str, Any], cli_level: Optional[str]) -> logging.Logger:
    log = logging.getLogger("stethoscope")
    log.propagate = False
    log.handlers.clear()
    log.setLevel(logging.DEBUG)  # handlers gate output

    lc = get_path(cfg, "logging", {}) or {}

    console_cfg = lc.get("console", {}) or {}
    file_cfg = lc.get("file", {}) or {}

    console_level = parse_level(console_cfg.get("verbosity"), logging.INFO)
    if cli_level:
        console_level = parse_level(cli_level, console_level)

    ch = logging.StreamHandler()
    ch.setLevel(console_level)
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(ch)

    if bool(file_cfg.get("enabled", False)):
        path = str(file_cfg.get("path", "stethoscope.log"))
        file_level = parse_level(file_cfg.get("verbosity"), logging.INFO)
        fh = logging.FileHandler(path, encoding="utf-8")
        fh.setLevel(file_level)
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        log.addHandler(fh)

    return log


# =============================================================================
# HARD TERMINATION (child-only)
# =============================================================================

# NOTE: We intentionally do NOT kill our process group or parent chain.
# Doing so can take down your terminal(s) and other unrelated shells.
# We only terminate subprocesses we spawned (if any), then os._exit.

# =============================================================================
# CLI + entrypoint
# =============================================================================

def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="BPF TCP capture + reassembly + forwarding (with CP noise control)")
    p.add_argument("--config", required=True, help="Path to JSON (or json-ish) config file")
    p.add_argument("--log-level", default=None, help="Optional console override: DEBUG/INFO/WARNING/ERROR")
    return p


async def amain(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    log = setup_logging_from_config(cfg, args.log_level)

    svc = Service(cfg, log)

    stop_ev = asyncio.Event()
    loop = asyncio.get_running_loop()

    def _request_stop() -> None:
        if not stop_ev.is_set():
            stop_ev.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _request_stop)
        except NotImplementedError:
            pass

    def _sig_handler(_signum, _frame) -> None:
        try:
            loop.call_soon_threadsafe(_request_stop)
        except Exception:
            _request_stop()

    try:
        signal.signal(signal.SIGINT, _sig_handler)
        signal.signal(signal.SIGTERM, _sig_handler)
    except Exception:
        pass

    await svc.start()

    try:
        await stop_ev.wait()
    except KeyboardInterrupt:
        _request_stop()

    # HARD TERMINATION: if stop hangs, nuke everything
    try:
        await asyncio.wait_for(svc.stop(), timeout=3.0)
    except Exception:
        hard_exit(0)

    await asyncio.sleep(0)
    return 0


def main() -> None:
    args = build_argparser().parse_args()
    try:
        rc = asyncio.run(amain(args))
    except KeyboardInterrupt:
        # If we ever get here (some environments), mimic the same behavior:
        hard_exit(0)
        rc = 0
    raise SystemExit(rc)


if __name__ == "__main__":
    main()