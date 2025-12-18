#!/usr/bin/env python3
"""
stethoscope.py

BPF/pcap capture + TCP reassembly + forwarding, with sane control-plane event routing.

Key features:
- Capture via scapy/libpcap using BPF filter.
- TCP reassembly per session (local_port is session_id), both directions.
- Forward reassembled byte streams to:
    * listener ports (per session: requests/responses)
    * connector remote-host ports (per session: requests/responses)
    * mixed mode
    * control-only mode (no outputs enabled)
- Control plane: single TCP client, JSON lines.

Noise control:
- Events are categorized: session/ports/output/control/flow/debug/stats
- Control plane receives only subscribed categories (default from config).
- Flow notes (ack_stall / tcp_reassembly) are gated behind tcp_flow_enable.

Connector event policy (as requested):
- output.connector_disconnected is sent to CP ONLY when a connector was connected and then got disconnected.
- Retry attempts that never had a successful connection do NOT produce connector_disconnected for CP.
  Instead logs-only events are emitted:
    * output.connector_connection_reattempt (never connected yet)
    * output.connector_reconnect (had connected before, now retrying)

Drops:
- No per-drop CP/log spam.
- Drops are aggregated and reported in session_summary and stats-on-demand.

Shutdown:
- Ctrl+C exits cleanly. Capture thread uses timed sniff loop to stop even when idle.
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

# --- Scapy / libpcap ----------------------------------------------------------
try:
    from scapy.all import conf, sniff  # type: ignore
    from scapy.layers.inet import IP, TCP  # type: ignore
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
# TCP reassembly
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

        # old first, then new (so new cannot overwrite old)
        parts_sorted = sorted(parts, key=lambda x: 0 if x[2] == "old" else 1)
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

    highest_seq_sent: int = 0

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
        asyncio.create_task(self._event_pump())

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

        self._client_task = asyncio.create_task(_cmd_loop())
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
# Event router: local logs vs CP, with per-event cp flag
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
        # Always local log (handler levels decide visibility)
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

            if p.payload:
                end_seq = p.seq + len(p.payload)
                if end_seq > dir_state.highest_seq_sent:
                    dir_state.highest_seq_sent = end_seq

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
    ) -> None:
        super().__init__(name="pcap")
        self.iface = iface
        self.bpf = bpf
        self.local_ip = local_ip
        self.remote_ip = remote_ip
        self.q_by_worker = q_by_worker
        self.log = log
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def _dispatch(self, p: PacketInfo) -> None:
        sid = p.flow.session_id
        idx = sid % len(self.q_by_worker) if self.q_by_worker else 0
        try:
            self.q_by_worker[idx].put_nowait(p)
        except queue.Full:
            # capture overload: drop packet at capture stage
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

        # Timed loop => stop even if no packets
        try:
            while not self._stop.is_set():
                sniff(
                    iface=self.iface,
                    filter=self.bpf,
                    prn=_cb,
                    store=False,
                    timeout=1,  # key for clean shutdown
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
                so.tasks.append(asyncio.create_task(self._connector_loop(so, "requests")))
                so.tasks.append(asyncio.create_task(self._connector_loop(so, "responses")))

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
                # Logs-only attempt events (as requested)
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

                # Transition to connected
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
                # Logs-only error
                await self.router.emit(
                    cat="debug",
                    event="connector_error",
                    level="debug",
                    payload={"flow": so.flow.to_dict(), "stream": stream, "error": repr(e)},
                    cp=False,
                )

            # Connector ended. Decide whether this is a "real disconnect" transition.
            tw = so.connectors.get(stream)
            so.connectors[stream] = None
            if tw:
                try:
                    tw.writer.close()
                except Exception:
                    pass

            if st.currently_connected:
                # real transition connected -> disconnected
                st.currently_connected = False
                await self.router.emit(
                    cat="output",
                    event="connector_disconnected",
                    level="warning",
                    payload={"flow": so.flow.to_dict(), "stream": stream, "retry_every_sec": self.conn_retry_every},
                    cp=True,  # CP only in this case
                )
            else:
                # never connected, or already disconnected: do NOT spam CP
                await self.router.emit(
                    cat="debug",
                    event="connector_disconnected_suppressed",
                    level="debug",
                    payload={"flow": so.flow.to_dict(), "stream": stream},
                    cp=False,
                )

            await asyncio.sleep(self.conn_retry_every)

    async def write_chunk(self, flow: FlowKey, direction: str, data: bytes) -> Tuple[int, int, str, int]:
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

        for tw in targets:
            if tw.is_closing():
                dropped += len(data)
                reason = "closing"
                continue
            if tw.buffer_size() > self.max_output_buffer:
                dropped += len(data)
                reason = "backpressure"
                continue
            try:
                tw.writer.write(data)
                if self.drain_timeout_ms > 0:
                    try:
                        await asyncio.wait_for(tw.writer.drain(), timeout=self.drain_timeout_ms / 1000.0)
                    except asyncio.TimeoutError:
                        pass
                sent += len(data)
            except Exception:
                dropped += len(data)
                reason = "write_error"
                try:
                    tw.writer.close()
                except Exception:
                    pass

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
        self.workers = clamp_int(rt.get("workers", os.cpu_count() or 4), default=4, lo=1, hi=256)
        self.capture_queue_size = clamp_int(rt.get("capture_queue_size", 50000), default=50000, lo=1000, hi=5_000_000)

        self.session_idle_sec = float(cap.get("session_idle_sec", 120) or 120)
        ack_stall_sec = get_path(cfg, "io.output.listner.timeouts.ack_stall_sec", None)
        self.ack_stall_sec = float(ack_stall_sec) if ack_stall_sec is not None else None

        # Control defaults
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

        # Session accounting
        self._sessions: Dict[int, Dict[str, Any]] = {}  # session_id -> {flow, open_ts, last_ts}
        self._session_bytes_out: DefaultDict[int, int] = defaultdict(int)
        self._session_bytes_drop: DefaultDict[int, int] = defaultdict(int)

        # Drop aggregation: (sid, stream, reason) -> count/bytes
        self._drop_count: DefaultDict[Tuple[int, str, str], int] = defaultdict(int)
        self._drop_bytes: DefaultDict[Tuple[int, str, str], int] = defaultdict(int)

        self._bytes_forwarded = 0
        self._bytes_dropped = 0
        self._chunks_forwarded = 0
        self._chunks_dropped = 0

        self.stats_interval_sec = float(get_path(cfg, "runtime.stats_interval_sec", 5) or 5)

    def stats_snapshot(self) -> Dict[str, Any]:
        return {
            "ts": utc_iso(),
            "workers": self.workers,
            "sessions": len(self._sessions),
            "bytes_forwarded": self._bytes_forwarded,
            "bytes_dropped": self._bytes_dropped,
            "chunks_forwarded": self._chunks_forwarded,
            "chunks_dropped": self._chunks_dropped,
            "control_bytes_out": self.control.bytes_out,
            "control_events_dropped": self.control.events_dropped,
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

        asyncio.create_task(self._consume_events())
        asyncio.create_task(self._consume_forward())
        asyncio.create_task(self._periodic_stats_local())

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

        self.capture = CaptureThread(
            iface=self.iface,
            bpf=self.bpf,
            local_ip=self.local_ip,
            remote_ip=self.remote_ip,
            q_by_worker=self.worker_inqs,
            log=self.log,
        )
        self.capture.start()

        await self.router.emit(cat="control", event="service_started", level="info", payload={"iface": self.iface, "bpf": self.bpf, "workers": self.workers}, cp=True)

    async def stop(self) -> None:
        await self.router.emit(cat="control", event="service_stopping", level="info", payload={}, cp=True)

        if self.capture:
            self.capture.stop()
        for w in self.workers_threads:
            w.stop()

        # Close CP first so emit() won't block on dead socket
        await self.control.close()

        # Close outputs
        for fk in list(self.outputs.sessions.keys()):
            try:
                await self.outputs.close_session(fk, reason="service_stop")
            except Exception:
                pass

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
                await self.router.emit(cat="session", event="tcp_close", level="info", payload={"flow": ev.flow.to_dict(), "reason": ev.data.get("reason")}, cp=True)

                # cleanup
                self._sessions.pop(sid, None)
                self._session_bytes_out.pop(sid, None)
                self._session_bytes_drop.pop(sid, None)
                for key in list(self._drop_count.keys()):
                    if key[0] == sid:
                        self._drop_count.pop(key, None)
                        self._drop_bytes.pop(key, None)

            else:
                note = ev.data.get("note", "note")
                lvl = "warning" if note == "ack_stall" else "debug"
                await self.router.emit(cat="flow", event="tcp_note", level=lvl, payload={"flow": ev.flow.to_dict(), **ev.data}, cp=True)

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
# Logging setup from config
# =============================================================================

def setup_logging_from_config(cfg: Dict[str, Any]) -> logging.Logger:
    log = logging.getLogger("stethoscope")
    log.propagate = False
    log.handlers.clear()
    log.setLevel(logging.DEBUG)  # handlers gate output

    lc = get_path(cfg, "logging", {}) or {}

    console_cfg = lc.get("console", {}) or {}
    file_cfg = lc.get("file", {}) or {}

    console_level = parse_level(console_cfg.get("verbosity"), logging.INFO)

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
# CLI + entrypoint
# =============================================================================

def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="BPF TCP capture + reassembly + forwarding (with CP noise control)")
    p.add_argument("--config", required=True, help="Path to JSON (or json-ish) config file")
    return p


async def amain(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    log = setup_logging_from_config(cfg)

    # runtime.workers: 0 => auto
    rt = get_path(cfg, "runtime", {}) or {}
    try:
        if int(rt.get("workers", 0) or 0) == 0:
            rt["workers"] = os.cpu_count() or 4
            cfg["runtime"] = rt
    except Exception:
        pass

    svc = Service(cfg, log)

    stop_ev = asyncio.Event()

    def _stop(*_a) -> None:
        stop_ev.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _stop)
        except NotImplementedError:
            pass

    await svc.start()
    await stop_ev.wait()

    # Clean shutdown
    await svc.stop()

    # Let pending cancellations settle
    await asyncio.sleep(0)

    return 0


def main() -> None:
    args = build_argparser().parse_args()
    try:
        rc = asyncio.run(amain(args))
    except KeyboardInterrupt:
        rc = 130
    raise SystemExit(rc)


if __name__ == "__main__":
    main()
