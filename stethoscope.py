#!/usr/bin/env python3
"""
bpf_tcp_relay.py

BPF/pcap packet capture + TCP reassembly + fan-out forwarding (prototype).

- Captures TCP packets (Scapy + libpcap/BPF).
- Reassembles TCP byte streams per session (both directions).
- Forwards reassembled bytes to outputs:
    * listener mode: per-session ports for requests/responses
    * connector mode: per-session outgoing conns to remote host ports
    * mixed mode: both
    * control-only: emits only open/close/flow events
- Control plane: single TCP client, JSON-lines (1 JSON object per line).

Config format:
- Accepts strict JSON
- Also accepts your “json-ish” example (unquoted keys, trailing commas, ///# comments).

Ethics/legal:
- Use only on interfaces/traffic you’re authorized to inspect.
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
from typing import Any, Dict, Optional, Tuple, List

# --- Scapy (packet capture) ---------------------------------------------------
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
# Utilities
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


def json_dumps_line(obj: Any) -> bytes:
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


# =============================================================================
# “json-ish” loader
# =============================================================================

_KEY_RE = re.compile(r'(?m)(^|\s|[{,])([A-Za-z_][A-Za-z0-9_-]*)(\s*):')
_TRAILING_COMMA_RE = re.compile(r",(\s*[}\]])")
_LINE_COMMENT_RE = re.compile(r"(?m)^\s*(//|#).*$")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)


def _jsonish_to_json(text: str) -> str:
    """
    Best-effort conversion of a JS-object-ish config into strict JSON.

    Handles:
      - unquoted keys:  io: { output: { remote-host: {...}}}
      - comments (# or //, and /* ... */)
      - trailing commas before } or ]
    """
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
# TCP reassembly (based on your mtproto_follow_stream19.py)
# =============================================================================

MAX_OOO_SEGMENTS = 4096


@dataclass
class TCPReassembler:
    """
    Interval-merging TCP reassembler with overlap/retransmit handling.

    - before first emission: keep segments even if behind next_seq, track min(seq)
    - conflict-safe overlap merge: never overwrite existing buffered bytes on conflict
    """
    next_seq: Optional[int] = None
    segments: Dict[int, bytes] = field(default_factory=dict)
    emitted_bytes: int = 0

    # Counters for stats/events
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
                # overlap or touch
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

        # old first, then new (so new can't overwrite old)
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

        # while no emission happened, keep “behind” segments
        if self.emitted_bytes == 0:
            self.segments.setdefault(seq, b"")
            if self.segments[seq] == b"":
                del self.segments[seq]

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
            # keep earlier segments; evict highest seq
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
# Packet + session model
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

    # ACK/window stats observed in this direction
    last_ack: Optional[int] = None
    last_ack_ts: float = field(default_factory=monotime)
    max_rwnd_bytes: int = 0
    wscale: Optional[int] = None

    # inflight estimate support
    highest_seq_sent: int = 0
    max_inflight_est: int = 0

    # last reasm counters snapshot (for delta events)
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
# Worker->asyncio events
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
# Reassembly worker threads (sharded by session_id)
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
        log: logging.Logger,
    ) -> None:
        super().__init__(name=f"reasm-{wid}")
        self.wid = wid
        self.inq = inq
        self.loop = loop
        self.outq = outq
        self.evq = evq
        self.session_idle_sec = session_idle_sec
        self.ack_stall_sec = ack_stall_sec
        self.log = log
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
                # If ACK doesn't advance in either direction for too long, emit a note (rate-limited)
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

    def run(self) -> None:  # noqa: C901
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

            # FIN/RST close detection (coarse)
            if p.flags & 0x04:  # RST
                self._session_close(st, ts, "rst")
                continue
            if p.flags & 0x01:  # FIN
                self._session_close(st, ts, "fin")
                continue

            dir_state = st.c2s if p.from_local else st.s2c
            dir_state.note_packet(p)

            # track highest seq in this direction
            if p.payload:
                end_seq = p.seq + len(p.payload)
                if end_seq > dir_state.highest_seq_sent:
                    dir_state.highest_seq_sent = end_seq

            # estimate inflight from opposite ACKs
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

            # reassembly + contiguous emit
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
# Output plumbing (asyncio)
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
class SessionOutputs:
    flow: FlowKey
    listener_ports: Optional[Tuple[int, int]] = None  # (requests_port, responses_port)
    listeners: Dict[str, Optional[TargetWriter]] = field(default_factory=lambda: {"requests": None, "responses": None})
    connectors: Dict[str, Optional[TargetWriter]] = field(default_factory=lambda: {"requests": None, "responses": None})
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
    def __init__(self, *, cfg: Dict[str, Any], control: "ControlPlane", log: logging.Logger) -> None:
        self.cfg = cfg
        self.control = control
        self.log = log

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
        """
        role=client: c2s=requests, s2c=responses
        role=server: c2s=responses, s2c=requests
        """
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
                await self.control.emit({
                    "ts": utc_iso(),
                    "event": "listener_ports",
                    "flow": flow.to_dict(),
                    "requests_port": req_p,
                    "responses_port": resp_p,
                })

            if self.connector_enabled and self.conn_req_port > 0 and self.conn_resp_port > 0:
                so.tasks.append(asyncio.create_task(self._connector_loop(so, "requests")))
                so.tasks.append(asyncio.create_task(self._connector_loop(so, "responses")))

            return so

    async def close_session(self, flow: FlowKey, reason: str) -> None:
        async with self._lock:
            so = self.sessions.pop(flow, None)
        if not so:
            return

        await self.control.emit({
            "ts": utc_iso(),
            "event": "session_close_outputs",
            "flow": flow.to_dict(),
            "reason": reason,
        })

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

    async def _start_listener_servers(self, so: SessionOutputs, req_port: int, resp_port: int) -> None:
        async def _handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, stream: str) -> None:
            peer = writer.get_extra_info("peername")
            tw = TargetWriter(name=f"listener:{stream}:{so.flow.session_id}", writer=writer, kind="listener")
            so.listeners[stream] = tw
            await self.control.emit({
                "ts": utc_iso(),
                "event": "listener_connected",
                "flow": so.flow.to_dict(),
                "stream": stream,
                "peer": str(peer),
            })
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
            await self.control.emit({
                "ts": utc_iso(),
                "event": "listener_disconnected",
                "flow": so.flow.to_dict(),
                "stream": stream,
                "peer": str(peer),
            })

        srv_req = await asyncio.start_server(
            lambda r, w: _handler(r, w, "requests"),
            host=self.listener_bind_ip,
            port=req_port,
            start_serving=True,
        )
        srv_resp = await asyncio.start_server(
            lambda r, w: _handler(r, w, "responses"),
            host=self.listener_bind_ip,
            port=resp_port,
            start_serving=True,
        )
        so.servers.extend([srv_req, srv_resp])

    async def _connector_loop(self, so: SessionOutputs, stream: str) -> None:
        host = self.conn_host
        port = self.conn_req_port if stream == "requests" else self.conn_resp_port
        name = f"connector:{stream}:{so.flow.session_id}"

        while True:
            try:
                await self.control.emit({
                    "ts": utc_iso(),
                    "event": "connector_connecting",
                    "flow": so.flow.to_dict(),
                    "stream": stream,
                    "host": host,
                    "port": port,
                })
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host=host, port=port),
                    timeout=self.conn_connect_timeout,
                )
                tw = TargetWriter(name=name, writer=writer, kind="connector")
                so.connectors[stream] = tw
                await self.control.emit({
                    "ts": utc_iso(),
                    "event": "connector_connected",
                    "flow": so.flow.to_dict(),
                    "stream": stream,
                    "peer": str(writer.get_extra_info("peername")),
                })

                while True:
                    buf = await reader.read(65536)
                    if not buf:
                        break

            except asyncio.CancelledError:
                raise
            except Exception as e:
                await self.control.emit({
                    "ts": utc_iso(),
                    "event": "connector_error",
                    "flow": so.flow.to_dict(),
                    "stream": stream,
                    "error": repr(e),
                })

            tw = so.connectors.get(stream)
            so.connectors[stream] = None
            if tw:
                try:
                    tw.writer.close()
                except Exception:
                    pass

            await self.control.emit({
                "ts": utc_iso(),
                "event": "connector_disconnected",
                "flow": so.flow.to_dict(),
                "stream": stream,
                "retry_every_sec": self.conn_retry_every,
            })
            await asyncio.sleep(self.conn_retry_every)

    async def write_chunk(self, flow: FlowKey, direction: str, data: bytes) -> Dict[str, Any]:
        if not data:
            return {"sent": 0, "dropped": 0, "targets": 0}

        so = await self.ensure_session(flow)
        stream = self.map_stream(direction)
        targets = so.all_targets_for(stream)

        if not targets:
            return {"sent": 0, "dropped": len(data), "targets": 0, "reason": "no_targets"}

        sent = 0
        dropped = 0
        for tw in targets:
            if tw.is_closing():
                dropped += len(data)
                continue
            if tw.buffer_size() > self.max_output_buffer:
                dropped += len(data)
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
                try:
                    tw.writer.close()
                except Exception:
                    pass

        return {"sent": sent, "dropped": dropped, "targets": len(targets)}


# =============================================================================
# Control plane (single TCP connection, JSON lines)
# =============================================================================

class ControlPlane:
    def __init__(self, *, bind_ip: str, port: int, log: logging.Logger) -> None:
        self.bind_ip = bind_ip
        self.port = port
        self.log = log
        self._server: Optional[asyncio.base_events.Server] = None
        self._client_lock = asyncio.Lock()
        self._client_writer: Optional[asyncio.StreamWriter] = None
        self._client_task: Optional[asyncio.Task] = None
        self._events: "asyncio.Queue[Dict[str, Any]]" = asyncio.Queue(maxsize=5000)

        self.bytes_out = 0
        self.events_dropped = 0

        self._get_stats_cb = None  # type: ignore
        self._close_session_cb = None  # type: ignore

    def set_callbacks(self, *, get_stats, close_session) -> None:
        self._get_stats_cb = get_stats
        self._close_session_cb = close_session

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle_client, host=self.bind_ip, port=self.port)
        self.log.info("control plane listening on %s:%d", self.bind_ip, self.port)
        asyncio.create_task(self._event_pump())

    async def close(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        async with self._client_lock:
            if self._client_writer:
                try:
                    self._client_writer.close()
                except Exception:
                    pass
                self._client_writer = None
            if self._client_task:
                self._client_task.cancel()

    async def emit(self, ev: Dict[str, Any]) -> None:
        try:
            self._events.put_nowait(ev)
        except asyncio.QueueFull:
            self.events_dropped += 1

    async def _event_pump(self) -> None:
        while True:
            ev = await self._events.get()
            async with self._client_lock:
                w = self._client_writer
                if not w or w.transport.is_closing():
                    continue
                try:
                    line = json_dumps_line(ev)
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
            if self._client_writer and not self._client_writer.transport.is_closing():
                try:
                    self._client_writer.close()
                except Exception:
                    pass
            self._client_writer = writer

        await self.emit({"ts": utc_iso(), "event": "control_connected", "peer": str(peer)})

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
                    await self.emit({"ts": utc_iso(), "event": "control_error", "error": "bad_json"})
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
            await self.emit({"ts": utc_iso(), "event": "control_disconnected", "peer": str(peer)})

    async def _handle_cmd(self, cmd: Dict[str, Any]) -> None:
        c = str(cmd.get("cmd", "")).lower().strip()
        if c in ("ping", "hello"):
            await self.emit({"ts": utc_iso(), "event": "control_reply", "reply_to": c, "ok": True})
            return
        if c in ("stats", "get_stats"):
            s = self._get_stats_cb() if self._get_stats_cb else {}
            await self.emit({"ts": utc_iso(), "event": "control_reply", "reply_to": c, "stats": s})
            return
        if c in ("close_session", "close"):
            sid = cmd.get("session_id")
            if sid is None:
                await self.emit({"ts": utc_iso(), "event": "control_reply", "reply_to": c, "ok": False, "error": "missing_session_id"})
                return
            ok = await self._close_session_cb(int(sid), reason="control_close") if self._close_session_cb else False
            await self.emit({"ts": utc_iso(), "event": "control_reply", "reply_to": c, "ok": bool(ok), "session_id": int(sid)})
            return
        await self.emit({"ts": utc_iso(), "event": "control_reply", "reply_to": c, "ok": False, "error": "unknown_cmd"})


# =============================================================================
# Capture (Scapy sniff in a dedicated thread)
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
            return

    def run(self) -> None:
        self.log.info("capture starting iface=%s bpf=%s", self.iface, self.bpf)

        def _cb(pkt) -> None:
            if self._stop.is_set():
                raise KeyboardInterrupt()

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
            except KeyboardInterrupt:
                raise
            except Exception:
                return

        try:
            sniff(
                iface=self.iface,
                filter=self.bpf,
                prn=_cb,
                store=False,
            )
        except KeyboardInterrupt:
            self.log.info("capture stopping")
        except Exception as e:
            self.log.error("capture error: %r", e)
        finally:
            self.log.info("capture stopped")


# =============================================================================
# Main service
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

        # If local_port is set but not used in template, enforce it as tcp port filter
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

        ctrl = get_path(cfg, "control", {}) or {}
        self.control_bind_ip = str(ctrl.get("bind_ip", "0.0.0.0"))
        self.control_port = int(ctrl.get("listen_port", 50005) or 50005)

        self.control = ControlPlane(bind_ip=self.control_bind_ip, port=self.control_port, log=log)
        self.outputs = OutputManager(cfg=cfg, control=self.control, log=log)

        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.forward_q: "asyncio.Queue[ForwardChunk]" = asyncio.Queue(maxsize=20000)
        self.event_q: "asyncio.Queue[SessionEvent]" = asyncio.Queue(maxsize=20000)

        self.worker_inqs: List["queue.Queue[PacketInfo]"] = []
        self.workers_threads: List[ReassemblyWorker] = []
        self.capture: Optional[CaptureThread] = None

        self._session_meta: Dict[int, Dict[str, Any]] = {}
        self._bytes_forwarded = 0
        self._bytes_dropped = 0
        self._chunks_forwarded = 0
        self._chunks_dropped = 0

        self.stats_interval_sec = float(get_path(cfg, "runtime.stats_interval_sec", 5) or 5)

    def stats_snapshot(self) -> Dict[str, Any]:
        return {
            "ts": utc_iso(),
            "workers": self.workers,
            "sessions": len(self._session_meta),
            "bytes_forwarded": self._bytes_forwarded,
            "bytes_dropped": self._bytes_dropped,
            "chunks_forwarded": self._chunks_forwarded,
            "chunks_dropped": self._chunks_dropped,
            "control_bytes_out": self.control.bytes_out,
            "control_events_dropped": self.control.events_dropped,
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
        self.control.set_callbacks(get_stats=self.stats_snapshot, close_session=self.close_session_by_id)
        await self.control.start()

        asyncio.create_task(self._consume_events())
        asyncio.create_task(self._consume_forward())
        asyncio.create_task(self._periodic_stats())

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
                log=self.log,
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

        await self.control.emit({
            "ts": utc_iso(),
            "event": "service_started",
            "iface": self.iface,
            "bpf": self.bpf,
            "workers": self.workers,
        })

    async def stop(self) -> None:
        await self.control.emit({"ts": utc_iso(), "event": "service_stopping"})
        if self.capture:
            self.capture.stop()
        for w in self.workers_threads:
            w.stop()
        await self.control.close()
        for fk in list(self.outputs.sessions.keys()):
            try:
                await self.outputs.close_session(fk, reason="service_stop")
            except Exception:
                pass

    async def _periodic_stats(self) -> None:
        while True:
            await asyncio.sleep(self.stats_interval_sec)
            await self.control.emit({"ts": utc_iso(), "event": "stats", **self.stats_snapshot()})

    async def _consume_events(self) -> None:
        while True:
            ev = await self.event_q.get()
            sid = ev.flow.session_id
            if ev.kind == "open":
                self._session_meta[sid] = {"flow": ev.flow.to_dict(), "open_ts": ev.ts}
                await self.outputs.ensure_session(ev.flow)
                await self.control.emit({"ts": utc_iso(), "event": "tcp_open", "flow": ev.flow.to_dict()})
            elif ev.kind == "close":
                self._session_meta.pop(sid, None)
                await self.outputs.close_session(ev.flow, reason=ev.data.get("reason", "close"))
                await self.control.emit({
                    "ts": utc_iso(),
                    "event": "tcp_close",
                    "flow": ev.flow.to_dict(),
                    "reason": ev.data.get("reason"),
                })
            else:
                await self.control.emit({"ts": utc_iso(), "event": "tcp_note", "flow": ev.flow.to_dict(), **ev.data})

    async def _consume_forward(self) -> None:
        while True:
            ch = await self.forward_q.get()
            try:
                res = await self.outputs.write_chunk(ch.flow, ch.direction, ch.data)
                if res.get("sent", 0) > 0:
                    self._bytes_forwarded += res["sent"]
                    self._chunks_forwarded += 1
                if res.get("dropped", 0) > 0:
                    self._bytes_dropped += res["dropped"]
                    self._chunks_dropped += 1
                if res.get("dropped", 0) and (res.get("sent", 0) == 0 or res.get("targets", 0) == 0):
                    await self.control.emit({
                        "ts": utc_iso(),
                        "event": "drop",
                        "flow": ch.flow.to_dict(),
                        "direction": ch.direction,
                        "stream": self.outputs.map_stream(ch.direction),
                        "bytes": len(ch.data),
                        "reason": res.get("reason", "output_backpressure_or_unready"),
                        "targets": res.get("targets", 0),
                    })
            except Exception as e:
                await self.control.emit({
                    "ts": utc_iso(),
                    "event": "forward_error",
                    "flow": ch.flow.to_dict(),
                    "direction": ch.direction,
                    "error": repr(e),
                })


# =============================================================================
# CLI + entrypoint
# =============================================================================

def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="BPF TCP capture + reassembly + forwarding (prototype)")
    p.add_argument("--config", required=True, help="Path to JSON (or json-ish) config file")
    p.add_argument("--log-level", default="INFO", help="DEBUG/INFO/WARNING/ERROR")
    return p


async def amain(args: argparse.Namespace) -> int:
    log = logging.getLogger("bpf_tcp_relay")
    log.setLevel(getattr(logging, str(args.log_level).upper(), logging.INFO))
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(h)

    cfg = load_config(args.config)

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
    await svc.stop()
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
