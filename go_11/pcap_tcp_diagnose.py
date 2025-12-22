#!/usr/bin/env python3
"""
pcap_tcp_diagnose.py

Pure-Python TCP diagnostics for PCAP/PCAPNG (no tshark).

What it does (best-effort, capture-based inference):
- Enumerates TCP flows (bidirectional 4-tuple).
- Tracks per-direction sequence/ACK progress with 32-bit unwrap.
- Estimates bytes-in-flight and compares with advertised receive window (rwnd).
- Detects:
  * receiver-window backpressure: rwnd==0, tiny rwnd, draining rwnd trend, sustained rwnd-limited flight ("window full")
  * duplicate ACKs ("dupACKs"), dupACK streaks
  * retransmissions (exact seq+len repeats), and "fast retrans" heuristic (retrans after >=3 dupACKs)
  * out-of-order arrivals (reordering symptoms)
  * RTO-ish retrans heuristic (retrans after long delay vs RTT baseline)
- Reports per-flow summary + findings. Optional JSON output.

Notes (important reality check):
- cwnd is NOT carried on the wire; we cannot read it from a capture.
  We provide an estimate proxy: peak bytes-in-flight during "clean" periods,
  and classify likely limitation source (rwnd vs loss vs app-limited) heuristically.

Usage:
  python3 pcap_tcp_diagnose.py <file.pcap|file.pcapng>
  python3 pcap_tcp_diagnose.py <file> --flow 0
  python3 pcap_tcp_diagnose.py <file> --json > report.json
  python3 pcap_tcp_diagnose.py <file> --top 5

Debug:
  python3 pcap_tcp_diagnose.py <file> --debug 1
"""

from __future__ import annotations

import argparse
import collections
import dataclasses
import heapq
import json
import math
import os
import struct
import sys
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, Iterator, List, Optional, Tuple


# ----------------------------- formatting helpers -----------------------------

def die(msg: str, code: int = 2) -> None:
    sys.stderr.write(msg.rstrip() + "\n")
    raise SystemExit(code)


def fmt_num(x: Any, digits: int = 3) -> str:
    try:
        xf = float(x)
    except Exception:
        return "n/a"
    if math.isnan(xf) or math.isinf(xf):
        return "n/a"
    s = f"{xf:.{digits}f}".rstrip("0").rstrip(".")
    return s if s else "0"


def fmt_bytes(n: Any) -> str:
    try:
        n = int(n)
    except Exception:
        return "n/a"
    if n < 1024:
        return f"{n} B"
    units = ["KiB", "MiB", "GiB", "TiB"]
    v = float(n)
    for u in units:
        v /= 1024.0
        if v < 1024.0:
            return f"{fmt_num(v, 2)} {u}"
    return f"{fmt_num(v, 2)} PiB"


def fmt_rate(bps: Any) -> str:
    try:
        bps = float(bps)
    except Exception:
        return "n/a"
    if math.isnan(bps) or math.isinf(bps):
        return "n/a"
    return fmt_bytes(int(bps)) + "/s"


def quantile(xs: List[float], q: float) -> float:
    if not xs:
        return float("nan")
    xs = sorted(xs)
    if len(xs) == 1:
        return float(xs[0])
    pos = (len(xs) - 1) * q
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    if lo == hi:
        return float(xs[lo])
    w = pos - lo
    return float(xs[lo] * (1 - w) + xs[hi] * w)


# ----------------------------- PCAP / PCAPNG reader -----------------------------

DLT_EN10MB = 1
DLT_RAW = 101
DLT_LINUX_SLL = 113

PCAP_MAGIC_USEC_LE = 0xA1B2C3D4
PCAP_MAGIC_USEC_BE = 0xD4C3B2A1
PCAP_MAGIC_NSEC_LE = 0xA1B23C4D
PCAP_MAGIC_NSEC_BE = 0x4D3CB2A1

PCAPNG_BLOCK_SHB = 0x0A0D0D0A
PCAPNG_BLOCK_IDB = 0x00000001
PCAPNG_BLOCK_SPB = 0x00000003
PCAPNG_BLOCK_EPB = 0x00000006

PCAPNG_OPT_IF_TSRESOL = 9
PCAPNG_OPT_IF_TSOFFSET = 14


def _read_exact(f, n: int) -> bytes:
    b = f.read(n)
    if len(b) != n:
        raise EOFError
    return b


def _u16(endian: str, b: bytes, off: int = 0) -> int:
    return struct.unpack(endian + "H", b[off:off+2])[0]


def _u32(endian: str, b: bytes, off: int = 0) -> int:
    return struct.unpack(endian + "I", b[off:off+4])[0]


def _u64(endian: str, b: bytes, off: int = 0) -> int:
    return struct.unpack(endian + "Q", b[off:off+8])[0]


def _pad4(n: int) -> int:
    return (n + 3) & ~3


@dataclass
class CapturePacket:
    frame_no: int
    ts: float
    linktype: int
    data: bytes


class PcapReader:
    def __init__(self, path: str):
        self.path = path
        self._f = open(path, "rb")
        self._mode = None  # "pcap" or "pcapng"
        self._pcap_endian = "<"
        self._pcap_nsec = False
        self._pcap_linktype = None

        # pcapng state
        self._ng_endian = "<"
        self._ng_if_linktype: Dict[int, int] = {}
        self._ng_if_tsresol: Dict[int, float] = {}   # seconds per tick
        self._ng_if_tsoffset: Dict[int, float] = {}  # seconds offset

        self._init()

    def close(self) -> None:
        try:
            self._f.close()
        except Exception:
            pass

    def __enter__(self) -> "PcapReader":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _init(self) -> None:
        head = self._f.read(4)
        if len(head) < 4:
            die("Empty file.")
        magic = struct.unpack("<I", head)[0]

        if magic == PCAPNG_BLOCK_SHB:
            self._mode = "pcapng"
            # rewind and parse SHB to determine endian
            self._f.seek(0)
            self._read_pcapng_shb()
            return

        # classic pcap
        self._mode = "pcap"
        # Determine endian / ts resolution.
        magic_le = struct.unpack("<I", head)[0]
        magic_be = struct.unpack(">I", head)[0]

        if magic_le in (PCAP_MAGIC_USEC_LE, PCAP_MAGIC_NSEC_LE):
            self._pcap_endian = "<"
            self._pcap_nsec = (magic_le == PCAP_MAGIC_NSEC_LE)
        elif magic_be in (PCAP_MAGIC_USEC_LE, PCAP_MAGIC_NSEC_LE):
            self._pcap_endian = ">"
            self._pcap_nsec = (magic_be == PCAP_MAGIC_NSEC_LE)
        elif magic_le in (PCAP_MAGIC_USEC_BE, PCAP_MAGIC_NSEC_BE):
            # swapped magic means opposite endian interpretation
            self._pcap_endian = ">"
            self._pcap_nsec = (magic_le == PCAP_MAGIC_NSEC_BE)
        elif magic_be in (PCAP_MAGIC_USEC_BE, PCAP_MAGIC_NSEC_BE):
            self._pcap_endian = "<"
            self._pcap_nsec = (magic_be == PCAP_MAGIC_NSEC_BE)
        else:
            die(f"Unrecognized PCAP/PCAPNG magic: 0x{magic:08x}")

        # read rest global header
        rest = _read_exact(self._f, 20)
        gh = head + rest
        # pcap global header layout:
        # magic(4) version_major(2) version_minor(2) thiszone(4) sigfigs(4) snaplen(4) network(4)
        network = _u32(self._pcap_endian, gh, 20)
        self._pcap_linktype = network

    def _read_pcapng_shb(self) -> None:
        # SHB block: type(4) total_len(4) bom(4) major(2) minor(2) section_len(8) ... options ... total_len(4)
        # Need endian: BOM is 0x1A2B3C4D in host endian.
        hdr = _read_exact(self._f, 8)
        block_type_le = struct.unpack("<I", hdr[:4])[0]
        if block_type_le != PCAPNG_BLOCK_SHB:
            die("PCAPNG: first block is not SHB.")
        total_len_le = struct.unpack("<I", hdr[4:8])[0]
        total_len_be = struct.unpack(">I", hdr[4:8])[0]

        def read_block(total_len: int) -> bytes:
            if total_len < 12 or total_len % 4 != 0:
                raise ValueError
            body = _read_exact(self._f, total_len - 8)
            return hdr + body

        # try LE first, then BE
        pos0 = self._f.tell()
        blk = None
        endian = None
        for cand_len, cand_endian in ((total_len_le, "<"), (total_len_be, ">")):
            try:
                self._f.seek(pos0)
                blk = read_block(cand_len)
            except Exception:
                continue
            # check trailing len matches
            trail = struct.unpack(cand_endian + "I", blk[-4:])[0]
            if trail != cand_len:
                continue
            bom = struct.unpack(cand_endian + "I", blk[8:12])[0]
            if bom == 0x1A2B3C4D:
                endian = cand_endian
                break

        if blk is None or endian is None:
            die("PCAPNG: could not determine endianness from SHB.")

        self._ng_endian = endian
        # SHB options ignored; we just set endian and continue.

    def __iter__(self) -> Iterator[CapturePacket]:
        if self._mode == "pcap":
            yield from self._iter_pcap()
        else:
            yield from self._iter_pcapng()

    def _iter_pcap(self) -> Iterator[CapturePacket]:
        endian = self._pcap_endian
        nsec = self._pcap_nsec
        linktype = int(self._pcap_linktype or 0)

        # per-packet header: ts_sec(4) ts_usec/nsec(4) incl_len(4) orig_len(4)
        frame_no = 0
        while True:
            hdr = self._f.read(16)
            if not hdr:
                return
            if len(hdr) != 16:
                return
            ts_sec = _u32(endian, hdr, 0)
            ts_sub = _u32(endian, hdr, 4)
            incl_len = _u32(endian, hdr, 8)
            _ = _u32(endian, hdr, 12)
            data = self._f.read(incl_len)
            if len(data) != incl_len:
                return
            ts = ts_sec + (ts_sub / (1e9 if nsec else 1e6))
            frame_no += 1
            yield CapturePacket(frame_no=frame_no, ts=ts, linktype=linktype, data=data)

    def _parse_idb_options(self, iface_id: int, opts: bytes) -> None:
        endian = self._ng_endian
        off = 0
        tsresol = None
        tsoffset = 0.0

        while off + 4 <= len(opts):
            opt_code = _u16(endian, opts, off)
            opt_len = _u16(endian, opts, off + 2)
            off += 4
            if opt_code == 0:
                break
            val = opts[off:off + opt_len]
            off += _pad4(opt_len)
            if opt_code == PCAPNG_OPT_IF_TSRESOL and opt_len >= 1:
                b = val[0]
                if b & 0x80:
                    # base 2
                    p = b & 0x7F
                    tsresol = 2.0 ** (-p)
                else:
                    # base 10
                    tsresol = 10.0 ** (-b)
            elif opt_code == PCAPNG_OPT_IF_TSOFFSET and opt_len == 8:
                # signed 64? spec says unsigned 64 seconds offset; treat as unsigned.
                tsoffset = float(_u64(endian, val, 0))

        if tsresol is None:
            # default per spec: 10^-6
            tsresol = 1e-6

        self._ng_if_tsresol[iface_id] = float(tsresol)
        self._ng_if_tsoffset[iface_id] = float(tsoffset)

    def _iter_pcapng(self) -> Iterator[CapturePacket]:
        endian = self._ng_endian
        iface_id_counter = 0
        frame_no = 0

        while True:
            hdr = self._f.read(8)
            if not hdr:
                return
            if len(hdr) != 8:
                return
            block_type = _u32(endian, hdr, 0)
            total_len = _u32(endian, hdr, 4)
            if total_len < 12 or total_len % 4 != 0:
                return
            body = _read_exact(self._f, total_len - 8)
            blk = hdr + body
            # trailing length sanity
            if _u32(endian, blk, total_len - 4) != total_len:
                # corrupt or wrong endian
                return

            # body excluding trailing len
            b = blk[8:total_len - 4]

            if block_type == PCAPNG_BLOCK_SHB:
                # start of a new section; endian should remain same for most captures
                # (we won't re-negotiate here)
                continue

            if block_type == PCAPNG_BLOCK_IDB:
                # linktype(2) reserved(2) snaplen(4) options...
                if len(b) < 8:
                    continue
                linktype = struct.unpack(endian + "H", b[0:2])[0]
                # snaplen = _u32(endian, b, 4)
                opts = b[8:]
                iface_id = iface_id_counter
                iface_id_counter += 1
                self._ng_if_linktype[iface_id] = int(linktype)
                self._parse_idb_options(iface_id, opts)
                continue

            if block_type == PCAPNG_BLOCK_EPB:
                # interface_id(4) ts_high(4) ts_low(4) caplen(4) pktlen(4) data... options...
                if len(b) < 20:
                    continue
                iface = _u32(endian, b, 0)
                ts_high = _u32(endian, b, 4)
                ts_low = _u32(endian, b, 8)
                caplen = _u32(endian, b, 12)
                # pktlen = _u32(endian, b, 16)
                pkt_off = 20
                pkt_end = pkt_off + caplen
                if pkt_end > len(b):
                    continue
                pkt_data = b[pkt_off:pkt_end]
                # options start at padded end, but we ignore
                tsresol = self._ng_if_tsresol.get(iface, 1e-6)
                tsoffset = self._ng_if_tsoffset.get(iface, 0.0)
                ts_ticks = (ts_high << 32) | ts_low
                ts = tsoffset + (ts_ticks * tsresol)
                linktype = self._ng_if_linktype.get(iface, DLT_EN10MB)
                frame_no += 1
                yield CapturePacket(frame_no=frame_no, ts=float(ts), linktype=int(linktype), data=pkt_data)
                continue

            if block_type == PCAPNG_BLOCK_SPB:
                # pktlen(4) data...
                if len(b) < 4:
                    continue
                pktlen = _u32(endian, b, 0)
                pkt_data = b[4:4 + pktlen]
                # SPB doesn't include timestamp; can't do much. We'll skip.
                # (Most modern captures use EPB.)
                continue

            # other blocks ignored


# ----------------------------- packet parsing -----------------------------

@dataclass
class TcpPacket:
    frame_no: int
    ts: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    seq: int
    ack: int
    flags: int
    win: int
    data_offset: int
    payload_len: int
    syn: bool
    fin: bool
    rst: bool
    ack_flag: bool
    mss: Optional[int] = None
    wscale: Optional[int] = None


TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
TCP_ECE = 0x40
TCP_CWR = 0x80


def _ip4_to_str(b: bytes) -> str:
    return ".".join(str(x) for x in b)


def _ip6_to_str(b: bytes) -> str:
    # minimal: hex groups
    parts = [b[i:i+2] for i in range(0, 16, 2)]
    return ":".join(f"{(p[0]<<8)|p[1]:x}" for p in parts)


def parse_ethernet(pkt: bytes) -> Tuple[int, bytes]:
    if len(pkt) < 14:
        return (0, b"")
    eth_type = struct.unpack("!H", pkt[12:14])[0]
    return (eth_type, pkt[14:])


def parse_linux_sll(pkt: bytes) -> Tuple[int, bytes]:
    # Linux cooked capture v1: 16 bytes header; protocol at offset 14
    if len(pkt) < 16:
        return (0, b"")
    proto = struct.unpack("!H", pkt[14:16])[0]
    return (proto, pkt[16:])


def parse_ipv4(pkt: bytes) -> Optional[Tuple[str, str, int, bytes]]:
    if len(pkt) < 20:
        return None
    v_ihl = pkt[0]
    ver = v_ihl >> 4
    if ver != 4:
        return None
    ihl = (v_ihl & 0x0F) * 4
    if ihl < 20 or len(pkt) < ihl:
        return None
    proto = pkt[9]
    src = _ip4_to_str(pkt[12:16])
    dst = _ip4_to_str(pkt[16:20])
    return (src, dst, proto, pkt[ihl:])


def parse_ipv6(pkt: bytes) -> Optional[Tuple[str, str, int, bytes]]:
    if len(pkt) < 40:
        return None
    ver = pkt[0] >> 4
    if ver != 6:
        return None
    nxt = pkt[6]
    src = _ip6_to_str(pkt[8:24])
    dst = _ip6_to_str(pkt[24:40])
    return (src, dst, nxt, pkt[40:])


def parse_tcp_options(opts: bytes) -> Tuple[Optional[int], Optional[int]]:
    mss = None
    wscale = None
    i = 0
    while i < len(opts):
        kind = opts[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        if i + 2 > len(opts):
            break
        ln = opts[i + 1]
        if ln < 2 or i + ln > len(opts):
            break
        val = opts[i + 2:i + ln]
        if kind == 2 and ln == 4:
            mss = struct.unpack("!H", val)[0]
        elif kind == 3 and ln == 3:
            wscale = val[0]
        i += ln
    return mss, wscale


def parse_tcp(frame_no: int, ts: float, src_ip: str, dst_ip: str, payload: bytes) -> Optional[TcpPacket]:
    if len(payload) < 20:
        return None
    src_port, dst_port, seq, ack, off_flags, win = struct.unpack("!HHIIHH", payload[:16])
    data_offset = ((off_flags >> 12) & 0xF) * 4
    flags = off_flags & 0x01FF  # includes NS? ignore
    if data_offset < 20 or len(payload) < data_offset:
        return None
    opts = payload[20:data_offset]
    tcp_payload = payload[data_offset:]
    mss, wscale = parse_tcp_options(opts)

    syn = bool(flags & TCP_SYN)
    fin = bool(flags & TCP_FIN)
    rst = bool(flags & TCP_RST)
    ack_flag = bool(flags & TCP_ACK)

    return TcpPacket(
        frame_no=frame_no,
        ts=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        seq=seq,
        ack=ack,
        flags=flags,
        win=win,
        data_offset=data_offset,
        payload_len=len(tcp_payload),
        syn=syn,
        fin=fin,
        rst=rst,
        ack_flag=ack_flag,
        mss=mss,
        wscale=wscale,
    )


def iter_tcp_packets(path: str, debug: bool = False) -> Iterator[TcpPacket]:
    with PcapReader(path) as r:
        for cap in r:
            pkt = cap.data
            # linktype -> ip payload
            ip_payload = None
            proto = None
            src_ip = dst_ip = None

            if cap.linktype == DLT_EN10MB:
                eth_type, rest = parse_ethernet(pkt)
                if eth_type == 0x0800:
                    ip4 = parse_ipv4(rest)
                    if ip4:
                        src_ip, dst_ip, proto, ip_payload = ip4
                elif eth_type == 0x86DD:
                    ip6 = parse_ipv6(rest)
                    if ip6:
                        src_ip, dst_ip, proto, ip_payload = ip6
            elif cap.linktype == DLT_RAW:
                # raw IP
                if len(pkt) >= 1 and (pkt[0] >> 4) == 4:
                    ip4 = parse_ipv4(pkt)
                    if ip4:
                        src_ip, dst_ip, proto, ip_payload = ip4
                elif len(pkt) >= 1 and (pkt[0] >> 4) == 6:
                    ip6 = parse_ipv6(pkt)
                    if ip6:
                        src_ip, dst_ip, proto, ip_payload = ip6
            elif cap.linktype == DLT_LINUX_SLL:
                proto_eth, rest = parse_linux_sll(pkt)
                if proto_eth == 0x0800:
                    ip4 = parse_ipv4(rest)
                    if ip4:
                        src_ip, dst_ip, proto, ip_payload = ip4
                elif proto_eth == 0x86DD:
                    ip6 = parse_ipv6(rest)
                    if ip6:
                        src_ip, dst_ip, proto, ip_payload = ip6
            else:
                # unsupported linktype
                continue

            if proto != 6 or not ip_payload or not src_ip or not dst_ip:
                continue

            t = parse_tcp(cap.frame_no, cap.ts, src_ip, dst_ip, ip_payload)
            if t:
                yield t


# ----------------------------- TCP flow state -----------------------------

class SeqUnwrapper:
    def __init__(self) -> None:
        self.inited = False
        self.last32 = 0
        self.last_abs = 0

    def unwrap(self, x32: int) -> int:
        x32 &= 0xFFFFFFFF
        if not self.inited:
            self.inited = True
            self.last32 = x32
            self.last_abs = x32
            return x32
        diff = (x32 - self.last32) & 0xFFFFFFFF
        if diff > 0x7FFFFFFF:
            diff -= 0x100000000
        self.last_abs += diff
        self.last32 = x32
        return self.last_abs


@dataclass
class AckTracker:
    last_ack_rel: Optional[int] = None
    last_win_scaled: Optional[int] = None
    dup_streak: int = 0
    dup_total: int = 0
    dup_frames: List[int] = field(default_factory=list)
    dup_events: List[Tuple[int, float]] = field(default_factory=list)  # (frame_no, ts)


@dataclass
class DirectionState:
    sender: Tuple[str, int]
    receiver: Tuple[str, int]

    isn_abs: Optional[int] = None
    unwrap: SeqUnwrapper = field(default_factory=SeqUnwrapper)

    ws_shift: Optional[int] = None  # window scale shift for *sender* when it advertises window
    mss: Optional[int] = None

    sent_payload_bytes: int = 0

    # seq-space tracking
    highest_acked: int = 0
    max_sent_end: int = 0

    # retrans / ordering
    seen_seg_first_ts: Dict[Tuple[int, int], float] = field(default_factory=dict)  # (start_rel, seglen)->first_ts
    seen_seg_first_frame: Dict[Tuple[int, int], int] = field(default_factory=dict)  # (start_rel, seglen)->first_frame
    retrans_total: int = 0
    fast_retrans_total: int = 0
    rto_retrans_total: int = 0
    out_of_order_total: int = 0

    # dupack tracking (ACKs sent by receiver for this direction)
    ack_tracker_from_receiver: AckTracker = field(default_factory=AckTracker)

    # samples (downsampled)
    inflight_samples: List[int] = field(default_factory=list)
    rwnd_samples: List[int] = field(default_factory=list)
    rwnd_zero_count: int = 0
    rwnd_tiny_count: int = 0
    window_full_samples: int = 0

    # sample metadata (aligned with rwnd_samples after downsampling)
    rwnd_sample_meta: List[Tuple[int, float]] = field(default_factory=list)  # (frame_no, ts)

    # event evidence (bounded examples)
    rwnd_zero_events: List[Tuple[int, float]] = field(default_factory=list)
    rwnd_tiny_events: List[Tuple[int, float]] = field(default_factory=list)
    window_full_events: List[Tuple[int, float]] = field(default_factory=list)
    retrans_events: List[Tuple[int, float]] = field(default_factory=list)
    fast_retrans_events: List[Tuple[int, float]] = field(default_factory=list)
    rto_retrans_events: List[Tuple[int, float]] = field(default_factory=list)
    out_of_order_events: List[Tuple[int, float]] = field(default_factory=list)

    # RTT estimation
    sent_heap: List[Tuple[int, float]] = field(default_factory=list)  # (end_rel, send_ts)
    rtt_samples: List[float] = field(default_factory=list)

    # current rwnd estimate (advertised by receiver endpoint)
    current_rwnd: Optional[int] = None

    # internal sampling limiter
    _sample_every: int = 1
    _sample_counter: int = 0

    def rel_seq(self, seq32: int) -> int:
        abs_seq = self.unwrap.unwrap(seq32)
        if self.isn_abs is None:
            self.isn_abs = abs_seq
        return abs_seq - self.isn_abs

    def note_send_segment(self, start_rel: int, seg_len_seqspace: int, ts: float) -> None:
        end_rel = start_rel + seg_len_seqspace
        self.max_sent_end = max(self.max_sent_end, end_rel)

        if seg_len_seqspace > 0:
            heapq.heappush(self.sent_heap, (end_rel, ts))

    def ack_progress(self, ack_rel: int, ts: float) -> None:
        if ack_rel <= self.highest_acked:
            return
        self.highest_acked = ack_rel

        # RTT samples: pop any sent ends <= ack
        # (best-effort; out-of-order may make this noisy)
        popped = 0
        while self.sent_heap and self.sent_heap[0][0] <= ack_rel:
            end_rel, sent_ts = heapq.heappop(self.sent_heap)
            rtt = ts - sent_ts
            if 0 <= rtt < 120:
                self.rtt_samples.append(rtt)
            popped += 1
            if popped > 1024:
                break  # avoid pathological loops

    def update_inflight(self, frame_no: int, ts: float) -> None:
        inflight = max(0, self.max_sent_end - self.highest_acked)
        # downsample if needed
        self._sample_counter += 1
        if self._sample_counter >= self._sample_every:
            self._sample_counter = 0
            self.inflight_samples.append(inflight)
            # dynamic downsample to keep memory bounded
            if len(self.inflight_samples) > 50000:
                self.inflight_samples = self.inflight_samples[::2]
                self._sample_every *= 2

        # window full heuristic
        if self.current_rwnd is not None and self.current_rwnd > 0:
            if inflight >= int(0.9 * self.current_rwnd):
                self.window_full_samples += 1
                if len(self.window_full_events) < 20:
                    self.window_full_events.append((int(frame_no), float(ts)))

    def update_rwnd_from_receiver_advertisement(self, rwnd: int, frame_no: int, ts: float) -> None:
        self.current_rwnd = int(rwnd)
        self.rwnd_samples.append(int(rwnd))
        self.rwnd_sample_meta.append((int(frame_no), float(ts)))
        if rwnd == 0:
            self.rwnd_zero_count += 1
            if len(self.rwnd_zero_events) < 20:
                self.rwnd_zero_events.append((int(frame_no), float(ts)))
        if 0 < rwnd < 16 * 1024:
            self.rwnd_tiny_count += 1
            if len(self.rwnd_tiny_events) < 20:
                self.rwnd_tiny_events.append((int(frame_no), float(ts)))
        if len(self.rwnd_samples) > 50000:
            self.rwnd_samples = self.rwnd_samples[::2]
            self.rwnd_sample_meta = self.rwnd_sample_meta[::2]
    def est_srtt(self) -> Optional[float]:
        if len(self.rtt_samples) < 5:
            return None
        # robust-ish: median
        xs = sorted(self.rtt_samples)
        return float(xs[len(xs) // 2])


@dataclass
class FlowState:
    flow_id: int
    a: Tuple[str, int]
    b: Tuple[str, int]

    # per-endpoint window scaling shift (applies to that endpoint's advertised window)
    ws_shift: Dict[Tuple[str, int], int] = field(default_factory=dict)
    mss: Dict[Tuple[str, int], int] = field(default_factory=dict)

    # per-endpoint seq unwrap + isn
    unwrap: Dict[Tuple[str, int], SeqUnwrapper] = field(default_factory=dict)
    isn_abs: Dict[Tuple[str, int], int] = field(default_factory=dict)

    # per-direction (sender endpoint) state
    dir_state: Dict[Tuple[str, int], DirectionState] = field(default_factory=dict)

    # tracking time range
    t0: float = float("inf")
    t1: float = float("-inf")

    # close flags
    rst_seen: bool = False
    fin_seen: bool = False
    rst_event: Optional[Tuple[int, float]] = None  # (frame_no, ts)
    fin_event: Optional[Tuple[int, float]] = None  # (frame_no, ts)

    def duration(self) -> float:
        if self.t0 == float("inf") or self.t1 == float("-inf"):
            return 0.0
        return max(0.0, self.t1 - self.t0)

    def get_dir(self, sender: Tuple[str, int], receiver: Tuple[str, int]) -> DirectionState:
        d = self.dir_state.get(sender)
        if d is None:
            d = DirectionState(sender=sender, receiver=receiver)
            d.ws_shift = self.ws_shift.get(sender)
            d.mss = self.mss.get(sender)
            # share unwrap/ISN knowledge if already present
            if sender not in self.unwrap:
                self.unwrap[sender] = SeqUnwrapper()
            d.unwrap = self.unwrap[sender]
            if sender in self.isn_abs:
                d.isn_abs = self.isn_abs[sender]
            self.dir_state[sender] = d
        else:
            d.receiver = receiver
        return d

    def set_isn_if_syn(self, ep: Tuple[str, int], seq32: int, syn: bool) -> None:
        if ep not in self.unwrap:
            self.unwrap[ep] = SeqUnwrapper()
        abs_seq = self.unwrap[ep].unwrap(seq32)
        if syn and ep not in self.isn_abs:
            self.isn_abs[ep] = abs_seq
        # if no syn ever seen, set ISN on first sight to allow relative numbers
        if ep not in self.isn_abs:
            self.isn_abs[ep] = abs_seq

    def rel_seq(self, ep: Tuple[str, int], seq32: int) -> int:
        if ep not in self.unwrap:
            self.unwrap[ep] = SeqUnwrapper()
        abs_seq = self.unwrap[ep].unwrap(seq32)
        if ep not in self.isn_abs:
            self.isn_abs[ep] = abs_seq
        return abs_seq - self.isn_abs[ep]

    def rel_ack_for_ep(self, ack_for_sender_ep: Tuple[str, int], ack32: int) -> Optional[int]:
        # ack32 is in sender_ep's sequence space, so unwrap using sender_ep unwrap.
        if ack_for_sender_ep not in self.unwrap or ack_for_sender_ep not in self.isn_abs:
            return None
        abs_ack = self.unwrap[ack_for_sender_ep].unwrap(ack32)
        return abs_ack - self.isn_abs[ack_for_sender_ep]


# ----------------------------- analysis & reporting -----------------------------

@dataclass
class Finding:
    severity: str  # SEVERE / WARN / INFO
    direction: Optional[str]
    title: str
    details: str
    evidence: List[Dict[str, Any]] = field(default_factory=list)  # [{'frame':..,'t_rel_s':..,'t_rel_pct':..}]



def _when_from_ts(t0: float, dur: float, ts: float) -> Dict[str, Any]:
    if t0 == float('inf') or dur <= 0:
        return {'t_rel_s': None, 't_rel_pct': None}
    rel = float(ts) - float(t0)
    if rel < 0:
        rel = 0.0
    pct = (rel / dur) * 100.0 if dur > 0 else None
    return {'t_rel_s': rel, 't_rel_pct': pct}

def _evidence_from_events(t0: float, dur: float, events: List[Tuple[int, float]], max_n: int = 6) -> List[Dict[str, Any]]:
    if not events:
        return []
    # sort by ts then frame
    evs = sorted(events, key=lambda x: (x[1], x[0]))[:max_n]
    out: List[Dict[str, Any]] = []
    for fr, ts in evs:
        w = _when_from_ts(t0, dur, ts)
        out.append({'frame': int(fr), **w})
    return out

def _evidence_from_meta_indices(t0: float, dur: float, meta: List[Tuple[int, float]], idxs: List[int]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for idx in idxs:
        if idx is None:
            continue
        if 0 <= int(idx) < len(meta):
            fr, ts = meta[int(idx)]
            w = _when_from_ts(t0, dur, ts)
            out.append({'frame': int(fr), **w})
    return out

def summarize_int(xs: List[int]) -> Dict[str, Any]:
    if not xs:
        return {"count": 0}
    fx = [float(x) for x in xs]
    return {
        "count": len(xs),
        "min": int(min(xs)),
        "p50": int(quantile(fx, 0.50)),
        "p90": int(quantile(fx, 0.90)),
        "max": int(max(xs)),
    }


def summarize_float(xs: List[float]) -> Dict[str, Any]:
    if not xs:
        return {"count": 0}
    return {
        "count": len(xs),
        "p50": float(quantile(xs, 0.50)),
        "p90": float(quantile(xs, 0.90)),
        "max": float(max(xs)),
        "mean": float(sum(xs) / len(xs)),
    }


def detect_draining_window(rwnd: List[int]) -> Tuple[bool, str, Optional[int], Optional[int]]:
    if len(rwnd) < 100:
        return False, "", None, None
    n = len(rwnd)
    early_len = max(20, n // 4)
    late_len = max(20, n // 4)
    early = rwnd[:early_len]
    late = rwnd[-late_len:]
    e = quantile([float(x) for x in early], 0.50)
    l = quantile([float(x) for x in late], 0.50)
    if l < e * 0.6 and l < 32 * 1024:
        e_idx = max(0, early_len // 2)
        l_idx = max(0, (n - late_len) + (late_len // 2))
        return True, f"rwnd median drifted down {int(e)}→{int(l)} bytes", e_idx, l_idx
    return False, "", None, None

def classify_direction(d: DirectionState) -> Tuple[str, List[str]]:
    rationale: List[str] = []
    rwnd_score = 0
    loss_score = 0
    app_score = 0

    if d.rwnd_zero_count > 0:
        rwnd_score += 3
        rationale.append("zero rwnd observed")
    if d.window_full_samples > 50:
        rwnd_score += 2
        rationale.append("sustained inflight near rwnd (window-full proxy)")
    draining, drain_msg, drain_e_idx, drain_l_idx = detect_draining_window(d.rwnd_samples)
    if draining:
        rwnd_score += 2
        rationale.append(drain_msg)
    if d.rwnd_tiny_count > 200:
        rwnd_score += 1
        rationale.append("frequent tiny rwnd (<16KiB)")

    if d.retrans_total > 0:
        loss_score += 1
        rationale.append("retransmissions observed")
    if d.fast_retrans_total > 0:
        loss_score += 2
        rationale.append("fast retrans heuristic observed")
    if d.rto_retrans_total > 0:
        loss_score += 3
        rationale.append("RTO-ish retrans heuristic observed")
    if d.ack_tracker_from_receiver.dup_total > 200:
        loss_score += 1
        rationale.append("many dupACKs")

    if d.rwnd_samples and d.inflight_samples and rwnd_score == 0 and loss_score == 0:
        rwnd_med = quantile([float(x) for x in d.rwnd_samples], 0.50)
        infl_p90 = quantile([float(x) for x in d.inflight_samples], 0.90)
        if rwnd_med > 256 * 1024 and infl_p90 < 0.2 * rwnd_med:
            app_score += 2
            rationale.append("large rwnd but low inflight (likely app-limited)")

    if rwnd_score >= max(loss_score, app_score) and rwnd_score >= 2:
        return "rwnd_limited", rationale
    if loss_score >= max(rwnd_score, app_score) and loss_score >= 2:
        return "loss_or_congestion", rationale
    if app_score >= max(rwnd_score, loss_score) and app_score >= 2:
        return "app_limited", rationale
    return "unknown", rationale


def analyze_file(path: str, flow_filter: Optional[int], top_n: int, debug: bool) -> List[Dict[str, Any]]:
    flows: Dict[Tuple[Tuple[str, int], Tuple[str, int]], FlowState] = {}
    flow_id_counter = 0

    for p in iter_tcp_packets(path, debug=debug):
        frame_no = int(p.frame_no)
        src = (p.src_ip, p.src_port)
        dst = (p.dst_ip, p.dst_port)
        key = tuple(sorted([src, dst], key=lambda x: (x[0], x[1])))

        fs = flows.get(key)
        if fs is None:
            fs = FlowState(flow_id=flow_id_counter, a=key[0], b=key[1])
            flows[key] = fs
            flow_id_counter += 1

        fs.t0 = min(fs.t0, p.ts)
        fs.t1 = max(fs.t1, p.ts)
        if p.rst:
            fs.rst_seen = True
            if fs.rst_event is None:
                fs.rst_event = (int(frame_no), float(p.ts))
        if p.fin:
            fs.fin_seen = True
            if fs.fin_event is None:
                fs.fin_event = (int(frame_no), float(p.ts))

        # record ISN (or first seq) per endpoint
        fs.set_isn_if_syn(src, p.seq, syn=p.syn)

        # TCP options in SYN configure scaling/mss for the sender endpoint
        if p.syn:
            if p.wscale is not None and src not in fs.ws_shift:
                fs.ws_shift[src] = int(p.wscale)
            if p.mss is not None and src not in fs.mss:
                fs.mss[src] = int(p.mss)

        # ensure direction state exists for both senders
        d_send = fs.get_dir(src, dst)
        d_peer = fs.get_dir(dst, src)

        # refresh cached ws/mss into direction objects
        d_send.ws_shift = fs.ws_shift.get(src, d_send.ws_shift)
        d_peer.ws_shift = fs.ws_shift.get(dst, d_peer.ws_shift)
        d_send.mss = fs.mss.get(src, d_send.mss)
        d_peer.mss = fs.mss.get(dst, d_peer.mss)

        # seq-relative for sender
        start_rel = fs.rel_seq(src, p.seq)

        seg_len_seqspace = p.payload_len
        if p.syn:
            seg_len_seqspace += 1
        if p.fin:
            seg_len_seqspace += 1

        # advertised rwnd from src endpoint, scaled by src shift (if known)
        shift = fs.ws_shift.get(src, 0)
        rwnd_scaled = int(p.win) * (1 << int(shift))
        # this advertised rwnd limits dst->src direction (sender=dst)
        d_limited = d_peer  # dst sender state (because d_peer.sender == dst)
        d_limited.update_rwnd_from_receiver_advertisement(rwnd_scaled, frame_no, p.ts)

        # ACK processing: ack acknowledges dst->src direction (sender=dst)
        if p.ack_flag:
            ack_rel = fs.rel_ack_for_ep(dst, p.ack)
            if ack_rel is not None:
                d_peer.ack_progress(ack_rel, p.ts)

            # dupACK detection belongs to ACK sender (src) but references ack for peer (dst)
            # We store it in d_peer.ack_tracker_from_receiver (receiver == src sends ACKs for peer == dst).
            # Here, "receiver" of direction dst->src is src, so it matches d_peer.ack_tracker_from_receiver.
            tr = d_peer.ack_tracker_from_receiver
            if ack_rel is not None and p.payload_len == 0 and (not p.syn) and (not p.fin) and (not p.rst):
                if tr.last_ack_rel is not None and ack_rel == tr.last_ack_rel:
                    # window update? if window changed, treat as update not dupack
                    if tr.last_win_scaled is not None and rwnd_scaled != tr.last_win_scaled:
                        tr.dup_streak = 0
                    else:
                        tr.dup_streak += 1
                        tr.dup_total += 1
                        if len(tr.dup_frames) < 20:
                            tr.dup_frames.append(frame_no)
                        if len(tr.dup_events) < 20:
                            tr.dup_events.append((int(frame_no), float(p.ts)))
                else:
                    tr.dup_streak = 0
                tr.last_ack_rel = ack_rel
                tr.last_win_scaled = rwnd_scaled

        # sending segment bookkeeping (for src->dst direction)
        d_send.note_send_segment(start_rel, seg_len_seqspace, p.ts)

        # retrans / out-of-order detection
        if seg_len_seqspace > 0:
            key_seg = (start_rel, seg_len_seqspace)
            first_ts = d_send.seen_seg_first_ts.get(key_seg)
            if first_ts is not None:
                # seen before => retrans or duplicate capture
                # classify fast retrans if receiver (dst) has dupACK streak >=3 for this direction (src->dst)
                # dupacks come from dst (receiver) in direction src->dst, which are tracked in d_send.ack_tracker_from_receiver.
                d_send.retrans_total += 1
                if len(d_send.retrans_events) < 20:
                    d_send.retrans_events.append((int(frame_no), float(p.ts)))
                if d_send.ack_tracker_from_receiver.dup_streak >= 3 and d_send.ack_tracker_from_receiver.last_ack_rel == start_rel:
                    d_send.fast_retrans_total += 1
                    if len(d_send.fast_retrans_events) < 20:
                        d_send.fast_retrans_events.append((int(frame_no), float(p.ts)))

                # RTO-ish retrans heuristic: retrans occurs after "long" time vs RTT baseline
                srtt = d_send.est_srtt()
                dt = p.ts - first_ts
                if srtt is not None:
                    thr = max(1.0, 4.0 * srtt)
                    if dt >= thr:
                        d_send.rto_retrans_total += 1
                        if len(d_send.rto_retrans_events) < 20:
                            d_send.rto_retrans_events.append((int(frame_no), float(p.ts)))
                else:
                    if dt >= 1.0:
                        d_send.rto_retrans_total += 1
            else:
                d_send.seen_seg_first_ts[key_seg] = p.ts
                d_send.seen_seg_first_frame[key_seg] = int(frame_no)

            # out-of-order heuristic: start_rel < max_sent_end but not a known retrans yet
            if start_rel < d_send.max_sent_end - seg_len_seqspace and first_ts is None:
                d_send.out_of_order_total += 1
                if len(d_send.out_of_order_events) < 20:
                    d_send.out_of_order_events.append((int(frame_no), float(p.ts)))

            d_send.sent_payload_bytes += p.payload_len

        # update inflight samples for both directions (cheap)
        d_send.update_inflight(frame_no, p.ts)
        d_peer.update_inflight(frame_no, p.ts)

    # build reports
    reports: List[Dict[str, Any]] = []
    for _, fs in sorted(flows.items(), key=lambda kv: kv[1].flow_id):
        if flow_filter is not None and fs.flow_id != flow_filter:
            continue

        dur = fs.duration()
        dirs_out: Dict[str, Any] = {}
        findings: List[Finding] = []

        for sender_ep, d in fs.dir_state.items():
            label = f"{d.sender[0]}:{d.sender[1]} → {d.receiver[0]}:{d.receiver[1]}"

            infl = d.inflight_samples
            rwnd = d.rwnd_samples
            rtt = d.rtt_samples

            classification, rationale = classify_direction(d)

            # findings
            if d.rwnd_zero_count > 0:
                findings.append(Finding(
                    "SEVERE",
                    label,
                    "Zero rwnd observed",
                    f"Receiver advertised 0 window {d.rwnd_zero_count} times; sender should stall / persist-probe.",
                    evidence=_evidence_from_events(fs.t0, dur, d.rwnd_zero_events),
                ))
            draining, drain_msg, drain_e_idx, drain_l_idx = detect_draining_window(rwnd)
            if draining:
                findings.append(Finding("WARN", label, "Draining receive window", drain_msg, evidence=_evidence_from_meta_indices(fs.t0, dur, d.rwnd_sample_meta, [drain_e_idx, drain_l_idx])))
            if d.window_full_samples > 50:
                findings.append(Finding(
                    "WARN",
                    label,
                    "Sustained rwnd-limited flight (window-full proxy)",
                    f"inflight ≥ 0.9*rwnd for {d.window_full_samples} samples",
                    evidence=_evidence_from_events(fs.t0, dur, d.window_full_events),
                ))
            if d.ack_tracker_from_receiver.dup_total > 0:
                findings.append(Finding("INFO" if d.ack_tracker_from_receiver.dup_total < 200 else "WARN",
                                       label, "Duplicate ACKs",
                                       f"dupACK total={d.ack_tracker_from_receiver.dup_total}, example_frames={d.ack_tracker_from_receiver.dup_frames}"))
            if d.retrans_total > 0:
                findings.append(Finding(
                    "WARN",
                    label,
                    "Retransmissions",
                    f"retrans_total={d.retrans_total}, fast_retrans={d.fast_retrans_total}, rto-ish={d.rto_retrans_total}",
                    evidence=_evidence_from_events(fs.t0, dur, d.retrans_events),
                ))
            if d.out_of_order_total > 0:
                findings.append(Finding("INFO" if d.out_of_order_total < 200 else "WARN",
                                       label, "Out-of-order segments (heuristic)",
                                       f"count={d.out_of_order_total}"))

            dirs_out[label] = {
                "sender": {"ip": d.sender[0], "port": d.sender[1]},
                "receiver": {"ip": d.receiver[0], "port": d.receiver[1]},
                "payload_bytes": int(d.sent_payload_bytes),
                "payload_rate_Bps": (d.sent_payload_bytes / dur) if dur > 0 else None,
                "rwnd_summary": summarize_int(rwnd),
                "inflight_summary": summarize_int(infl),
                "rtt_summary": summarize_float(rtt),
                "dupacks_total": int(d.ack_tracker_from_receiver.dup_total),
                "retrans_total": int(d.retrans_total),
                "fast_retrans_total": int(d.fast_retrans_total),
                "rto_retrans_total": int(d.rto_retrans_total),
                "out_of_order_total": int(d.out_of_order_total),
                "window_full_samples": int(d.window_full_samples),
                "rwnd_zero_count": int(d.rwnd_zero_count),
                "rwnd_tiny_count": int(d.rwnd_tiny_count),
                "estimated_srtt_sec": d.est_srtt(),
                # cwnd proxy: peak inflight (bytes)
                "estimated_cwnd_proxy_bytes": int(max(infl) if infl else 0),
                "classification": classification,
                "classification_rationale": rationale,
            }

        if fs.rst_seen:
            findings.append(Finding("INFO", None, "RST observed", "Connection reset seen in flow.", evidence=_evidence_from_events(fs.t0, dur, [fs.rst_event] if fs.rst_event else [])))
        if fs.fin_seen:
            findings.append(Finding("INFO", None, "FIN observed", "FIN seen in flow.", evidence=_evidence_from_events(fs.t0, dur, [fs.fin_event] if fs.fin_event else [])))

        sev_order = {"SEVERE": 0, "WARN": 1, "INFO": 2}
        findings_sorted = sorted(findings, key=lambda f: (sev_order.get(f.severity, 9), f.direction or "", f.title))

        rep = {
            "flow_id": fs.flow_id,
            "endpoints": [{"ip": fs.a[0], "port": fs.a[1]}, {"ip": fs.b[0], "port": fs.b[1]}],
            "duration_sec": dur,
            "rst_seen": fs.rst_seen,
            "fin_seen": fs.fin_seen,
            "directions": dirs_out,
            "findings": [dataclasses.asdict(f) for f in findings_sorted],
        }
        reports.append(rep)

    if top_n and top_n > 0:
        def score(rep: Dict[str, Any]) -> int:
            sc = 0
            for f in rep.get("findings", []):
                sc += 100 if f["severity"] == "SEVERE" else 10 if f["severity"] == "WARN" else 1
            return sc
        reports.sort(key=score, reverse=True)
        reports = reports[:top_n]

    return reports


def print_human(reports: List[Dict[str, Any]]) -> None:
    for rep in reports:
        eps = rep.get("endpoints") or []
        ep_s = "  <->  ".join([f"{e['ip']}:{e['port']}" for e in eps]) if len(eps) == 2 else "?"
        sys.stdout.write("\n" + "=" * 78 + "\n")
        sys.stdout.write(f"Flow {rep['flow_id']}  ({ep_s})\n")
        sys.stdout.write(f"Duration: {fmt_num(rep.get('duration_sec'), 3)} s   RST={rep.get('rst_seen')} FIN={rep.get('fin_seen')}\n")

        findings = rep.get("findings") or []
        if findings:
            sys.stdout.write("\nFindings:\n")
            for f in findings:
                sev = f["severity"]
                direction = f.get("direction")
                title = f["title"]
                details = f["details"]
                evidence = f.get("evidence") or []

                when = ""
                if evidence:
                    e0 = evidence[0] or {}
                    bits: List[str] = []
                    rel = e0.get("t_rel_s")
                    pct = e0.get("t_rel_pct")
                    fr = e0.get("frame")
                    if rel is not None:
                        bits.append(f"+{fmt_num(float(rel), 3)}s")
                    if pct is not None:
                        bits.append(f"{fmt_num(float(pct), 1)}%")
                    if fr is not None:
                        bits.append(f"frame={int(fr)}")
                    if bits:
                        when = "  (" + ", ".join(bits) + ")"

                if direction:
                    sys.stdout.write(f"  [{sev}] {direction}: {title}{when}\n        {details}\n")
                else:
                    sys.stdout.write(f"  [{sev}] {title}{when}\n        {details}\n")

                if len(evidence) > 1:
                    ex_parts: List[str] = []
                    for e in evidence[1:6]:
                        rel = e.get("t_rel_s")
                        pct = e.get("t_rel_pct")
                        fr = e.get("frame")
                        s = []
                        if fr is not None:
                            s.append(f"{int(fr)}")
                        if rel is not None:
                            s.append(f"+{fmt_num(float(rel), 3)}s")
                        if pct is not None:
                            s.append(f"{fmt_num(float(pct), 1)}%")
                        ex_parts.append("@".join(s) if s else "?")
                    if ex_parts:
                        sys.stdout.write(f"        examples: {', '.join(ex_parts)}\n")
        sys.stdout.write("\nDirections:\n")
        for label, d in (rep.get("directions") or {}).items():
            sys.stdout.write(f"  - {label}\n")
            sys.stdout.write(f"      payload: {fmt_bytes(d['payload_bytes'])}  rate={fmt_rate(d.get('payload_rate_Bps'))}\n")
            rw = d.get("rwnd_summary", {})
            inf = d.get("inflight_summary", {})
            rt = d.get("rtt_summary", {})
            if rw.get("count", 0) > 0:
                sys.stdout.write(f"      rwnd: min={fmt_bytes(rw.get('min'))} p50={fmt_bytes(rw.get('p50'))} p90={fmt_bytes(rw.get('p90'))} max={fmt_bytes(rw.get('max'))}\n")
            if inf.get("count", 0) > 0:
                sys.stdout.write(f"      inflight: p50={fmt_bytes(inf.get('p50'))} p90={fmt_bytes(inf.get('p90'))} max={fmt_bytes(inf.get('max'))}\n")
            if rt.get("count", 0) > 0:
                sys.stdout.write(f"      RTT: p50={fmt_num(rt.get('p50'), 6)}s p90={fmt_num(rt.get('p90'), 6)}s max={fmt_num(rt.get('max'), 6)}s\n")

            sys.stdout.write(f"      dupACKs={d.get('dupacks_total')} retrans={d.get('retrans_total')} fast_retrans={d.get('fast_retrans_total')} rto-ish={d.get('rto_retrans_total')}\n")
            sys.stdout.write(f"      cwnd_proxy_peak_inflight={fmt_bytes(d.get('estimated_cwnd_proxy_bytes'))}\n")
            sys.stdout.write(f"      classification: {d.get('classification')}\n")
            rat = d.get("classification_rationale") or []
            if rat:
                sys.stdout.write(f"      rationale: {'; '.join(rat[:8])}\n")

    sys.stdout.flush()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap", help="Path to .pcap or .pcapng")
    ap.add_argument("--flow", type=int, default=None, help="Analyze only one flow id (0..N-1)")
    ap.add_argument("--top", type=int, default=0, help="Show only top-N flows by severity score")
    ap.add_argument("--json", action="store_true", help="Emit JSON report to stdout")
    ap.add_argument("--debug", type=int, default=0, help="Enable some debug prints")
    args = ap.parse_args()

    if not os.path.exists(args.pcap):
        die(f"File not found: {args.pcap}")

    reports = analyze_file(args.pcap, flow_filter=args.flow, top_n=args.top, debug=bool(args.debug))

    if not reports:
        die("No TCP flows found in capture.", code=1)

    if args.json:
        json.dump({"pcap": args.pcap, "flows": reports}, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    print_human(reports)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
