#!/usr/bin/env python3
"""
pcap_http_pairs.py

Extract HTTP request -> response pairs from a PCAP/PCAPNG using tshark.

Pairs are matched using Wireshark's linker fields:
- http.response_in (on request)
- http.request_in  (on response)

This version fixes:
  - Broken parsing due to tshark quoting (-E quote=d): parsed via csv/TSV reader
  - Spurious quotes in fields/headers ("\"Host", "\"192.168...")
  - Trailing CRLFs in headers (both real \r\n and literal "\\r\\n")
  - More reliable matching (frame numbers now parse correctly)

Also exports *all request/response header lines* (decoded by tshark) into:
  - headers_raw: list[str]
  - headers: map[str, list[str]]
  - start_line: request/status line

--text prints a terminal table:
  request method, URL, response code, response length (human), response content-type (no charset),
  request->response latency (ms)

NEW:
  - response frame is always included as: response.frame (and top-level resp_frame for convenience)
  - request frame is always included as: request.frame (and top-level req_frame for convenience)

So you can do: txn["resp_frame"] and pass that to tshark frame.number==N to extract http.file_data.

Requirements:
  - tshark in PATH (Wireshark CLI)
  - Python 3.9+

Examples:
  ./pcap_http_pairs.py tcpdumps/foo.pcapng --pretty | jq
  ./pcap_http_pairs.py tcpdumps/foo.pcapng --ndjson | jq
  ./pcap_http_pairs.py tcpdumps/foo.pcapng --text
  ./pcap_http_pairs.py --list-http-fields --pretty | jq
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import shutil
import signal
import subprocess
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

HDR_AGG = "\x1f"  # unit separator, used as tshark aggregator for repeated fields


@dataclass
class ReqRow:
    ts: Optional[float]
    frame: Optional[int]
    stream: Optional[int]
    src: str
    dst: str
    host: Optional[str]
    method: Optional[str]
    uri: Optional[str]
    resp_frame: Optional[int]  # http.response_in (frame number)
    req_lines_raw: List[str]   # http.request.line (all occurrences)


@dataclass
class RespRow:
    ts: Optional[float]
    frame: Optional[int]
    stream: Optional[int]
    src: str
    dst: str
    req_frame: Optional[int]  # http.request_in (frame number)
    status: Optional[int]
    content_type: Optional[str]
    content_length: Optional[int]
    resp_lines_raw: List[str]  # http.response.line (all occurrences)


def _to_float(s: Optional[str]) -> Optional[float]:
    if s is None:
        return None
    s = s.strip()
    if not s:
        return None
    try:
        return float(s)
    except ValueError:
        return None


def _to_int(s: Optional[str]) -> Optional[int]:
    if s is None:
        return None
    s = s.strip()
    if not s:
        return None
    try:
        return int(s)
    except ValueError:
        try:
            return int(float(s))
        except Exception:
            return None


def _strip_crlf(s: str) -> str:
    s = s.rstrip("\r\n")
    if s.endswith("\\r\\n"):
        s = s[:-4]
    if s.endswith("\\n"):
        s = s[:-2]
    if s.endswith("\\r"):
        s = s[:-2]
    return s


def _clean_scalar(s: Optional[str]) -> Optional[str]:
    if s is None:
        return None
    s = s.strip()
    if not s:
        return None
    s = _strip_crlf(s)
    return s if s != "" else None


def _split_agg(s: Optional[str]) -> List[str]:
    if s is None:
        return []
    s = s.strip()
    if not s:
        return []
    parts = [p for p in s.split(HDR_AGG) if p != ""]
    return [_strip_crlf(p) for p in parts if _strip_crlf(p) != ""]


def run_tshark_fields(
    pcap: str,
    display_filter: str,
    fields: List[str],
    *,
    occurrence: str = "f",
    aggregator: Optional[str] = None,
) -> List[List[str]]:
    cmd = [
        "tshark",
        "-r", pcap,
        "-o", "tcp.desegment_tcp_streams:TRUE",
        "-o", "http.desegment_headers:TRUE",
        "-Y", display_filter,
        "-T", "fields",
        "-E", "separator=\t",
        "-E", f"occurrence={occurrence}",
        "-E", "quote=d",
    ]
    if aggregator is not None:
        cmd += ["-E", f"aggregator={aggregator}"]

    for f in fields:
        cmd += ["-e", f]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        raise RuntimeError("tshark not found in PATH. Install Wireshark (tshark).")

    if proc.returncode != 0:
        raise RuntimeError(
            "tshark failed.\n"
            f"Command: {' '.join(cmd)}\n"
            f"Exit code: {proc.returncode}\n"
            f"stderr:\n{proc.stderr.strip()}\n"
        )

    rows: List[List[str]] = []
    reader = csv.reader(io.StringIO(proc.stdout), delimiter="\t", quotechar='"', doublequote=True)
    for row in reader:
        rows.append(row)
    return rows


def tshark_http_fields() -> List[str]:
    cmd = ["tshark", "-G", "fields"]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    except FileNotFoundError:
        raise RuntimeError("tshark not found in PATH. Install Wireshark (tshark).")

    if proc.returncode != 0:
        raise RuntimeError(
            "tshark -G fields failed.\n"
            f"Command: {' '.join(cmd)}\n"
            f"Exit code: {proc.returncode}\n"
            f"stderr:\n{proc.stderr.strip()}\n"
        )

    out: List[str] = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            abbr = parts[2]
            if abbr.startswith("http.") or abbr.startswith("http2."):
                out.append(abbr)
    return sorted(set(out))


def _headers_from_lines(lines: List[str]) -> Tuple[Optional[str], Dict[str, List[str]], List[str]]:
    start_line: Optional[str] = None
    hdrs: Dict[str, List[str]] = {}
    raw: List[str] = []

    for line in lines:
        line = _strip_crlf(line.strip())
        if not line:
            continue

        raw.append(line)

        if start_line is None:
            if line.startswith("HTTP/"):
                start_line = line
                continue
            if "HTTP/" in line and line.split(" ", 1)[0].isalpha():
                start_line = line
                continue

        if ":" in line:
            name, value = line.split(":", 1)
            name = name.strip()
            value = _strip_crlf(value.lstrip())
            if name:
                hdrs.setdefault(name, []).append(value)

    return start_line, hdrs, raw


def load_requests(pcap: str) -> List[ReqRow]:
    fields = [
        "frame.time_epoch",
        "frame.number",
        "tcp.stream",
        "ip.src",
        "ip.dst",
        "http.host",
        "http.request.method",
        "http.request.uri",
        "http.response_in",
        "http.request.line",
    ]
    rows = run_tshark_fields(
        pcap,
        "http.request",
        fields,
        occurrence="a",
        aggregator=HDR_AGG,
    )

    out: List[ReqRow] = []
    for cols in rows:
        cols = cols + [""] * (len(fields) - len(cols))
        out.append(
            ReqRow(
                ts=_to_float(cols[0]),
                frame=_to_int(cols[1]),
                stream=_to_int(cols[2]),
                src=_clean_scalar(cols[3]) or "",
                dst=_clean_scalar(cols[4]) or "",
                host=_clean_scalar(cols[5]),
                method=_clean_scalar(cols[6]),
                uri=_clean_scalar(cols[7]),
                resp_frame=_to_int(cols[8]),
                req_lines_raw=_split_agg(cols[9]),
            )
        )
    return out


def load_responses(pcap: str) -> List[RespRow]:
    fields = [
        "frame.time_epoch",
        "frame.number",
        "tcp.stream",
        "ip.src",
        "ip.dst",
        "http.request_in",
        "http.response.code",
        "http.content_type",
        "http.content_length",
        "http.response.line",
    ]
    rows = run_tshark_fields(
        pcap,
        "http.response",
        fields,
        occurrence="a",
        aggregator=HDR_AGG,
    )

    out: List[RespRow] = []
    for cols in rows:
        cols = cols + [""] * (len(fields) - len(cols))
        out.append(
            RespRow(
                ts=_to_float(cols[0]),
                frame=_to_int(cols[1]),
                stream=_to_int(cols[2]),
                src=_clean_scalar(cols[3]) or "",
                dst=_clean_scalar(cols[4]) or "",
                req_frame=_to_int(cols[5]),
                status=_to_int(cols[6]),
                content_type=_clean_scalar(cols[7]),
                content_length=_to_int(cols[8]),
                resp_lines_raw=_split_agg(cols[9]),
            )
        )
    return out


def _strip_charset(content_type: str) -> str:
    ct = content_type.strip()
    if not ct:
        return ct
    return ct.split(";", 1)[0].strip()


def _human_bytes(n: Optional[int]) -> str:
    if n is None:
        return ""
    try:
        b = int(n)
    except Exception:
        return ""
    if b < 0:
        return str(b)

    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    v = float(b)
    i = 0
    while v >= 1024.0 and i < len(units) - 1:
        v /= 1024.0
        i += 1
    if i == 0:
        return f"{b}B"
    if v < 10:
        return f"{v:.1f}{units[i]}"
    return f"{v:.0f}{units[i]}"


def pair_http(reqs: List[ReqRow], resps: List[RespRow]) -> Tuple[List[dict], Dict[str, List[str]]]:
    resp_by_frame: Dict[int, RespRow] = {}
    resp_by_req_frame: Dict[int, List[RespRow]] = {}

    for r in resps:
        if r.frame is not None:
            resp_by_frame[r.frame] = r
        if r.req_frame is not None:
            resp_by_req_frame.setdefault(r.req_frame, []).append(r)

    def pick_best(cands: List[RespRow]) -> RespRow:
        cands = sorted(cands, key=lambda x: (x.ts is None, x.ts or 0.0, x.frame is None, x.frame or 0))
        return cands[0]

    req_hdr_names: Dict[str, int] = {}
    resp_hdr_names: Dict[str, int] = {}

    txns: List[dict] = []
    for q in reqs:
        resp: Optional[RespRow] = None
        pairing: Optional[str] = None

        if q.resp_frame is not None and q.resp_frame in resp_by_frame:
            resp = resp_by_frame[q.resp_frame]
            pairing = "http.response_in"
        elif q.frame is not None and q.frame in resp_by_req_frame:
            resp = pick_best(resp_by_req_frame[q.frame])
            pairing = "http.request_in"

        req_start, req_hdrs, req_raw = _headers_from_lines(q.req_lines_raw)
        for k in req_hdrs.keys():
            req_hdr_names[k] = req_hdr_names.get(k, 0) + 1

        resp_start, resp_hdrs, resp_raw = (None, {}, [])
        if resp is not None:
            resp_start, resp_hdrs, resp_raw = _headers_from_lines(resp.resp_lines_raw)
            for k in resp_hdrs.keys():
                resp_hdr_names[k] = resp_hdr_names.get(k, 0) + 1

        host = q.host
        uri = q.uri
        url = f"http://{host}{uri}" if (host and uri) else None

        content_type = resp.content_type if resp else None
        if content_type is None and "Content-Type" in resp_hdrs:
            content_type = resp_hdrs["Content-Type"][0]
        if content_type is not None:
            content_type = _strip_charset(content_type)

        content_length = resp.content_length if resp else None
        if content_length is None and "Content-Length" in resp_hdrs:
            content_length = _to_int(resp_hdrs["Content-Length"][0])

        status = resp.status if resp else None

        req_frame = q.frame
        resp_frame = resp.frame if (resp and resp.frame is not None) else q.resp_frame

        txns.append(
            {
                "tcp_stream": q.stream,
                "src": q.src,
                "dst": q.dst,
                "pairing": pairing,
                "ts_req": q.ts,
                "ts_resp": resp.ts if resp else None,

                # Convenience: easy to jq/grep/pipeline into extraction commands
                "req_frame": req_frame,
                "resp_frame": resp_frame,

                "request": {
                    "frame": req_frame,
                    "start_line": req_start,
                    "method": q.method,
                    "uri": uri,
                    "host": host,
                    "url": url,
                    "headers": req_hdrs,
                    "headers_raw": req_raw,
                },
                "response": None
                if resp is None
                else {
                    "frame": resp.frame,
                    "start_line": resp_start,
                    "status": status,
                    "content_type": content_type,
                    "content_length": content_length,
                    "headers": resp_hdrs,
                    "headers_raw": resp_raw,
                },
            }
        )

    txns.sort(
        key=lambda x: (
            x["tcp_stream"] is None,
            x["tcp_stream"] or -1,
            x["ts_req"] or 0.0,
            x["req_frame"] or 0,
        )
    )

    meta = {
        "request_header_names": [k for k, _ in sorted(req_hdr_names.items(), key=lambda kv: (-kv[1], kv[0].lower()))],
        "response_header_names": [k for k, _ in sorted(resp_hdr_names.items(), key=lambda kv: (-kv[1], kv[0].lower()))],
        "notes": [
            "Matching uses http.response_in (request->response frame link) when available, else http.request_in (response->request frame link).",
            "Use resp_frame with: tshark -Y 'frame.number==N && http.response' -e http.file_data | xxd -r -p",
        ],
    }
    return txns, meta


def _ellipsize_mid(s: str, width: int, head_ratio: float = 0.55) -> str:
    if width <= 0:
        return s
    if len(s) <= width:
        return s
    if width <= 5:
        return s[:width]
    w = width - 1
    head = int(w * head_ratio)
    tail = w - head
    if tail < 1:
        tail = 1
        head = w - tail
    return s[:head] + "…" + s[-tail:]


def _pad(s: str, width: int) -> str:
    if width <= 0:
        return ""
    if len(s) >= width:
        return s[:width]
    return s + (" " * (width - len(s)))


def print_text_table(txns: List[dict]) -> None:
    cols = shutil.get_terminal_size(fallback=(160, 24)).columns

    w_method = 6
    w_status = 6
    w_len = 10
    w_type = 24
    w_lat = 8
    w_rf = 7  # resp frame
    w_url = cols - (w_method + 1 + w_rf + 1 + w_status + 1 + w_len + 1 + w_type + 1 + w_lat)
    if w_url < 20:
        w_url = 20

    def row(method: str, url: str, rframe: str, status: str, length: str, ctype: str, lat: str) -> str:
        url2 = _ellipsize_mid(url, w_url)
        ctype2 = _ellipsize_mid(ctype, w_type)
        return " ".join(
            [
                _pad(method, w_method),
                _pad(url2, w_url),
                _pad(rframe, w_rf),
                _pad(status, w_status),
                _pad(length, w_len),
                _pad(ctype2, w_type),
                _pad(lat, w_lat),
            ]
        ).rstrip()

    print(row("method", "url", "rs.frame", "status", "len", "content_type", "lat_ms"))

    for t in txns:
        req = t.get("request") or {}
        resp = t.get("response") or {}

        method = (req.get("method") or "") if isinstance(req, dict) else ""
        url = (req.get("url") or "") if isinstance(req, dict) else ""

        rframe = ""
        rf = t.get("resp_frame")
        if rf is not None:
            rframe = str(rf)

        status = ""
        length = ""
        ctype = ""
        if isinstance(resp, dict) and resp:
            st = resp.get("status")
            if st is not None:
                status = str(st)

            cl = resp.get("content_length")
            length = _human_bytes(cl if isinstance(cl, int) else _to_int(str(cl)) if cl is not None else None)

            ct = resp.get("content_type")
            if ct is not None:
                ctype = _strip_charset(str(ct))

        lat = ""
        ts_req = t.get("ts_req")
        ts_resp = t.get("ts_resp")
        if isinstance(ts_req, (int, float)) and isinstance(ts_resp, (int, float)):
            lat = str(int(round((ts_resp - ts_req) * 1000.0)))

        print(row(method, url, rframe, status, length, ctype, lat))


def main() -> int:
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except Exception:
        pass

    ap = argparse.ArgumentParser(description="Extract HTTP request->response pairs from PCAP/PCAPNG (via tshark).")
    ap.add_argument("pcap", nargs="?", help="Path to .pcap or .pcapng")
    ap.add_argument("--ndjson", action="store_true", help="Output NDJSON (one JSON object per line)")
    ap.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    ap.add_argument("--meta", action="store_true", help="Wrap output as {meta, transactions}")
    ap.add_argument(
        "--text",
        action="store_true",
        help="Print a terminal table: method, url, rs.frame, status, len(human), content-type(no charset), latency(ms).",
    )
    ap.add_argument(
        "--list-http-fields",
        action="store_true",
        help="Print supported http*/http2* tshark field abbreviations and exit.",
    )
    args = ap.parse_args()

    try:
        if args.list_http_fields:
            fields = tshark_http_fields()
            print(json.dumps({"http_fields": fields}, ensure_ascii=False, indent=2 if args.pretty else None))
            return 0

        if not args.pcap:
            ap.error("pcap is required unless --list-http-fields is used")
            return 2

        reqs = load_requests(args.pcap)
        resps = load_responses(args.pcap)
        txns, meta = pair_http(reqs, resps)

    except RuntimeError as e:
        print(str(e), file=sys.stderr)
        return 2

    try:
        if args.text:
            print_text_table(txns)
            return 0

        if args.ndjson:
            for obj in txns:
                if args.pretty:
                    print(json.dumps(obj, ensure_ascii=False, indent=2))
                else:
                    print(json.dumps(obj, ensure_ascii=False, separators=(",", ":")))
            return 0

        payload: Any = {"meta": meta, "transactions": txns} if args.meta else txns
        if args.pretty:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
        return 0

    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
