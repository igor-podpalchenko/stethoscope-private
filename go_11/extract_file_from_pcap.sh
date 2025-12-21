#!/usr/bin/env bash
set -euo pipefail

# extract_http_body.sh
#
# Extract HTTP response body bytes from a PCAP/PCAPNG by response frame number.
# Uses: tshark ... -e http.file_data | xxd -r -p > out
#
# Example:
#   ./extract_http_body.sh --in capture.pcapng --frame 7444 --out 1.png
#
# Notes:
# - The frame must be a *response* frame (http.response), not a request frame.
# - tshark must be installed and in PATH.
# - xxd must be installed (on macOS it is).

usage() {
  cat >&2 <<'EOF'
Usage:
  extract_http_body.sh --in <pcap|pcapng> --frame <N> --out <path>

Required args:
  --in     Path to .pcap/.pcapng
  --frame  Response frame number (Wireshark/tshark frame.number)
  --out    Output file path for extracted body bytes

Example:
  extract_http_body.sh --in tcpdumps/foo.pcapng --frame 7444 --out 1.png

Tips:
  - Find response frames with your pcap_http_pairs.py table column "rs.frame"
  - Or: tshark -r <pcap> -Y "http.response" -T fields -e frame.number -e http.content_type -e http.content_length
EOF
}

IN=""
FRAME=""
OUT=""

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --in)
      [[ $# -ge 2 ]] || { echo "error: --in requires a value" >&2; usage; exit 2; }
      IN="$2"; shift 2
      ;;
    --frame)
      [[ $# -ge 2 ]] || { echo "error: --frame requires a value" >&2; usage; exit 2; }
      FRAME="$2"; shift 2
      ;;
    --out)
      [[ $# -ge 2 ]] || { echo "error: --out requires a value" >&2; usage; exit 2; }
      OUT="$2"; shift 2
      ;;
    -h|--help)
      usage; exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

# Validate args
if [[ -z "$IN" || -z "$FRAME" || -z "$OUT" ]]; then
  echo "error: missing required arguments" >&2
  usage
  exit 2
fi

if [[ ! -f "$IN" ]]; then
  echo "error: input file not found: $IN" >&2
  exit 2
fi

if ! [[ "$FRAME" =~ ^[0-9]+$ ]]; then
  echo "error: --frame must be an integer, got: $FRAME" >&2
  exit 2
fi

command -v tshark >/dev/null 2>&1 || { echo "error: tshark not found in PATH" >&2; exit 2; }
command -v xxd    >/dev/null 2>&1 || { echo "error: xxd not found in PATH" >&2; exit 2; }

# Ensure output dir exists
OUT_DIR="$(dirname "$OUT")"
if [[ "$OUT_DIR" != "." && ! -d "$OUT_DIR" ]]; then
  mkdir -p "$OUT_DIR"
fi

# Quick sanity: is this frame actually an HTTP response?
if ! tshark -r "$IN" -Y "frame.number==$FRAME && http.response" -T fields -e frame.number 2>/dev/null | grep -q .; then
  echo "error: frame $FRAME is not an http.response (or not present in capture)" >&2
  echo "hint: use response frame numbers (rs.frame) from your pairing output" >&2
  exit 2
fi

# Extract
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

tshark -r "$IN" \
  -o tcp.desegment_tcp_streams:TRUE \
  -o http.desegment_body:TRUE \
  -o http.dechunk_body:TRUE \
  -o http.decompress_body:TRUE \
  -Y "frame.number==$FRAME && http.response" \
  -T fields -e http.file_data \
  > "$tmp"

if [[ ! -s "$tmp" ]]; then
  echo "error: tshark returned empty http.file_data for frame $FRAME" >&2
  echo "hint: try disabling decompress/dechunk, or the body may not be dissected as HTTP" >&2
  exit 2
fi

# Convert hex -> bytes
xxd -r -p < "$tmp" > "$OUT"

# Print a tiny summary (content-type/len if available)
ctype="$(tshark -r "$IN" -Y "frame.number==$FRAME && http.response" -T fields -e http.content_type 2>/dev/null | head -n1 || true)"
clen="$(tshark -r "$IN" -Y "frame.number==$FRAME && http.response" -T fields -e http.content_length 2>/dev/null | head -n1 || true)"
bytes_written="$(wc -c < "$OUT" | tr -d ' ')"

echo "ok: wrote $bytes_written bytes to $OUT"
if [[ -n "$ctype" || -n "$clen" ]]; then
  echo "meta: content-type=${ctype:-<unknown>} content-length=${clen:-<unknown>}"
fi
