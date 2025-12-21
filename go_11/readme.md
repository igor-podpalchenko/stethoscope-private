# Stethoscope

## Purpose
Stethoscope is network utility (MacOS and Linux).
It passively captures (eavesdropping) a single TCP flow on a specified interface, reassembles TCP traffic in both directions, and forwards TCP L7 payloads to downstream sockets or pcap file.
Basic idea behind - build simple and powerful traffic analysis tool with minimal possible operating complexity, that are suitable for automated/unattended traffic inspection and protocol decoding.
It's intended for various network protocols research/reverse engineering.

Features: JSON-ish configs, startup buffering, control plane while adding guardrails such as stricter config validation and explicit back-pressure accounting.

## How it works
1. **Config + logging setup** – The entrypoint reads a required `--config` path, optionally overriding console verbosity with `--log-level`, then initializes logging and the service instance. Signal handlers cancel the service cleanly on SIGINT/SIGTERM ([main.go](./main.go)).
2. **Packet capture** – `Capture` uses gopacket/pcap with a generated BPF filter to read only packets matching the configured local/remote endpoints (and optional local port). It can apply a custom pcap buffer size, runs in promisc mode, and streams packets to worker queues ([service.go](./service.go), [capture.go](./capture.go)).
3. **Reassembly + routing** – Workers rebuild TCP byte streams, maintain per-direction startup buffers (to survive slow downstreams), and push chunks and session events through internal queues to the output manager and control plane ([service.go](./service.go)).
4. **Outputs** – Each session can simultaneously write to listener sockets (incoming clients), connector sockets (outgoing to a remote host), and optional PCAP files. Per-target buffers enforce `max_output_buffer_bytes` and drop with reason tracking when consumers can’t keep up. PCAP writes can be per-session or aggregated with a tunable queue ([output.go](./output.go), [service.go](./service.go)).
5. **Control plane + metrics** – A lightweight TCP control server publishes session metadata, drop stats, PCAP counters, and can close sessions on demand. Periodic stats logging is configurable or can be disabled by setting the interval to `0` ([service.go](./service.go)).

## Modes and operations
The service is a single-purpose TCP tap with multiple egress modes that can be combined in one config:
- **Connector mode (`io.output.remote-host`)** – Dials TCP connections to a remote host/ports for the requests and responses streams; reconnects on failure using configurable timeouts. Use when another process will ingest the reconstructed stream via outbound sockets.
- **Listener mode (`io.output.listner`)** – Listens on an address and allocates per-session ports from a range (with optional fixed first ports). Downstream consumers connect to receive data; useful for piping into tools that prefer inbound sockets.
- **PCAP sink (`io.output.pcap`)** – Writes raw packets to `.pcap` or `.pcapng`, either one rolling file or one file per session. Queue pressure is logged and counted; directories are created on demand.
- **Control plane (`control`)** – Exposes stats and controls over TCP (default 0.0.0.0:50005). Categories control which event groups are emitted on connect.

All three output families can run at once; drop accounting and per-stream labels (`requests`/`responses`) stay consistent regardless of the active mode ([config.json.md](../config.json.md)).

## Configuration
The app accepts JSON or “json-ish” (comments and unquoted keys) configs. Key sections and defaults are derived from the bundled `config.json.md`:
- **Capture (`io.input.capture`, required)** – Interface, `local_ip`, `remote_ip`, and `remote_port` are mandatory; `bpf-filter` is templated with those values and optional `local_port`. Supports `session_idle_sec` and per-direction startup buffers (`buffer_bytes`, `c2s_buffer_bytes`, `s2c_buffer_bytes`) ([config.json.md](../config.json.md), [service.go](./service.go)).
- **Output: connector (`io.output.remote-host`)** – Enable with `enabled: true` and provide `host`, `requests_port`, `responses_port`, plus optional timeouts (`connect`, `retry-every`). Missing required keys abort startup with clear errors ([config.json.md](../config.json.md)).
- **Output: listener (`io.output.listner`)** – Enable and set `port_range_start`/`port_range_end`; optional `first_requests_port`/`first_responses_port` seed the allocator. `ack_stall_sec` (under `timeouts`) informs the session idle/stall handler. Range validation happens at startup ([config.json.md](../config.json.md), [service.go](./service.go)).
- **Output: pcap (`io.output.pcap`)** – Toggle recording with `enabled`, choose `format` (`pcap`/`pcapng`), `per_session`, destination `dir` (or `path`), and `queue_size`. Non-writable paths disable PCAP with a warning rather than a crash ([config.json.md](../config.json.md), [service.go](./service.go)).
- **Control (`control`)** – `bind_ip` defaults to `0.0.0.0`, `listen_port` defaults to `50005`, and `default_cats` defines which event groups emit on client connect ([config.json.md](../config.json.md), [service.go](./service.go)).
- **Logging (`logging`)** – Console and optional file targets with independent verbosity; CLI `--log-level` overrides console only. Stats logging interval can live under `logging.stats.report_interval` or `runtime.stats_interval_sec` ([config.json.md](../config.json.md), [service.go](./service.go), [main.go](./main.go)).
- **Runtime (`runtime`)** – Worker count (default CPU cores, clamped to 1–256), capture queue size, per-output `max_output_buffer_bytes`, drain timeout, and stats interval. Capture can inherit a libpcap buffer size via `io.input.capture.scapy_bufsize` for legacy config compatibility ([config.json.md](../config.json.md), [service.go](./service.go), [capture.go](./capture.go)).
- **Role mapping (`io.mapping.role`)** – Marks the local side as `client` or `server`, affecting how request/response directions are labeled downstream ([config.json.md](../config.json.md)).

### Running
```bash
sudo ./stethoscope --config /path/to/config.json
# show control plane output
nc 127.0.0.1 50005
```

Use `sudo` or capabilities if your interface requires elevated privileges for pcap. Stats and warnings appear on stdout by default; logs can be mirrored to a file via config.

### PCAP decoding

Display info about pcap file content
```bash
capinfos tcpdumps/your.pcapng
```

Extract body as files
```bash
tshark -r tcpdumps/your.pcapng \
  -o tcp.desegment_tcp_streams:TRUE \
  -o http.desegment_body:TRUE \
  -o http.dechunk_body:TRUE \
  -o http.decompress_body:TRUE \
  --export-objects http,out_http
```

Display HTTP requests URL's
```bash
tshark -r tcpdumps/your.pcapng -Y "http.request" -T fields   -e tcp.stream -e http.host -e http.request.uri 
```

MSS / Window Scale / SACK negotiation per connection (the SYN is where the truth lives)
```bash
tshark -r tcpdumps/your.pcapng -Y "tcp.flags.syn==1" \
   -T fields -E header=y -E separator=$'\t' \
   -e frame.time -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport \
   -e tcp.options.mss_val -e tcp.options.wscale.shift -e tcp.options.sack_perm
```

HTTP stats (general)
```bash
tshark -r tcpdumps/your.pcapng -q -z http,stat
```

HTTP request <-> response stream
```bash
# Table text format
python3 print_pcap_http_stream.py tcpdumps/your.pcapng --text

# JSON format (jq it)
python3 print_pcap_http_stream.py tcpdumps/your.pcapng --pretty

# Extract single file from HTTP stream, XXX is value printed by print_pcap_http_stream.py - rs.frame
./extract_file_from_pcap.sh --in tcpdumps/your.pcapng  --out b.png  --frame XXX
```

