# Stethoscope Go v11

## Purpose
Stethoscope is network utility (MacOS and Linux).
It passively captures (eavesdropping) a single TCP flow on a specified interface, reassembles TCP traffic in both directions, and forwards TCP L7 payloads to downstream sockets or pcap file.
Basic idea behind - build simple and powerful traffic analysis tool with minimal possible operating complexity, that are suitable for automated/unattended traffic inspection and protocol decoding.
It's intended for various network protocols research/reverse engineering.

Features: JSON-ish configs, startup buffering, control plane while adding guardrails such as stricter config validation and explicit back-pressure accounting.

## How it works
1. **Config + logging setup** – The entrypoint reads a required `--config` path, optionally overriding console verbosity with `--log-level`, then initializes logging and the service instance. Signal handlers cancel the service cleanly on SIGINT/SIGTERM.【F:go_11/main.go†L12-L66】
2. **Packet capture** – `Capture` uses gopacket/pcap with a generated BPF filter to read only packets matching the configured local/remote endpoints (and optional local port). It can apply a custom pcap buffer size, runs in promisc mode, and streams packets to worker queues.【F:go_11/service.go†L126-L186】【F:go_11/capture.go†L16-L158】
3. **Reassembly + routing** – Workers rebuild TCP byte streams, maintain per-direction startup buffers (to survive slow downstreams), and push chunks and session events through internal queues to the output manager and control plane.【F:go_11/service.go†L70-L114】【F:go_11/service.go†L235-L274】
4. **Outputs** – Each session can simultaneously write to listener sockets (incoming clients), connector sockets (outgoing to a remote host), and optional PCAP files. Per-target buffers enforce `max_output_buffer_bytes` and drop with reason tracking when consumers can’t keep up. PCAP writes can be per-session or aggregated with a tunable queue.【F:go_11/output.go†L16-L120】【F:go_11/service.go†L220-L274】
5. **Control plane + metrics** – A lightweight TCP control server publishes session metadata, drop stats, PCAP counters, and can close sessions on demand. Periodic stats logging is configurable or can be disabled by setting the interval to `0`.【F:go_11/service.go†L195-L311】

## Modes and operations
The service is a single-purpose TCP tap with multiple egress modes that can be combined in one config:
- **Connector mode (`io.output.remote-host`)** – Dials TCP connections to a remote host/ports for the requests and responses streams; reconnects on failure using configurable timeouts. Use when another process will ingest the reconstructed stream via outbound sockets.
- **Listener mode (`io.output.listner`)** – Listens on an address and allocates per-session ports from a range (with optional fixed first ports). Downstream consumers connect to receive data; useful for piping into tools that prefer inbound sockets.
- **PCAP sink (`io.output.pcap`)** – Writes raw packets to `.pcap` or `.pcapng`, either one rolling file or one file per session. Queue pressure is logged and counted; directories are created on demand.
- **Control plane (`control`)** – Exposes stats and controls over TCP (default 0.0.0.0:50005). Categories control which event groups are emitted on connect.

All three output families can run at once; drop accounting and per-stream labels (`requests`/`responses`) stay consistent regardless of the active mode.【F:config.json.md†L4-L62】【F:config.json.md†L66-L157】

## Configuration
The app accepts JSON or “json-ish” (comments and unquoted keys) configs. Key sections and defaults are derived from the bundled `config.json.md`:
- **Capture (`io.input.capture`, required)** – Interface, `local_ip`, `remote_ip`, and `remote_port` are mandatory; `bpf-filter` is templated with those values and optional `local_port`. Supports `session_idle_sec` and per-direction startup buffers (`buffer_bytes`, `c2s_buffer_bytes`, `s2c_buffer_bytes`).【F:config.json.md†L18-L124】【F:go_11/service.go†L126-L187】
- **Output: connector (`io.output.remote-host`)** – Enable with `enabled: true` and provide `host`, `requests_port`, `responses_port`, plus optional timeouts (`connect`, `retry-every`). Missing required keys abort startup with clear errors.【F:config.json.md†L36-L81】
- **Output: listener (`io.output.listner`)** – Enable and set `port_range_start`/`port_range_end`; optional `first_requests_port`/`first_responses_port` seed the allocator. `ack_stall_sec` (under `timeouts`) informs the session idle/stall handler. Range validation happens at startup.【F:config.json.md†L36-L94】【F:go_11/service.go†L170-L175】
- **Output: pcap (`io.output.pcap`)** – Toggle recording with `enabled`, choose `format` (`pcap`/`pcapng`), `per_session`, destination `dir` (or `path`), and `queue_size`. Non-writable paths disable PCAP with a warning rather than a crash.【F:config.json.md†L54-L107】【F:go_11/service.go†L220-L234】
- **Control (`control`)** – `bind_ip` defaults to `0.0.0.0`, `listen_port` defaults to `50005`, and `default_cats` defines which event groups emit on client connect.【F:config.json.md†L132-L136】【F:go_11/service.go†L188-L206】
- **Logging (`logging`)** – Console and optional file targets with independent verbosity; CLI `--log-level` overrides console only. Stats logging interval can live under `logging.stats.report_interval` or `runtime.stats_interval_sec`.【F:config.json.md†L138-L156】【F:go_11/service.go†L209-L218】【F:go_11/main.go†L12-L66】
- **Runtime (`runtime`)** – Worker count (default CPU cores, clamped to 1–256), capture queue size, per-output `max_output_buffer_bytes`, drain timeout, and stats interval. Capture can inherit a libpcap buffer size via `io.input.capture.scapy_bufsize` for legacy config compatibility.【F:config.json.md†L149-L155】【F:go_11/service.go†L162-L234】【F:go_11/capture.go†L73-L124】
- **Role mapping (`io.mapping.role`)** – Marks the local side as `client` or `server`, affecting how request/response directions are labeled downstream.【F:config.json.md†L127-L129】

### Running
```bash
sudo ./stethoscope --config /path/to/config.json
# or build
```
Use `sudo` or capabilities if your interface requires elevated privileges for pcap. Stats and warnings appear on stdout by default; logs can be mirrored to a file via config.
