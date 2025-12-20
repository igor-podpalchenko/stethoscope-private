# stethoscope config.json.doc

This file is **documentation only** (human reference). The app must use a normal `config.json` without comments.

## High-level structure

- `io.input.capture` (**required**) – how packets are captured (BPF + interface + endpoints)
- `io.output.*` (**all optional**) – where reconstructed traffic is sent and/or recorded
  - `remote-host` (optional): connector mode (outgoing TCP)
  - `listner` (optional): listener mode (incoming TCP)
  - `pcap` (optional): write raw packets to `.pcap` / `.pcapng`
- `control` (optional) – control plane listener
- `logging` (optional) – console/file logging
- `runtime` (optional) – worker counts / queue sizes / tuning
- `io.mapping` (optional) – role mapping `client|server`

## Required vs optional (as implemented in code)

### Mandatory (service exits with a clear error if missing)
- `io.input.capture.iface`
- `io.input.capture.local_ip`
- `io.input.capture.remote_ip`
- `io.input.capture.remote_port`

If any are missing/empty, startup fails with:
`Missing io.input.capture fields: iface/local_ip/remote_ip/remote_port`

### Optional whole sections
- `io.output.remote-host` – may be absent or `"enabled": false`
- `io.output.listner` – may be absent or `"enabled": false`
- `io.output.pcap` – may be absent or `"enabled": false`
- `control` – defaults used when absent
- `logging` – defaults used when absent
- `runtime` – defaults used when absent
- `io.mapping` – defaults used when absent

### Conditional requirements (only if that output is enabled)
- If `io.output.remote-host.enabled == true` then these must be present and valid:
  - `host` (non-empty string)
  - `requests_port` (int > 0)
  - `responses_port` (int > 0)
  Otherwise the service exits with a **specific** error mentioning the missing keys.

- If `io.output.listner.enabled == true` then these must be present and valid:
  - `port_range_start` (int > 0)
  - `port_range_end` (int > 0)
  - and `port_range_end >= port_range_start`
  Otherwise the service exits with:
  `listener enabled, but port_range_start/end invalid in config`

  Notes:
  - `first_requests_port` and `first_responses_port` are optional.
    If both provided, the first session uses them; otherwise the allocator starts from the range.

- If `io.output.pcap.enabled == true` then:
  - `dir` (or legacy `path`) must be a non-empty string
  - directory must be creatable/writable
  If not, pcap output is disabled with a WARNING (service keeps running).

## Known gotcha that caused “missing X but Y reported wrong”
When a whole section is missing, code uses defaults for many fields.
If you enable a mode but forget one of the required fields for that mode, older versions could fail later during connect/listen and the first visible error could look unrelated (e.g. “cannot connect” instead of “missing port”).
The current code explicitly validates the connector ports/host when enabled, to make the error message point at the real missing key.

---

## Annotated example (same values as your working config)

```jsonc
{
  "io": {
    "output": {
      "remote-host": {
        "enabled": true,                // Connector mode (outgoing TCP connections)
        "host": "127.0.0.1",            // Where to connect
        "requests_port": 33030,         // Local->Remote stream port
        "responses_port": 33040,        // Remote->Local stream port
        "timeouts": {
          "connect": 5,                 // Seconds for connect() timeout
          "retry-every": 30             // Seconds between reconnect attempts
        }
      },

      "listner": {
        "enabled": true,                // Listener mode (incoming TCP connections)
        "first_requests_port": 33010,   // Optional: first session uses these exact ports
        "first_responses_port": 33020,  // Optional: first session uses these exact ports
        "port_range_start": 33530,      // Required when enabled
        "port_range_end": 33600,        // Required when enabled
        "bind_ip": "0.0.0.0",           // Bind for listen sockets

        "timeouts": {
          "ack_stall_sec": 5            // Optional: if set, stalls trigger events
        }
      },

      "pcap": {
        "enabled": true,                // Raw packet recording
        "dir": "tcpdumps/",             // Folder for pcap/pcapng output
        "format": "pcapng",             // "pcap" or "pcapng"
        "per_session": true,            // One file per TCP session (5-tuple w/ timestamps)
        "queue_size": 20000,            // Drop packets if writer queue is full

        "sync": false,                  // If true: flush/fsync more aggressively (slower)
        "idle_close_sec": 120,          // Close per-session file after inactivity (seconds)
        "close_on_fin": true,           // Close per-session file shortly after FIN/RST
        "fin_close_grace_sec": 1.0      // Seconds to wait after FINs before closing
      }
    },

    "input": {
      "capture": {
        "iface": "en0",                 // Capture interface (e.g. en0, eth0, utun7)
        "local_ip": "192.168.5.38",     // “Local” endpoint in your BPF template
        "remote_ip": "192.168.5.110",   // “Remote” endpoint in your BPF template
        "remote_port": 5000,            // Remote TCP port to match

        "bpf-filter": "tcp and ((src host {local_ip} and dst host {remote_ip} and dst port {remote_port}) or (src host {remote_ip} and src port {remote_port} and dst host {local_ip}))",

        "local_port": null,             // Optional: pin to one local source port if you want
        "session_idle_sec": 120,        // Optional: declare a session idle/closed after N seconds

        "linktype": "ethernet"          // Optional: only needed if the capture has no Ethernet L2
                                       // Values typically: "ethernet", "raw", "linux_sll"
      }
    },

    "mapping": {
      "role": "client"                  // "client" or "server" (affects req/resp direction mapping)
    }
  },

  "control": {
    "bind_ip": "0.0.0.0",               // Control-plane server bind
    "listen_port": 50005,               // Control-plane TCP port
    "default_cats": ["session", "ports", "output", "control"]
  },

  "logging": {
    "file": {
      "enabled": true,
      "path": "tcpdumps/service.log",
      "verbosity": "DEBUG"
    },
    "console": {
      "verbosity": "INFO"
    }
  },

  "runtime": {
    "workers": 10,                      // Optional: defaults to CPU count
    "capture_queue_size": 50000,        // Capture->worker queue
    "max_output_buffer_bytes": 1000000, // Per-output soft cap
    "drain_timeout_ms": 0,              // Optional: output drain timeout
    "stats_interval_sec": 5             // Stats log interval
  }
}
```

## How the app treats “comment-only” / “not used” keys
Any keys not referenced in code are ignored, but **it’s better to keep real config minimal**.
This is why this `.doc` exists: keep your real `config.json` clean, and use this file for explanations.

