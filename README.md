stethoscope (TCP eavesdropping tool)

	- Based on BPF (Berkley Packet Filter), works on MacOS and Linux
	- JSON format config
	- Prototype on Python

Packet capture and TCP reassembly:

	Based on BPF (Berkley Packet Filter) and python scapy library.
	Filtering is based	 on a BPF rule.

	   bpf = (
        			f"tcp and ((src host {args.local_ip} and dst host {args.remote_ip} and dst port {args.remote_port})"
        			" or "
        			f"(src host {args.remote_ip} and src port {args.remote_port} and dst host {args.local_ip}))"
    	   )

	

	IP packets matching a single or multiple TCP streams (sessions) go through pipeline where
	are inspected (logged as events), reassembled back to TCP stream and forwarded (to configured targets).
	With support for TCP protocol functionality - retransmission / reordering / out-of-order (events go to console log).
	Optionally MTU (max seen) / MSS (from ACK) / BDP (from ACK) / packet rates and statistics could be calculated and logged.
	Source port == tcp_session_id, which means when we detect packets with new source port - 
	we open new remote-host connections or start new listener on configured port range and reports  new connection event to control plane.
	Service has one listen TCP port as control plane (RX for commands, TX for output)

	Implementation is based on asynchronous IO (multithreaded, loading all CPU cores), packets are instantly sent to configured outputs (if so).
	If output can't process traffic without stuck/blocking - TCP packets/segments will be discarded.
	
	Traffic buffering is not implemented in current version. 
	It might be required in situations where bandwidth mismatches capture source throughput and output throughput.

IO output endpoints:

	1.)  Listener, has 2 listen ports for traffic (per N sockets - 2 incoming connections for requests/responses),               
		Configured in remote section io.output.listner.

	2.) Connector, can do N (2 per monitored TCP session) outgoing connections for traffic.
		For every new TCP sessions, service opens 2 outgoing connections.
		Configured in remote section io.output.remote-host.

	3.) Mixed mode. When config contains both io.output.remote-host and io.output.listner and they are both enabled.

	4.) Control only mode.
		For hardware/software offloaded on remote switch or router (i.e. switch port mirroring or sniffer capture).
		When config does not contain either io.output.remote-host or io.output.listner or they are both disabled.
		It that case, control plane (listener) still works and emits only connection events - open/closed.

	

Control plane protocol:

	- HTTP API
	- Is intentionally limited to 1 active control session (non HTTP)
	- Source (client that initiates connection) port is TCP session identifier
	- Bytes statistic
	
	Control plane events (HTTP comet, well-formed JSON structures per line): 

		- TCP connection opened (signals client to initiate connection to Listen ports if in Listener mode)
		- TCP connection closed (detect timeout? Or FIN based)
		- Flow events (stop due to non-ack'd traffic)

Common:
		
	Request-Response config model for target socket(s):

		- In client mode outgoing traffic is requests, incoming traffic is responses   (i.e. browser sends HTTP requests, receives HTTP responses).
			Example of outward filter:
			"tcp and ((src host {local_ip} and dst host {remote_ip} and dst port {remote_port}) or (src host {remote_ip} and src port {remote_port} and dst host {local_ip}))"

		- In server mode outgoing traffic is responses, incoming traffic is requests  (i.e. web server sends HTTP responses, receives HTTP requests)

Notes on testing / validation:

	- clients - curl, nc
	- server - nginx (may be in reverse proxy mode)


Notes:

	•	MSS (Maximum Segment Size) the “chunk size”: how big each TCP payload chunk is allowed to be.

			MSS is the maximum number of application bytes in a single TCP segment.
			•	It’s negotiated during the 3-way handshake using the TCP MSS option (each direction can have its own MSS).
			•	It’s basically derived from the path’s MTU (maximum IP packet size on the link):
			•	For IPv4 (no options): MSS ≈ MTU - 20(IP) - 20(TCP)

	•	TCP window (the “in-flight credit limit”): how much data can be in flight (sent but not yet ACKed).

			The receive window (rwnd) is the receiver telling the sender: “I can currently buffer this many bytes beyond what I’ve ACKed.”
			•	It’s carried in every TCP ACK (the Window field).
			•	Classic TCP window field is 16-bit, so max 65,535 bytes unless you use…
			•	Window Scaling (RFC 7323): negotiated in handshake; effectively multiplies the window by 2^scale.
		•	Example: scale=7 ⇒ multiply by 128 ⇒ 65,535 * 128 ≈ 8 MB max advertised.

	There’s also congestion window (cwnd) on the sender side: “How much I dare send based on congestion signals.”

	Actual sendable in-flight data is effectively:
		in_flight ≤ min(rwnd, cwnd)


	“Packets come broken” — what actually happens

		If a TCP segment arrives corrupted (bad checksum), the NIC/OS drops it silently. To TCP, that segment is indistinguishable from “never arrived”.

			So the receiver only has two realities:
			•	segment arrived intact → can be buffered/ACKed
			•	segment didn’t arrive (lost or corrupted) → causes a hole in the byte stream

		2) Reordering: receiver buffers, but ACK stays “stuck”

			Say the sender transmits three segments:
			•	A: seq 1000..1999
			•	B: seq 2000..2999
			•	C: seq 3000..3999

If the network reorders them and receiver gets A, then C, then B:

	•	After A arrives: receiver sends ACK=2000 (“next byte I want is 2000”)
	•	After C arrives (out of order): receiver buffers C but still sends ACK=2000 because B is missing
	•	When B finally arrives: receiver can now “stitch” A+B+C into a continuous stream and sends ACK=4000

	How the sender figures out something is missing

		TCP uses two main signals:

		A) Duplicate ACKs (fast retransmit)

			Receiver keeps ACKing the same value (e.g., ACK=2000) every time it gets something beyond the hole.

			Those repeated ACK=2000 are “dup ACKs”. When the sender sees typically 3 dup ACKs, it infers “segment starting at 2000 is missing”
			and retransmits it without waiting for a timer. 
			This is Fast Retransmit.

		B) Retransmission timeout (RTO)

			If not enough dup ACKs arrive (e.g., the loss was at the end, or traffic is sparse), sender relies on a timer:
			•	timer is based on measured RTT and variation
			•	on timeout, retransmit
			•	uses exponential backoff if repeated timeouts happen

		5) SACK: making retransmits smarter

			With SACK (Selective ACK) enabled, the receiver can say:

			“I’m still missing 2000..2999, but I do have 3000..3999 and 4000..4999…”
			That prevents the sender from needlessly retransmitting everything after the hole.
			Without SACK, dup ACKs only tell the sender “I’m stuck at 2000” and the sender must guess more.

"pcap": {
  "enabled": true,
  "dir": "tcpdumps/",
  "format": "pcapng",
  "per_session": true,
  "queue_size": 20000,
  "close_on_fin": true,
  "fin_close_grace_sec": 0.5,
  "idle_close_sec": 15
}

PCAP options available:
io.output.pcap.linktype ("ethernet" | "raw" | "null" | "linux_sll" or an int DLT)


