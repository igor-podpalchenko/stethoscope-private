package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type TargetWriter struct {
	Name string
	Kind string // listener|connector
	Conn net.Conn

	sendCh    chan []byte
	pending   atomic.Int64
	closed    atomic.Bool
	closeOnce sync.Once
	closeCh   chan struct{}

	writeTimeout time.Duration
}

func NewTargetWriter(name, kind string, conn net.Conn, writeTimeout time.Duration) *TargetWriter {
	tw := &TargetWriter{
		Name:         name,
		Kind:         kind,
		Conn:         conn,
		sendCh:       make(chan []byte, 256),
		closeCh:      make(chan struct{}),
		writeTimeout: writeTimeout,
	}
	go tw.writerLoop()
	return tw
}

func (tw *TargetWriter) Close() {
	tw.closeOnce.Do(func() {
		tw.closed.Store(true)
		close(tw.closeCh)
		close(tw.sendCh)
		_ = tw.Conn.Close()
	})
}

func (tw *TargetWriter) IsClosing() bool { return tw.closed.Load() }

func (tw *TargetWriter) BufferSize() int64 { return tw.pending.Load() }

func (tw *TargetWriter) TryWrite(data []byte, maxBufferBytes int64) (ok bool, reason string) {
	if len(data) == 0 {
		return true, "empty"
	}
	if tw.IsClosing() {
		return false, "closing"
	}
	if tw.BufferSize()+int64(len(data)) > maxBufferBytes {
		return false, "backpressure"
	}
	select {
	case tw.sendCh <- data:
		tw.pending.Add(int64(len(data)))
		return true, "ok"
	default:
		return false, "backpressure"
	}
}

func (tw *TargetWriter) writerLoop() {
	defer tw.Close()
	for {
		select {
		case <-tw.closeCh:
			return
		case b, ok := <-tw.sendCh:
			if !ok {
				return
			}
			if len(b) == 0 {
				continue
			}
			if tw.writeTimeout > 0 {
				_ = tw.Conn.SetWriteDeadline(time.Now().Add(tw.writeTimeout))
			}
			remaining := b
			for len(remaining) > 0 {
				n, err := tw.Conn.Write(remaining)
				if n > 0 {
					remaining = remaining[n:]
				}
				if err != nil {
					return
				}
			}
			tw.pending.Add(-int64(len(b)))
		}
	}
}

type ConnectorState struct {
	EverConnected      bool
	CurrentlyConnected bool
}

type SessionOutputs struct {
	Flow FlowKey

	listenerPorts *[2]int
	listeners     map[string]*TargetWriter
	connectors    map[string]*TargetWriter
	connState     map[string]*ConnectorState

	servers []net.Listener

	ctx    context.Context
	cancel context.CancelFunc

	mu sync.Mutex
}

func NewSessionOutputs(flow FlowKey, parent context.Context) *SessionOutputs {
	ctx, cancel := context.WithCancel(parent)
	return &SessionOutputs{
		Flow:       flow,
		listeners:  map[string]*TargetWriter{"requests": nil, "responses": nil},
		connectors: map[string]*TargetWriter{"requests": nil, "responses": nil},
		connState:  map[string]*ConnectorState{"requests": {}, "responses": {}},
		ctx:        ctx,
		cancel:     cancel,
	}
}

func (so *SessionOutputs) AllTargetsFor(stream string) []*TargetWriter {
	so.mu.Lock()
	defer so.mu.Unlock()
	out := make([]*TargetWriter, 0, 2)
	if tw := so.listeners[stream]; tw != nil {
		out = append(out, tw)
	}
	if tw := so.connectors[stream]; tw != nil {
		out = append(out, tw)
	}
	return out
}

type PortAllocator struct {
	start int
	end   int

	firstReq  int
	firstResp int
	didFirst  bool

	used map[int]struct{}
	next int
	mu   sync.Mutex
}

func NewPortAllocator(start, end int, firstReq, firstResp any) *PortAllocator {
	pa := &PortAllocator{
		start: start,
		end:   end,
		used:  map[int]struct{}{},
		next:  start,
	}
	pa.firstReq = ToInt(firstReq, 0)
	pa.firstResp = ToInt(firstResp, 0)
	return pa
}

func (pa *PortAllocator) allocOneLocked() (int, error) {
	for i := pa.start; i <= pa.end; i++ {
		p := pa.next
		pa.next++
		if pa.next > pa.end {
			pa.next = pa.start
		}
		if _, ok := pa.used[p]; ok {
			continue
		}
		pa.used[p] = struct{}{}
		return p, nil
	}
	return 0, errors.New("listener port range exhausted")
}

func (pa *PortAllocator) AllocatePair() (int, int, error) {
	pa.mu.Lock()
	defer pa.mu.Unlock()
	if !pa.didFirst && pa.firstReq > 0 && pa.firstResp > 0 {
		pa.didFirst = true
		if _, ok := pa.used[pa.firstReq]; !ok {
			if _, ok2 := pa.used[pa.firstResp]; !ok2 {
				pa.used[pa.firstReq] = struct{}{}
				pa.used[pa.firstResp] = struct{}{}
				return pa.firstReq, pa.firstResp, nil
			}
		}
	}
	a, err := pa.allocOneLocked()
	if err != nil {
		return 0, 0, err
	}
	b, err := pa.allocOneLocked()
	if err != nil {
		delete(pa.used, a)
		return 0, 0, err
	}
	return a, b, nil
}

func (pa *PortAllocator) FreePair(a, b int) {
	pa.mu.Lock()
	defer pa.mu.Unlock()
	delete(pa.used, a)
	delete(pa.used, b)
}

type OutputManager struct {
	cfg    Config
	router *EventRouter

	role string

	maxOutputBuffer int64
	drainTimeout    time.Duration

	listenerEnabled bool
	listenerBindIP  string
	pa              *PortAllocator

	connectorEnabled bool
	connHost         string
	connReqPort      int
	connRespPort     int
	connConnectTO    time.Duration
	connRetryEvery   time.Duration

	sessions map[FlowKey]*SessionOutputs
	mu       sync.Mutex

	ctx context.Context
}

func NewOutputManager(cfg Config, router *EventRouter, ctx context.Context) *OutputManager {
	role := stringsLowerTrim(GetString(cfg, "io.mapping.role", "client"))
	if role != "client" && role != "server" {
		role = "client"
	}

	rt := GetMap(cfg, "runtime")
	maxBuf := int64(ToInt(rt["max_output_buffer_bytes"], 1_000_000))
	drainTOms := ToInt(rt["drain_timeout_ms"], 0)
	var drain time.Duration
	if drainTOms > 0 {
		drain = time.Duration(drainTOms) * time.Millisecond
	}

	listenerCfg := GetMap(cfg, "io.output.listner")
	listenerEnabled := GetBoolPath(cfg, "io.output.listner.enabled", false)
	listenerBindIP := GetString(listenerCfg, "bind_ip", "0.0.0.0")
	ls := ToInt(listenerCfg["port_range_start"], 0)
	le := ToInt(listenerCfg["port_range_end"], 0)
	var pa *PortAllocator
	if listenerEnabled {
		if ls <= 0 || le <= 0 || le < ls {
			panic("listener enabled, but port_range_start/end invalid in config")
		}
		pa = NewPortAllocator(ls, le, listenerCfg["first_requests_port"], listenerCfg["first_responses_port"])
	}

	connCfg := GetMap(cfg, "io.output.remote-host")
	connectorEnabled := GetBoolPath(cfg, "io.output.remote-host.enabled", false)
	host := GetString(connCfg, "host", "127.0.0.1")
	reqPort := ToInt(connCfg["requests_port"], 0)
	respPort := ToInt(connCfg["responses_port"], 0)
	connectTO := time.Duration(ToFloat64(GetPath(connCfg, "timeouts.connect", 5), 5) * float64(time.Second))
	retryEvery := time.Duration(ToFloat64(GetPath(connCfg, "timeouts.retry-every", 30), 30) * float64(time.Second))

	return &OutputManager{
		cfg:              cfg,
		router:           router,
		role:             role,
		maxOutputBuffer:  maxBuf,
		drainTimeout:     drain,
		listenerEnabled:  listenerEnabled,
		listenerBindIP:   listenerBindIP,
		pa:               pa,
		connectorEnabled: connectorEnabled,
		connHost:         host,
		connReqPort:      reqPort,
		connRespPort:     respPort,
		connConnectTO:    connectTO,
		connRetryEvery:   retryEvery,
		sessions:         map[FlowKey]*SessionOutputs{},
		ctx:              ctx,
	}
}

func stringsLowerTrim(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func (om *OutputManager) MapStream(direction string) string {
	if om.role == "client" {
		if direction == "c2s" {
			return "requests"
		}
		return "responses"
	}
	// server
	if direction == "c2s" {
		return "responses"
	}
	return "requests"
}

func (om *OutputManager) EnsureSession(flow FlowKey) *SessionOutputs {
	om.mu.Lock()
	so := om.sessions[flow]
	if so != nil {
		om.mu.Unlock()
		return so
	}
	so = NewSessionOutputs(flow, om.ctx)
	om.sessions[flow] = so
	om.mu.Unlock()

	// Listener mode
	if om.listenerEnabled && om.pa != nil {
		reqP, respP, err := om.pa.AllocatePair()
		if err != nil {
			panic(err)
		}
		so.listenerPorts = &[2]int{reqP, respP}
		om.startListenerServers(so, reqP, respP)
		om.router.Emit("ports", "listener_ports", "info", map[string]any{
			"flow":           flow.ToDict(),
			"requests_port":  reqP,
			"responses_port": respP,
		}, true)
	}

	// Connector mode
	if om.connectorEnabled && om.connReqPort > 0 && om.connRespPort > 0 {
		go om.connectorLoop(so, "requests")
		go om.connectorLoop(so, "responses")
	}

	return so
}

func (om *OutputManager) FindFlowBySessionID(sessionID int) (FlowKey, bool) {
	om.mu.Lock()
	defer om.mu.Unlock()
	for fk := range om.sessions {
		if fk.SessionID() == sessionID {
			return fk, true
		}
	}
	return FlowKey{}, false
}

// FindBySessionID is a compatibility alias.
func (om *OutputManager) FindBySessionID(sessionID int) (FlowKey, bool) {
	return om.FindFlowBySessionID(sessionID)
}

func (om *OutputManager) ListFlows() []FlowKey {
	om.mu.Lock()
	defer om.mu.Unlock()
	out := make([]FlowKey, 0, len(om.sessions))
	for fk := range om.sessions {
		out = append(out, fk)
	}
	return out
}

func (om *OutputManager) CloseSession(flow FlowKey, reason string) {
	om.mu.Lock()
	so := om.sessions[flow]
	delete(om.sessions, flow)
	om.mu.Unlock()
	if so == nil {
		return
	}

	so.cancel()

	so.mu.Lock()
	for _, srv := range so.servers {
		_ = srv.Close()
	}
	so.servers = nil
	for k, tw := range so.listeners {
		if tw != nil {
			tw.Close()
		}
		so.listeners[k] = nil
	}
	for k, tw := range so.connectors {
		if tw != nil {
			tw.Close()
		}
		so.connectors[k] = nil
	}
	ports := so.listenerPorts
	so.listenerPorts = nil
	so.mu.Unlock()

	if ports != nil && om.pa != nil {
		om.pa.FreePair((*ports)[0], (*ports)[1])
	}

	om.router.Emit("debug", "session_close_outputs", "debug", map[string]any{
		"flow":   flow.ToDict(),
		"reason": reason,
	}, false)
}

func (om *OutputManager) startListenerServers(so *SessionOutputs, reqPort, respPort int) {
	start := func(stream string, port int) {
		addr := fmt.Sprintf("%s:%d", om.listenerBindIP, port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			panic(err)
		}
		so.mu.Lock()
		so.servers = append(so.servers, ln)
		so.mu.Unlock()

		go func() {
			defer ln.Close()
			for {
				select {
				case <-so.ctx.Done():
					return
				default:
				}
				_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(500 * time.Millisecond))
				conn, err := ln.Accept()
				if err != nil {
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						continue
					}
					return
				}
				om.handleListenerConn(so, stream, conn)
			}
		}()
	}

	start("requests", reqPort)
	start("responses", respPort)
}

func (om *OutputManager) handleListenerConn(so *SessionOutputs, stream string, conn net.Conn) {
	peer := conn.RemoteAddr().String()
	tw := NewTargetWriter(fmt.Sprintf("listener:%s:%d", stream, so.Flow.SessionID()), "listener", conn, om.drainTimeout)

	so.mu.Lock()
	prev := so.listeners[stream]
	so.listeners[stream] = tw
	so.mu.Unlock()
	if prev != nil {
		prev.Close()
	}

	om.router.Emit("output", "listener_connected", "info", map[string]any{
		"flow":   so.Flow.ToDict(),
		"stream": stream,
		"peer":   peer,
	}, true)

	// Drain any inbound bytes (listener sockets are sinks in this prototype).
	go func() {
		buf := make([]byte, 65536)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, err := conn.Read(buf)
			if n > 0 {
				// discard
			}
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					select {
					case <-so.ctx.Done():
						return
					default:
						continue
					}
				}
				return
			}
		}
	}()

	// When session context closes, close conn and clear target.
	go func() {
		<-so.ctx.Done()
		tw.Close()
	}()

	// Wait until closed
	<-tw.closeCh

	so.mu.Lock()
	if so.listeners[stream] == tw {
		so.listeners[stream] = nil
	}
	so.mu.Unlock()

	om.router.Emit("output", "listener_disconnected", "info", map[string]any{
		"flow":   so.Flow.ToDict(),
		"stream": stream,
		"peer":   peer,
	}, true)
}

func (om *OutputManager) connectorLoop(so *SessionOutputs, stream string) {
	host := om.connHost
	port := om.connReqPort
	if stream == "responses" {
		port = om.connRespPort
	}

	for {
		select {
		case <-so.ctx.Done():
			return
		default:
		}

		st := so.connState[stream]
		if st.EverConnected {
			om.router.Emit("output", "connector_reconnect", "info", map[string]any{
				"flow":            so.Flow.ToDict(),
				"stream":          stream,
				"host":            host,
				"port":            port,
				"retry_every_sec": om.connRetryEvery.Seconds(),
			}, false)
		} else {
			om.router.Emit("output", "connector_connection_reattempt", "debug", map[string]any{
				"flow":            so.Flow.ToDict(),
				"stream":          stream,
				"host":            host,
				"port":            port,
				"retry_every_sec": om.connRetryEvery.Seconds(),
			}, false)
		}

		dialer := net.Dialer{Timeout: om.connConnectTO}
		conn, err := dialer.DialContext(so.ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
		if err != nil {
			om.router.Emit("debug", "connector_error", "debug", map[string]any{
				"flow":   so.Flow.ToDict(),
				"stream": stream,
				"error":  fmt.Sprintf("%v", err),
			}, false)
			timer := time.NewTimer(om.connRetryEvery)
			select {
			case <-so.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
				continue
			}
		}

		peer := conn.RemoteAddr().String()
		tw := NewTargetWriter(fmt.Sprintf("connector:%s:%d", stream, so.Flow.SessionID()), "connector", conn, om.drainTimeout)

		so.mu.Lock()
		prev := so.connectors[stream]
		so.connectors[stream] = tw
		so.mu.Unlock()
		if prev != nil {
			prev.Close()
		}

		wasConnected := st.CurrentlyConnected
		st.CurrentlyConnected = true
		st.EverConnected = true

		if !wasConnected {
			om.router.Emit("output", "connector_connected", "info", map[string]any{
				"flow":   so.Flow.ToDict(),
				"stream": stream,
				"peer":   peer,
			}, true)
		}

		// Drain inbound bytes from connector socket (sink).
		buf := make([]byte, 65536)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			_, err := conn.Read(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					select {
					case <-so.ctx.Done():
						tw.Close()
						goto DISCONNECT
					default:
						continue
					}
				}
				goto DISCONNECT
			}
		}

	DISCONNECT:
		so.mu.Lock()
		if so.connectors[stream] == tw {
			so.connectors[stream] = nil
		}
		so.mu.Unlock()
		tw.Close()

		// Requested: CP event only if it *was* connected before.
		if st.CurrentlyConnected {
			st.CurrentlyConnected = false
			om.router.Emit("output", "connector_disconnected", "warning", map[string]any{
				"flow":            so.Flow.ToDict(),
				"stream":          stream,
				"retry_every_sec": om.connRetryEvery.Seconds(),
			}, true)
		} else {
			om.router.Emit("output", "connector_disconnect_suppressed", "debug", map[string]any{
				"flow":   so.Flow.ToDict(),
				"stream": stream,
			}, false)
		}

		timer := time.NewTimer(om.connRetryEvery)
		select {
		case <-so.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			continue
		}
	}
}

func (om *OutputManager) WriteChunk(flow FlowKey, direction string, data []byte) (sent int, dropped int, reason string, targets int) {
	if len(data) == 0 {
		return 0, 0, "empty", 0
	}

	so := om.EnsureSession(flow)
	stream := om.MapStream(direction)
	tws := so.AllTargetsFor(stream)
	if len(tws) == 0 {
		return 0, len(data), "no_targets", 0
	}

	reason = "ok"
	for _, tw := range tws {
		targets++
		ok, r := tw.TryWrite(data, om.maxOutputBuffer)
		if ok {
			sent += len(data)
			continue
		}
		dropped += len(data)
		reason = r
		if r == "write_error" || r == "closing" {
			tw.Close()
		}
	}

	return sent, dropped, reason, targets
}
