package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

type dropKey struct {
	sessionID int
	stream    string
	reason    string
}

type Service struct {
	cfg Config
	log *Logger

	iface           string
	localIP         string
	remoteIP        string
	remotePort      int
	localPortFilter any
	bpf             string

	workers          int
	captureQueueSize int

	sessionIdle time.Duration
	ackStall    time.Duration

	controlBindIP string
	controlPort   int
	defaultCats   []string

	control *ControlPlane
	router  *EventRouter
	outputs *OutputManager

	forwardQ chan ForwardChunk
	eventQ   chan SessionEvent

	workerInqs []chan PacketInfo
	workersW   []*ReassemblyWorker
	capture    *Capture

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	metaMu           sync.Mutex
	sessions         map[int]map[string]any
	sessionBytesOut  map[int]int64
	sessionBytesDrop map[int]int64
	dropCount        map[dropKey]int64
	dropBytes        map[dropKey]int64

	bytesForwarded  int64
	bytesDropped    int64
	chunksForwarded int64
	chunksDropped   int64

	statsInterval time.Duration
}

func formatBPF(tpl string, vals map[string]string) string {
	r := strings.NewReplacer(
		"{local_ip}", vals["local_ip"],
		"{remote_ip}", vals["remote_ip"],
		"{remote_port}", vals["remote_port"],
		"{local_port}", vals["local_port"],
	)
	return r.Replace(tpl)
}

func NewService(cfg Config, log *Logger) (*Service, error) {
	capCfg := GetMap(cfg, "io.input.capture")
	iface := strings.TrimSpace(fmt.Sprintf("%v", capCfg["iface"]))
	localIP := strings.TrimSpace(fmt.Sprintf("%v", capCfg["local_ip"]))
	remoteIP := strings.TrimSpace(fmt.Sprintf("%v", capCfg["remote_ip"]))
	remotePort := ToInt(capCfg["remote_port"], 0)
	localPortFilter := capCfg["local_port"]

	if iface == "" || localIP == "" || remoteIP == "" || remotePort == 0 {
		return nil, fmt.Errorf("missing io.input.capture fields: iface/local_ip/remote_ip/remote_port")
	}

	bpfTpl := strings.TrimSpace(fmt.Sprintf("%v", capCfg["bpf-filter"]))
	if bpfTpl == "" || bpfTpl == "<nil>" {
		bpfTpl = "tcp and (((src host {local_ip} and dst host {remote_ip} and dst port {remote_port}) or (src host {remote_ip} and src port {remote_port} and dst host {local_ip})))"
	}

	fmtMap := map[string]string{
		"local_ip":    localIP,
		"remote_ip":   remoteIP,
		"remote_port": fmt.Sprintf("%d", remotePort),
		"local_port":  "",
	}
	if localPortFilter != nil {
		fmtMap["local_port"] = fmt.Sprintf("%v", localPortFilter)
	}
	bpf := formatBPF(bpfTpl, fmtMap)

	// restored: if local_port is specified but template doesn't use it, append a cheap filter
	if localPortFilter != nil && !strings.Contains(bpfTpl, "{local_port}") {
		lp := ToInt(localPortFilter, 0)
		if lp > 0 {
			bpf = fmt.Sprintf("(%s) and (tcp port %d)", bpf, lp)
		}
	}

	rt := GetMap(cfg, "runtime")
	rawWorkers := ToInt(rt["workers"], runtime.NumCPU())
	if rawWorkers == 0 {
		rawWorkers = runtime.NumCPU()
	}
	workers := ClampInt(rawWorkers, 4, 1, 256)
	captureQ := ClampInt(rt["capture_queue_size"], 50000, 1000, 5_000_000)

	sessionIdleSec := ToFloat64(capCfg["session_idle_sec"], 120)
	ackStallAny := GetPath(cfg, "io.output.listner.timeouts.ack_stall_sec", nil)
	var ackStall time.Duration
	if ackStallAny != nil {
		ackStall = time.Duration(ToFloat64(ackStallAny, 0) * float64(time.Second))
	}

	ctrl := GetMap(cfg, "control")
	controlBindIP := strings.TrimSpace(fmt.Sprintf("%v", ctrl["bind_ip"]))
	if controlBindIP == "" || controlBindIP == "<nil>" {
		controlBindIP = "0.0.0.0"
	}
	controlPort := ToInt(ctrl["listen_port"], 50005)

	defaultCats := []string{"session", "ports", "output", "control"}
	if v, ok := ctrl["default_cats"].([]any); ok {
		cats := []string{}
		for _, x := range v {
			s := strings.TrimSpace(fmt.Sprintf("%v", x))
			if s != "" {
				cats = append(cats, s)
			}
		}
		if len(cats) > 0 {
			defaultCats = cats
		}
	}

	statsInterval := time.Duration(ToFloat64(GetPath(cfg, "runtime.stats_interval_sec", nil), 5) * float64(time.Second))

	s := &Service{
		cfg:              cfg,
		log:              log,
		iface:            iface,
		localIP:          localIP,
		remoteIP:         remoteIP,
		remotePort:       remotePort,
		localPortFilter:  localPortFilter,
		bpf:              bpf,
		workers:          workers,
		captureQueueSize: captureQ,
		sessionIdle:      time.Duration(sessionIdleSec * float64(time.Second)),
		ackStall:         ackStall,
		controlBindIP:    controlBindIP,
		controlPort:      controlPort,
		defaultCats:      defaultCats,
		forwardQ:         make(chan ForwardChunk, 20000),
		eventQ:           make(chan SessionEvent, 20000),
		sessions:         map[int]map[string]any{},
		sessionBytesOut:  map[int]int64{},
		sessionBytesDrop: map[int]int64{},
		dropCount:        map[dropKey]int64{},
		dropBytes:        map[dropKey]int64{},
		statsInterval:    statsInterval,
	}

	s.control = NewControlPlane(controlBindIP, controlPort, log, defaultCats)
	s.router = &EventRouter{Log: log, CP: s.control}

	return s, nil
}

func (s *Service) StatsSnapshot() map[string]any {
	s.metaMu.Lock()
	defer s.metaMu.Unlock()
	return map[string]any{
		"ts":                     utcISONow(),
		"workers":                s.workers,
		"sessions":               len(s.sessions),
		"bytes_forwarded":        s.bytesForwarded,
		"bytes_dropped":          s.bytesDropped,
		"chunks_forwarded":       s.chunksForwarded,
		"chunks_dropped":         s.chunksDropped,
		"control_bytes_out":      s.control.BytesOut(),
		"control_events_dropped": s.control.EventsDropped(),
	}
}

func (s *Service) ListSessions() []map[string]any {
	s.metaMu.Lock()
	defer s.metaMu.Unlock()
	out := []map[string]any{}
	for sid, meta := range s.sessions {
		out = append(out, map[string]any{
			"session_id":      sid,
			"flow":            meta["flow"],
			"open_ts":         meta["open_ts"],
			"last_ts":         meta["last_ts"],
			"bytes_forwarded": s.sessionBytesOut[sid],
			"bytes_dropped":   s.sessionBytesDrop[sid],
		})
	}
	return out
}

func (s *Service) GetSession(sessionID int) map[string]any {
	s.metaMu.Lock()
	defer s.metaMu.Unlock()
	meta, ok := s.sessions[sessionID]
	if !ok {
		return nil
	}
	drops := map[string]map[string]map[string]any{}
	for k, cnt := range s.dropCount {
		if k.sessionID != sessionID {
			continue
		}
		if _, ok := drops[k.stream]; !ok {
			drops[k.stream] = map[string]map[string]any{}
		}
		drops[k.stream][k.reason] = map[string]any{
			"count": cnt,
			"bytes": s.dropBytes[k],
		}
	}
	return map[string]any{
		"session_id":      sessionID,
		"flow":            meta["flow"],
		"open_ts":         meta["open_ts"],
		"last_ts":         meta["last_ts"],
		"bytes_forwarded": s.sessionBytesOut[sessionID],
		"bytes_dropped":   s.sessionBytesDrop[sessionID],
		"drops":           drops,
	}
}

func (s *Service) CloseSessionByID(sessionID int, reason string) bool {
	if s.outputs == nil {
		return false
	}
	fk, ok := s.outputs.FindBySessionID(sessionID)
	if !ok {
		return false
	}
	s.outputs.CloseSession(fk, reason)
	return true
}

func (s *Service) Start(parent context.Context) error {
	s.ctx, s.cancel = context.WithCancel(parent)

	s.outputs = NewOutputManager(s.cfg, s.router, s.ctx)
	s.control.SetCallbacks(s.StatsSnapshot, s.ListSessions, s.GetSession, s.CloseSessionByID)
	if err := s.control.Start(s.ctx); err != nil {
		return err
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.consumeEvents()
	}()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.consumeForward()
	}()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.periodicStatsLocal()
	}()

	s.workerInqs = make([]chan PacketInfo, 0, s.workers)
	s.workersW = make([]*ReassemblyWorker, 0, s.workers)
	for i := 0; i < s.workers; i++ {
		ch := make(chan PacketInfo, s.captureQueueSize)
		s.workerInqs = append(s.workerInqs, ch)
		w := NewReassemblyWorker(i, ch, s.forwardQ, s.eventQ, s.sessionIdle, s.ackStall)
		s.workersW = append(s.workersW, w)
		s.wg.Add(1)
		go func(w *ReassemblyWorker) {
			defer s.wg.Done()
			w.Run(s.ctx)
		}(w)
	}

	// Capture (maps Python's scapy conf.bufsize to libpcap buffer size when provided)
	var pcapBuf *int
	if v := GetPath(s.cfg, "io.input.capture.scapy_bufsize", nil); v != nil {
		vv := ToInt(v, 0)
		if vv > 0 {
			pcapBuf = &vv
		}
	}
	s.capture = NewCapture(s.iface, s.bpf, s.localIP, s.remoteIP, s.workerInqs, s.log, s.ctx, pcapBuf)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		_ = s.capture.Run()
	}()

	s.router.Emit("control", "service_started", "info", map[string]any{
		"iface":   s.iface,
		"bpf":     s.bpf,
		"workers": s.workers,
	}, true)

	return nil
}

func (s *Service) Stop(ctx context.Context) error {
	s.router.Emit("control", "service_stopping", "info", map[string]any{}, true)
	if s.cancel != nil {
		s.cancel()
	}
	// Close all output sessions.
	if s.outputs != nil {
		for _, fk := range s.outputs.ListFlows() {
			s.outputs.CloseSession(fk, "service_stop")
		}
	}
	if s.control != nil {
		s.control.Close()
	}
	// Wait for shutdown, but honor the provided context.
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) periodicStatsLocal() {
	t := time.NewTicker(s.statsInterval)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			s.router.Emit("stats", "stats", "info", s.StatsSnapshot(), false)
		}
	}
}

func (s *Service) consumeEvents() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case ev := <-s.eventQ:
			s.handleEvent(ev)
		}
	}
}

func (s *Service) handleEvent(ev SessionEvent) {
	sid := ev.Flow.SessionID()
	if ev.Kind == "open" {
		s.metaMu.Lock()
		s.sessions[sid] = map[string]any{"flow": ev.Flow.ToDict(), "open_ts": utcISONow(), "last_ts": utcISONow()}
		s.metaMu.Unlock()

		s.outputs.EnsureSession(ev.Flow)
		s.router.Emit("session", "tcp_open", "info", map[string]any{"flow": ev.Flow.ToDict()}, true)
		return
	}

	if ev.Kind == "close" {
		s.metaMu.Lock()
		meta := s.sessions[sid]
		if meta != nil {
			meta["last_ts"] = utcISONow()
		}
		s.metaMu.Unlock()

		summary := s.GetSession(sid)
		if summary == nil {
			summary = map[string]any{"session_id": sid, "flow": ev.Flow.ToDict()}
		}
		summary["reason"] = ev.Data["reason"]

		s.router.Emit("session", "session_summary", "info", summary, true)
		s.outputs.CloseSession(ev.Flow, fmt.Sprintf("%v", ev.Data["reason"]))
		s.router.Emit("session", "tcp_close", "info", map[string]any{"flow": ev.Flow.ToDict(), "reason": ev.Data["reason"]}, true)

		s.metaMu.Lock()
		delete(s.sessions, sid)
		delete(s.sessionBytesOut, sid)
		delete(s.sessionBytesDrop, sid)
		for k := range s.dropCount {
			if k.sessionID == sid {
				delete(s.dropCount, k)
				delete(s.dropBytes, k)
			}
		}
		s.metaMu.Unlock()
		return
	}

	// note
	payload := map[string]any{"flow": ev.Flow.ToDict()}
	for k, v := range ev.Data {
		payload[k] = v
	}
	// Requested: always DEBUG, including ack_stall
	s.router.Emit("flow", "tcp_note", "debug", payload, true)
}

func (s *Service) consumeForward() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case ch := <-s.forwardQ:
			s.handleChunk(ch)
		}
	}
}

func (s *Service) handleChunk(ch ForwardChunk) {
	sid := ch.Flow.SessionID()
	stream := s.outputs.MapStream(ch.Direction)

	sent, dropped, reason, _ := s.outputs.WriteChunk(ch.Flow, ch.Direction, ch.Data)

	s.metaMu.Lock()
	defer s.metaMu.Unlock()

	if sent > 0 {
		s.bytesForwarded += int64(sent)
		s.chunksForwarded += 1
		s.sessionBytesOut[sid] += int64(sent)
	}
	if dropped > 0 {
		s.bytesDropped += int64(dropped)
		s.chunksDropped += 1
		s.sessionBytesDrop[sid] += int64(dropped)
		k := dropKey{sessionID: sid, stream: stream, reason: reason}
		s.dropCount[k] += 1
		s.dropBytes[k] += int64(dropped)
	}
}

// Convenience: get current process pid for debug.
func (s *Service) PID() int { return os.Getpid() }
