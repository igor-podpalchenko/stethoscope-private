package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultStartupBufferBytes = 64 * 1024
	maxStartupBufferBytes     = 64 * 1024 * 1024
)

type dropKey struct {
	sessionID int
	stream    string
	reason    string
}

type PcapStats struct {
	Enabled      bool
	Format       string
	PerSession   bool
	Dir          string
	QueueSize    int
	PktsWritten  int64
	BytesWritten int64
	PktsDropped  int64
	PktsFailed   int64
	FilesOpened  int64
	FilesClosed  int64
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

	control  *ControlPlane
	router   *EventRouter
	outputs  *OutputManager
	pcapSink *PcapSink

	forwardQ chan ForwardChunk
	eventQ   chan SessionEvent

	startupBufferBytes int
	startupBuffers     map[int]*StartupBuffer
	startupMu          sync.Mutex

	workerInqs []chan PacketInfo
	workersW   []*ReassemblyWorker
	capture    *Capture

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	metaMu            sync.Mutex
	sessions          map[int]map[string]any
	sessionBytesOut   map[int]int64
	sessionBytesDrop  map[int]int64
	sessionChunksOut  map[int]int64
	sessionChunksDrop map[int]int64
	dropCount         map[dropKey]int64
	dropBytes         map[dropKey]int64

	bytesForwarded  int64
	bytesDropped    int64
	chunksForwarded int64
	chunksDropped   int64

	pcap PcapStats

	statsInterval time.Duration
}

type StartupBuffer struct {
	limit  int
	bytes  int
	buf    map[string][][]byte
	active map[string]bool
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
	// Respect configured startup buffer size (per session across directions) while
	// capping to a generous ceiling to avoid unbounded memory growth. The previous
	// hard cap at 64 KiB ignored larger configs and led to avoidable
	// startup_buffer_full drops when outputs connected slowly.
	startupBuf := ClampInt(capCfg["buffer_bytes"], defaultStartupBufferBytes, 0, maxStartupBufferBytes)

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

	logStats := GetMap(cfg, "logging.stats")
	statsAny := logStats["report_interval"]
	if statsAny == nil {
		statsAny = GetPath(cfg, "runtime.stats_interval_sec", nil)
	}
	statsIntervalSec := ToFloat64(statsAny, 5)
	if statsIntervalSec < 0 {
		statsIntervalSec = 0
	}
	statsInterval := time.Duration(statsIntervalSec * float64(time.Second))

	pcapCfg := GetMap(cfg, "io.output.pcap")
	pcapEnabled := GetBool(pcapCfg, "enabled", false)
	pcapFormat := stringsLowerTrim(GetString(pcapCfg, "format", "pcapng"))
	if pcapFormat == "" {
		pcapFormat = "pcapng"
	}
	pcapPerSession := GetBool(pcapCfg, "per_session", false)
	pcapDir := GetString(pcapCfg, "dir", "")
	pcapQueue := ToInt(pcapCfg["queue_size"], 0)
	if pcapQueue <= 0 {
		pcapQueue = 20000
	}
	pcapSink := NewPcapSink(pcapEnabled, pcapDir, pcapFormat, pcapPerSession, pcapQueue, log)
	pcapStats := pcapSink.Stats()

	s := &Service{
		cfg:                cfg,
		log:                log,
		iface:              iface,
		localIP:            localIP,
		remoteIP:           remoteIP,
		remotePort:         remotePort,
		localPortFilter:    localPortFilter,
		bpf:                bpf,
		workers:            workers,
		captureQueueSize:   captureQ,
		sessionIdle:        time.Duration(sessionIdleSec * float64(time.Second)),
		ackStall:           ackStall,
		startupBufferBytes: startupBuf,
		startupBuffers:     map[int]*StartupBuffer{},
		controlBindIP:      controlBindIP,
		controlPort:        controlPort,
		defaultCats:        defaultCats,
		forwardQ:           make(chan ForwardChunk, 20000),
		eventQ:             make(chan SessionEvent, 20000),
		sessions:           map[int]map[string]any{},
		sessionBytesOut:    map[int]int64{},
		sessionBytesDrop:   map[int]int64{},
		sessionChunksOut:   map[int]int64{},
		sessionChunksDrop:  map[int]int64{},
		dropCount:          map[dropKey]int64{},
		dropBytes:          map[dropKey]int64{},
		pcap:               pcapStats,
		pcapSink:           pcapSink,
		statsInterval:      statsInterval,
	}

	s.control = NewControlPlane(controlBindIP, controlPort, log, defaultCats)
	s.router = &EventRouter{Log: log, CP: s.control}

	return s, nil
}

func (s *Service) StatsSnapshot() map[string]any {
	pcapStats := s.pcap
	if s.pcapSink != nil {
		pcapStats = s.pcapSink.Stats()
	}

	s.metaMu.Lock()
	snapshot := map[string]any{
		"ts":               utcISONow(),
		"workers":          s.workers,
		"sessions":         len(s.sessions),
		"bytes_forwarded":  s.bytesForwarded,
		"bytes_dropped":    s.bytesDropped,
		"chunks_forwarded": s.chunksForwarded,
		"chunks_dropped":   s.chunksDropped,
		"pcap": map[string]any{
			"enabled":       pcapStats.Enabled,
			"format":        pcapStats.Format,
			"per_session":   pcapStats.PerSession,
			"dir":           pcapStats.Dir,
			"pkts_written":  pcapStats.PktsWritten,
			"bytes_written": pcapStats.BytesWritten,
			"pkts_dropped":  pcapStats.PktsDropped,
			"pkts_failed":   pcapStats.PktsFailed,
			"files_opened":  pcapStats.FilesOpened,
			"files_closed":  pcapStats.FilesClosed,
		},
	}
	s.metaMu.Unlock()

	snapshot["drop_detail"] = s.DropDetailSnapshot(0)
	snapshot["control_bytes_out"] = s.control.BytesOut()
	snapshot["control_events_dropped"] = s.control.EventsDropped()
	return snapshot
}

func (s *Service) DropDetailSnapshot(topN int) map[string]any {
	s.metaMu.Lock()
	defer s.metaMu.Unlock()

	if len(s.dropCount) == 0 {
		return map[string]any{
			"total_drops":    map[string]any{"count": 0, "bytes": 0},
			"drop_by_why":    map[string]any{},
			"drop_by_stream": map[string]any{},
		}
	}

	byReasonCnt := map[string]int64{}
	byReasonBytes := map[string]int64{}
	byStreamCnt := map[string]int64{}
	byStreamBytes := map[string]int64{}
	var totalCnt int64
	var totalBytes int64

	for k, cnt := range s.dropCount {
		b := s.dropBytes[k]
		totalCnt += cnt
		totalBytes += b

		byReasonCnt[k.reason] += cnt
		byReasonBytes[k.reason] += b
		byStreamCnt[k.stream] += cnt
		byStreamBytes[k.stream] += b
	}

	type reasonKV struct {
		key   string
		bytes int64
	}

	reasons := make([]reasonKV, 0, len(byReasonBytes))
	for r, b := range byReasonBytes {
		reasons = append(reasons, reasonKV{key: r, bytes: b})
	}
	sort.Slice(reasons, func(i, j int) bool { return reasons[i].bytes > reasons[j].bytes })

	if topN > 0 && len(reasons) > topN {
		keep := reasons[:topN]
		rest := reasons[topN:]
		var otherBytes int64
		var otherCnt int64
		for _, r := range rest {
			otherBytes += r.bytes
			otherCnt += byReasonCnt[r.key]
		}
		reasons = keep
		if otherBytes > 0 || otherCnt > 0 {
			byReasonBytes["__other__"] = otherBytes
			byReasonCnt["__other__"] = otherCnt
			reasons = append(reasons, reasonKV{key: "__other__", bytes: otherBytes})
		}
	}

	dropByWhy := map[string]any{}
	for _, r := range reasons {
		dropByWhy[r.key] = map[string]any{
			"count": byReasonCnt[r.key],
			"bytes": byReasonBytes[r.key],
		}
	}

	type streamKV struct {
		key   string
		bytes int64
	}
	streams := make([]streamKV, 0, len(byStreamBytes))
	for sName, b := range byStreamBytes {
		streams = append(streams, streamKV{key: sName, bytes: b})
	}
	sort.Slice(streams, func(i, j int) bool { return streams[i].bytes > streams[j].bytes })

	dropByStream := map[string]any{}
	for _, sInfo := range streams {
		dropByStream[sInfo.key] = map[string]any{
			"count": byStreamCnt[sInfo.key],
			"bytes": byStreamBytes[sInfo.key],
		}
	}

	return map[string]any{
		"total_drops":    map[string]any{"count": totalCnt, "bytes": totalBytes},
		"drop_by_why":    dropByWhy,
		"drop_by_stream": dropByStream,
	}
}

func (s *Service) ListSessions() []map[string]any {
	s.metaMu.Lock()
	defer s.metaMu.Unlock()
	out := []map[string]any{}
	for sid, meta := range s.sessions {
		out = append(out, map[string]any{
			"session_id":       sid,
			"flow":             meta["flow"],
			"open_ts":          meta["open_ts"],
			"last_ts":          meta["last_ts"],
			"bytes_forwarded":  s.sessionBytesOut[sid],
			"bytes_dropped":    s.sessionBytesDrop[sid],
			"chunks_forwarded": s.sessionChunksOut[sid],
			"chunks_dropped":   s.sessionChunksDrop[sid],
		})
	}
	return out
}

func (s *Service) ensureStartupBufferState(sid int) *StartupBuffer {
	s.startupMu.Lock()
	defer s.startupMu.Unlock()

	if sb, ok := s.startupBuffers[sid]; ok {
		return sb
	}

	sb := &StartupBuffer{
		limit:  s.startupBufferBytes,
		bytes:  0,
		buf:    map[string][][]byte{"c2s": [][]byte{}, "s2c": [][]byte{}},
		active: map[string]bool{"c2s": true, "s2c": true},
	}
	s.startupBuffers[sid] = sb
	return sb
}

func (s *Service) flushStartupBuffer(flow FlowKey, direction string, sb *StartupBuffer) {
	sid := flow.SessionID()
	stream := s.outputs.MapStream(direction)

	for {
		s.startupMu.Lock()
		q := sb.buf[direction]
		if len(q) == 0 {
			sb.active[direction] = false
			s.startupMu.Unlock()
			return
		}
		data := q[0]
		sb.buf[direction] = q[1:]
		sb.bytes -= len(data)
		s.startupMu.Unlock()

		sent, dropped, reason, _ := s.outputs.WriteChunk(flow, direction, data)
		s.accountForwardResult(sid, stream, sent, dropped, reason)
	}
}

func (s *Service) discardStartupBuffers(flow FlowKey, reason string) {
	sid := flow.SessionID()

	s.startupMu.Lock()
	sb, ok := s.startupBuffers[sid]
	if !ok {
		s.startupMu.Unlock()
		return
	}

	bufCopy := map[string][][]byte{
		"c2s": append([][]byte{}, sb.buf["c2s"]...),
		"s2c": append([][]byte{}, sb.buf["s2c"]...),
	}
	delete(s.startupBuffers, sid)
	s.startupMu.Unlock()

	for _, direction := range []string{"c2s", "s2c"} {
		stream := s.outputs.MapStream(direction)
		var droppedBytes int
		chunks := len(bufCopy[direction])
		for _, data := range bufCopy[direction] {
			droppedBytes += len(data)
		}
		if droppedBytes > 0 {
			s.accountLocalDrop(sid, stream, droppedBytes, reason, chunks)
		}
	}
}

func (s *Service) flushStartupBuffersOnClose(flow FlowKey, reason string) {
	if s.startupBufferBytes <= 0 {
		return
	}
	sid := flow.SessionID()

	closeGraceMS := ClampInt(GetPath(s.cfg, "runtime.close_grace_ms", 100), 100, 0, 10_000)
	if closeGraceMS > 0 {
		time.Sleep(time.Duration(closeGraceMS) * time.Millisecond)
	}

	s.startupMu.Lock()
	sb, ok := s.startupBuffers[sid]
	if !ok {
		s.startupMu.Unlock()
		return
	}
	buffered := sb.bytes
	s.startupMu.Unlock()

	if buffered <= 0 {
		s.startupMu.Lock()
		delete(s.startupBuffers, sid)
		s.startupMu.Unlock()
		return
	}

	lingerSec := ToFloat64(GetPath(s.cfg, "runtime.close_linger_sec", 2.0), 2.0)
	if lingerSec < 0 {
		lingerSec = 0
	}
	deadline := time.Now().Add(time.Duration(lingerSec * float64(time.Second)))

	for _, direction := range []string{"c2s", "s2c"} {
		for {
			s.startupMu.Lock()
			empty := len(sb.buf[direction]) == 0
			s.startupMu.Unlock()
			if empty {
				s.startupMu.Lock()
				sb.active[direction] = false
				s.startupMu.Unlock()
				break
			}

			if s.outputs.HasActiveTargets(flow, direction) {
				s.flushStartupBuffer(flow, direction, sb)
				break
			}

			if time.Now().After(deadline) {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	s.startupMu.Lock()
	leftover := sb.bytes
	s.startupMu.Unlock()

	if leftover > 0 {
		s.discardStartupBuffers(flow, "startup_buffer_discard_on_close")
	} else {
		s.startupMu.Lock()
		delete(s.startupBuffers, sid)
		s.startupMu.Unlock()
	}
}

func (s *Service) accountForwardResult(sid int, stream string, sent int, dropped int, reason string) {
	s.metaMu.Lock()
	defer s.metaMu.Unlock()

	if sent > 0 {
		s.bytesForwarded += int64(sent)
		s.chunksForwarded += 1
		s.sessionBytesOut[sid] += int64(sent)
		s.sessionChunksOut[sid] += 1
	}

	if dropped > 0 {
		s.bytesDropped += int64(dropped)
		s.chunksDropped += 1
		s.sessionBytesDrop[sid] += int64(dropped)
		s.sessionChunksDrop[sid] += 1
		k := dropKey{sessionID: sid, stream: stream, reason: reason}
		s.dropCount[k] += 1
		s.dropBytes[k] += int64(dropped)
	}
}

func (s *Service) accountLocalDrop(sid int, stream string, dropped int, reason string, chunks int) {
	if dropped <= 0 {
		return
	}

	s.metaMu.Lock()
	defer s.metaMu.Unlock()

	s.bytesDropped += int64(dropped)
	s.sessionBytesDrop[sid] += int64(dropped)

	if chunks > 0 {
		s.chunksDropped += int64(chunks)
		s.sessionChunksDrop[sid] += int64(chunks)
		k := dropKey{sessionID: sid, stream: stream, reason: reason}
		s.dropCount[k] += int64(chunks)
	}

	k := dropKey{sessionID: sid, stream: stream, reason: reason}
	s.dropBytes[k] += int64(dropped)
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
		"session_id":       sessionID,
		"flow":             meta["flow"],
		"open_ts":          meta["open_ts"],
		"last_ts":          meta["last_ts"],
		"bytes_forwarded":  s.sessionBytesOut[sessionID],
		"bytes_dropped":    s.sessionBytesDrop[sessionID],
		"chunks_forwarded": s.sessionChunksOut[sessionID],
		"chunks_dropped":   s.sessionChunksDrop[sessionID],
		"drops":            drops,
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
	if s.pcapSink != nil {
		_ = s.pcapSink.Start(s.ctx)
		s.pcap = s.pcapSink.Stats()
	}
	if s.pcap.Enabled {
		s.log.Infof("pcap output enabled format=%s per_session=%v dir=%s queue=%d", s.pcap.Format, s.pcap.PerSession, s.pcap.Dir, s.pcap.QueueSize)
	}
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

	if s.statsInterval > 0 {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.periodicStatsLocal()
		}()
	}

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
	s.capture = NewCapture(s.iface, s.bpf, s.localIP, s.remoteIP, s.workerInqs, s.log, s.ctx, pcapBuf, s.pcapSink)
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
	if s.pcapSink != nil {
		s.pcapSink.Stop()
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

		if s.startupBufferBytes > 0 {
			s.ensureStartupBufferState(sid)
		}

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

		if s.startupBufferBytes > 0 {
			s.flushStartupBuffersOnClose(ev.Flow, fmt.Sprintf("%v", ev.Data["reason"]))
		}

		s.router.Emit("session", "session_summary", "info", summary, true)
		s.outputs.CloseSession(ev.Flow, fmt.Sprintf("%v", ev.Data["reason"]))
		if s.pcapSink != nil {
			s.pcapSink.CloseFlow(ev.Flow, fmt.Sprintf("%v", ev.Data["reason"]))
		}
		s.router.Emit("session", "tcp_close", "info", map[string]any{"flow": ev.Flow.ToDict(), "reason": ev.Data["reason"]}, true)

		s.metaMu.Lock()
		delete(s.sessions, sid)
		delete(s.sessionBytesOut, sid)
		delete(s.sessionBytesDrop, sid)
		delete(s.sessionChunksOut, sid)
		delete(s.sessionChunksDrop, sid)
		for k := range s.dropCount {
			if k.sessionID == sid {
				delete(s.dropCount, k)
				delete(s.dropBytes, k)
			}
		}
		s.metaMu.Unlock()

		s.startupMu.Lock()
		delete(s.startupBuffers, sid)
		s.startupMu.Unlock()
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
			sid := ch.Flow.SessionID()
			stream := s.outputs.MapStream(ch.Direction)

			if s.startupBufferBytes > 0 {
				sb := s.ensureStartupBufferState(sid)
				s.startupMu.Lock()
				active := sb.active[ch.Direction]
				s.startupMu.Unlock()

				if active {
					if s.outputs.HasActiveTargets(ch.Flow, ch.Direction) {
						s.flushStartupBuffer(ch.Flow, ch.Direction, sb)
					} else {
						s.startupMu.Lock()
						remaining := sb.limit - sb.bytes
						s.startupMu.Unlock()
						if remaining <= 0 {
							s.accountLocalDrop(sid, stream, len(ch.Data), "startup_buffer_full", 1)
							continue
						}

						if len(ch.Data) <= remaining {
							s.startupMu.Lock()
							sb.buf[ch.Direction] = append(sb.buf[ch.Direction], ch.Data)
							sb.bytes += len(ch.Data)
							s.startupMu.Unlock()
						} else {
							s.startupMu.Lock()
							sb.buf[ch.Direction] = append(sb.buf[ch.Direction], ch.Data[:remaining])
							sb.bytes += remaining
							s.startupMu.Unlock()
							s.accountLocalDrop(sid, stream, len(ch.Data)-remaining, "startup_buffer_full", 1)
						}
						continue
					}
				}
			}

			s.handleChunk(ch)
		}
	}
}

func (s *Service) handleChunk(ch ForwardChunk) {
	sid := ch.Flow.SessionID()
	stream := s.outputs.MapStream(ch.Direction)

	sent, dropped, reason, _ := s.outputs.WriteChunk(ch.Flow, ch.Direction, ch.Data)
	s.accountForwardResult(sid, stream, sent, dropped, reason)
}

// Convenience: get current process pid for debug.
func (s *Service) PID() int { return os.Getpid() }
