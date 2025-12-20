package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket/tcpassembly"
)

// Service wires capture and output pieces together.
type Service struct {
	cfg     Config
	log     Logger
	outMgr  *OutputManager
	capture *Capture
	chunks  chan Chunk
	cancel  context.CancelFunc
	ctx     context.Context
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

func NewService(cfg Config, log Logger) (*Service, error) {
	capCfg := cfg.IO.Input.Capture
	if capCfg.Iface == "" || capCfg.LocalIP == "" || capCfg.RemoteIP == "" || capCfg.RemotePort == 0 {
		return nil, fmt.Errorf("missing io.input.capture fields")
	}

	bpfTpl := strings.TrimSpace(capCfg.BPFFilter)
	if bpfTpl == "" {
		bpfTpl = "tcp and (((src host {local_ip} and dst host {remote_ip} and dst port {remote_port}) or (src host {remote_ip} and src port {remote_port} and dst host {local_ip})))"
	}

	replacements := map[string]string{
		"local_ip":    capCfg.LocalIP,
		"remote_ip":   capCfg.RemoteIP,
		"remote_port": fmt.Sprintf("%d", capCfg.RemotePort),
		"local_port":  "",
	}
	if capCfg.LocalPort != 0 {
		replacements["local_port"] = fmt.Sprintf("%d", capCfg.LocalPort)
	}

	bpf := formatBPF(bpfTpl, replacements)
	if capCfg.LocalPort != 0 && !strings.Contains(bpfTpl, "{local_port}") {
		bpf = fmt.Sprintf("(%s) and (tcp port %d)", bpf, capCfg.LocalPort)
	}

	chunks := make(chan Chunk, 1024)
	outMgr := NewOutputManager(cfg.IO.Output, log)
	capture := NewCapture(capCfg, bpf, log, chunks)

	ctx, cancel := context.WithCancel(context.Background())
	return &Service{cfg: cfg, log: log, outMgr: outMgr, capture: capture, chunks: chunks, ctx: ctx, cancel: cancel}, nil
}

// Start begins packet capture and forwarding.
func (s *Service) Start() error {
	if err := s.capture.Start(); err != nil {
		return err
	}
	go s.forwardLoop()
	s.log.Infof("capture started on %s with filter '%s'", s.cfg.IO.Input.Capture.Iface, s.capture.bpf)
	return nil
}

// Stop terminates the capture and cleans up output targets.
func (s *Service) Stop() {
	s.cancel()
	s.capture.Stop()
	if s.outMgr.requests != nil {
		s.outMgr.requests.Close()
	}
	if s.outMgr.responses != nil {
		s.outMgr.responses.Close()
	}
}

func (s *Service) forwardLoop() {
	idle := time.Duration(s.cfg.IO.Input.Capture.SessionIdleSec * float64(time.Second))
	if idle <= 0 {
		idle = 2 * time.Minute
	}
	timer := time.NewTimer(idle)
	defer timer.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case ch := <-s.chunks:
			s.outMgr.WriteChunk(s.ctx, ch)
			if !timer.Stop() {
				<-timer.C
			}
			timer.Reset(idle)
		case <-timer.C:
			// Periodic wake-up prevents idle goroutine leaks in tcpassembly.
			s.capture.assembler.FlushWithOptions(tcpassembly.FlushOptions{CloseAll: false})
			timer.Reset(idle)
		}
	}
}
