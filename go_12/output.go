package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// OutputManager forwards reconstructed TCP payloads to configured sinks.
type OutputManager struct {
	cfg       OutputConfig
	log       Logger
	requests  *tcpTarget
	responses *tcpTarget
}

func NewOutputManager(cfg OutputConfig, log Logger) *OutputManager {
	om := &OutputManager{cfg: cfg, log: log}
	if cfg.RemoteHost.Enabled {
		om.requests = newTCPTarget(cfg.RemoteHost.Host, cfg.RemoteHost.RequestsPort, cfg.RemoteHost.Timeouts, log)
		om.responses = newTCPTarget(cfg.RemoteHost.Host, cfg.RemoteHost.ResponsesPort, cfg.RemoteHost.Timeouts, log)
	}
	return om
}

// WriteChunk delivers a chunk to the appropriate output.
func (o *OutputManager) WriteChunk(ctx context.Context, ch Chunk) {
	if o.requests == nil && o.responses == nil {
		return
	}
	switch ch.Direction {
	case DirClientToServer:
		if o.requests != nullTarget {
			o.requests.send(ctx, ch)
		}
	case DirServerToClient:
		if o.responses != nullTarget {
			o.responses.send(ctx, ch)
		}
	}
}

var nullTarget = &tcpTarget{}

// tcpTarget maintains a single persistent TCP connection with automatic reconnects.
type tcpTarget struct {
	address string
	timeout time.Duration
	retry   time.Duration
	mu      sync.Mutex
	conn    net.Conn
	log     Logger
}

func newTCPTarget(host string, port int, t TimeoutConfig, log Logger) *tcpTarget {
	timeout := time.Duration(t.Connect) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	retry := time.Duration(t.RetryEvery) * time.Second
	if retry <= 0 {
		retry = 5 * time.Second
	}
	return &tcpTarget{
		address: fmt.Sprintf("%s:%d", host, port),
		timeout: timeout,
		retry:   retry,
		log:     log,
	}
}

func (t *tcpTarget) send(ctx context.Context, ch Chunk) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn == nil {
		if err := t.connectLocked(); err != nil {
			t.log.Warnf("output connect %s failed: %v", t.address, err)
			return
		}
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = t.conn.SetWriteDeadline(deadline)
	} else {
		_ = t.conn.SetWriteDeadline(time.Now().Add(t.timeout))
	}

	_, err := t.conn.Write(ch.Data)
	if err == nil {
		return
	}

	t.log.Warnf("output write to %s failed, reconnecting: %v", t.address, err)
	_ = t.conn.Close()
	t.conn = nil

	// attempt reconnect once
	if err := t.connectLocked(); err != nil {
		t.log.Warnf("output reconnect %s failed: %v", t.address, err)
		return
	}
	if _, err := t.conn.Write(ch.Data); err != nil {
		t.log.Warnf("output write after reconnect %s failed: %v", t.address, err)
	}
}

func (t *tcpTarget) connectLocked() error {
	if t.address == "" {
		return fmt.Errorf("missing address")
	}
	var d net.Dialer
	d.Timeout = t.timeout
	conn, err := d.Dial("tcp", t.address)
	if err != nil {
		return err
	}
	t.conn = conn
	t.log.Infof("connected to %s", t.address)
	return nil
}

func (t *tcpTarget) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn != nil {
		_ = t.conn.Close()
		t.conn = nil
	}
}
