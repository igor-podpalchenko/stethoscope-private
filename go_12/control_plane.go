package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ControlPlane mirrors the TCP control interface from go_11.
type ControlPlane struct {
	BindIP string
	Port   int
	Log    Logger

	serverMu sync.Mutex
	listener net.Listener

	clientMu     sync.Mutex
	clientConn   net.Conn
	clientClosed bool

	events chan map[string]any

	bytesOut      atomic.Int64
	eventsDropped atomic.Int64

	defaultCats map[string]bool
	cats        map[string]bool

	flowMu       sync.Mutex
	flowGlobal   bool
	flowSessions map[int]bool

	cbMu           sync.Mutex
	getStatsCb     func() map[string]any
	listSessionsCb func() []map[string]any
	getSessionCb   func(int) map[string]any
	closeSessionCb func(int, string) bool
}

func NewControlPlane(bindIP string, port int, log Logger, defaultCats []string) *ControlPlane {
	dc := map[string]bool{}
	for _, c := range defaultCats {
		c = strings.TrimSpace(c)
		if c != "" {
			dc[c] = true
		}
	}
	cats := map[string]bool{}
	for k := range dc {
		cats[k] = true
	}
	return &ControlPlane{
		BindIP:       bindIP,
		Port:         port,
		Log:          log,
		events:       make(chan map[string]any, 10000),
		defaultCats:  dc,
		cats:         cats,
		flowSessions: map[int]bool{},
	}
}

func (cp *ControlPlane) SetCallbacks(getStats func() map[string]any, listSessions func() []map[string]any, getSession func(int) map[string]any, closeSession func(int, string) bool) {
	cp.cbMu.Lock()
	defer cp.cbMu.Unlock()
	cp.getStatsCb = getStats
	cp.listSessionsCb = listSessions
	cp.getSessionCb = getSession
	cp.closeSessionCb = closeSession
}

func (cp *ControlPlane) BytesOut() int64      { return cp.bytesOut.Load() }
func (cp *ControlPlane) EventsDropped() int64 { return cp.eventsDropped.Load() }

func (cp *ControlPlane) CPEnabled() bool {
	cp.clientMu.Lock()
	defer cp.clientMu.Unlock()
	return cp.clientConn != nil && !cp.clientClosed
}

// Enabled is a compatibility alias.
func (cp *ControlPlane) Enabled() bool { return cp.CPEnabled() }

func (cp *ControlPlane) CatEnabled(cat string) bool {
	cp.clientMu.Lock()
	defer cp.clientMu.Unlock()
	return cp.cats[cat]
}

func (cp *ControlPlane) Cats() map[string]bool {
	cp.clientMu.Lock()
	defer cp.clientMu.Unlock()
	out := map[string]bool{}
	for k, v := range cp.cats {
		out[k] = v
	}
	return out
}

func (cp *ControlPlane) ResetSubscribe() {
	cp.clientMu.Lock()
	defer cp.clientMu.Unlock()
	cp.cats = map[string]bool{}
	for k := range cp.defaultCats {
		cp.cats[k] = true
	}
}

func (cp *ControlPlane) Subscribe(cats []string) {
	m := map[string]bool{}
	for _, c := range cats {
		c = strings.TrimSpace(c)
		if c != "" {
			m[c] = true
		}
	}
	cp.clientMu.Lock()
	cp.cats = m
	cp.clientMu.Unlock()
}

func (cp *ControlPlane) FlowEnabledFor(sessionID *int) bool {
	cp.flowMu.Lock()
	defer cp.flowMu.Unlock()
	if cp.flowGlobal {
		return true
	}
	if sessionID == nil {
		return false
	}
	return cp.flowSessions[*sessionID]
}

func (cp *ControlPlane) SetFlow(enable bool, sessionID *int) {
	cp.flowMu.Lock()
	defer cp.flowMu.Unlock()
	if sessionID == nil {
		cp.flowGlobal = enable
		if !enable {
			cp.flowSessions = map[int]bool{}
		}
		return
	}
	if enable {
		cp.flowSessions[*sessionID] = true
	} else {
		delete(cp.flowSessions, *sessionID)
	}
}

func (cp *ControlPlane) EmitRaw(ev map[string]any) {
	select {
	case cp.events <- ev:
	default:
		cp.eventsDropped.Add(1)
	}
}

func (cp *ControlPlane) Start(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", cp.BindIP, cp.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	cp.serverMu.Lock()
	cp.listener = ln
	cp.serverMu.Unlock()

	if cp.Log != nil {
		cp.Log.Infof("control plane listening on %s", addr)
	}
	stop := ctx.Done()
	go cp.eventPump(stop)
	go cp.acceptLoop(stop)
	return nil
}

func (cp *ControlPlane) Close() {
	cp.serverMu.Lock()
	ln := cp.listener
	cp.listener = nil
	cp.serverMu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	cp.clientMu.Lock()
	if cp.clientConn != nil {
		_ = cp.clientConn.Close()
		cp.clientConn = nil
		cp.clientClosed = true
	}
	cp.clientMu.Unlock()
}

func (cp *ControlPlane) acceptLoop(stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		default:
		}
		cp.serverMu.Lock()
		ln := cp.listener
		cp.serverMu.Unlock()
		if ln == nil {
			return
		}
		conn, err := ln.Accept()
		if err != nil {
			// listener closed => exit
			return
		}
		go cp.handleClient(conn)
	}
}

func (cp *ControlPlane) handleClient(conn net.Conn) {
	peer := conn.RemoteAddr().String()

	// Only one active client: close previous.
	cp.clientMu.Lock()
	if cp.clientConn != nil {
		_ = cp.clientConn.Close()
	}
	cp.clientConn = conn
	cp.clientClosed = false
	cp.clientMu.Unlock()

	cp.EmitRaw(map[string]any{"ts": utcISONow(), "cat": "control", "event": "control_connected", "peer": peer})

	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			break
		}
		line = bytesTrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var cmd map[string]any
		if err := json.Unmarshal(line, &cmd); err != nil {
			cp.EmitRaw(map[string]any{"ts": utcISONow(), "cat": "control", "event": "control_error", "error": "bad_json"})
			continue
		}
		cp.handleCmd(cmd)
	}

	cp.clientMu.Lock()
	if cp.clientConn == conn {
		cp.clientConn = nil
		cp.clientClosed = true
	}
	cp.clientMu.Unlock()
	_ = conn.Close()
	cp.EmitRaw(map[string]any{"ts": utcISONow(), "cat": "control", "event": "control_disconnected", "peer": peer})
}

func (cp *ControlPlane) reply(replyTo string, payload map[string]any) {
	ev := map[string]any{"ts": utcISONow(), "cat": "control", "event": "control_reply", "reply_to": replyTo}
	for k, v := range payload {
		ev[k] = v
	}
	cp.EmitRaw(ev)
}

func (cp *ControlPlane) handleCmd(cmd map[string]any) {
	c := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", cmd["cmd"])))

	cp.cbMu.Lock()
	getStats := cp.getStatsCb
	listSessions := cp.listSessionsCb
	getSession := cp.getSessionCb
	closeSession := cp.closeSessionCb
	cp.cbMu.Unlock()

	switch c {
	case "ping", "hello":
		cp.reply(c, map[string]any{"ok": true})
		return
	case "stats", "get_stats":
		s := map[string]any{}
		if getStats != nil {
			s = getStats()
		}
		cp.reply(c, map[string]any{"ok": true, "stats": s})
		return
	case "subscribe":
		raw := cmd["cats"]
		lst, ok := raw.([]any)
		if !ok {
			cp.reply(c, map[string]any{"ok": false, "error": "cats must be list"})
			return
		}
		cats := make([]string, 0, len(lst))
		for _, x := range lst {
			cats = append(cats, fmt.Sprintf("%v", x))
		}
		cp.Subscribe(cats)
		cp.reply(c, map[string]any{"ok": true, "cats": sortedKeys(cp.Cats())})
		return
	case "subscribe_default":
		cp.ResetSubscribe()
		cp.reply(c, map[string]any{"ok": true, "cats": sortedKeys(cp.Cats())})
		return
	case "tcp_flow_enable", "tcp_flow_disable":
		enable := (c == "tcp_flow_enable")
		var sidPtr *int
		if cmd["session_id"] != nil {
			sid := ToInt(cmd["session_id"], 0)
			sidPtr = &sid
		}
		cp.SetFlow(enable, sidPtr)
		cp.flowMu.Lock()
		fg := cp.flowGlobal
		sessions := sortedIntKeys(cp.flowSessions)
		cp.flowMu.Unlock()
		cp.reply(c, map[string]any{"ok": true, "flow_global": fg, "flow_sessions": sessions})
		return
	case "list_sessions":
		lst2 := []map[string]any{}
		if listSessions != nil {
			lst2 = listSessions()
		}
		cp.reply(c, map[string]any{"ok": true, "sessions": lst2})
		return
	case "get_session":
		if cmd["session_id"] == nil {
			cp.reply(c, map[string]any{"ok": false, "error": "missing_session_id"})
			return
		}
		sid := ToInt(cmd["session_id"], 0)
		var s map[string]any
		if getSession != nil {
			s = getSession(sid)
		}
		if s == nil || len(s) == 0 {
			cp.reply(c, map[string]any{"ok": false, "error": "not_found"})
			return
		}
		cp.reply(c, map[string]any{"ok": true, "session": s})
		return
	case "close_session", "close":
		if cmd["session_id"] == nil {
			cp.reply(c, map[string]any{"ok": false, "error": "missing_session_id"})
			return
		}
		sid := ToInt(cmd["session_id"], 0)
		ok := false
		if closeSession != nil {
			ok = closeSession(sid, "control_close")
		}
		cp.reply(c, map[string]any{"ok": ok, "session_id": sid})
		return
	default:
		cp.reply(c, map[string]any{"ok": false, "error": "unknown_cmd"})
		return
	}
}

func (cp *ControlPlane) eventPump(stop <-chan struct{}) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case ev := <-cp.events:
			cp.writeEvent(ev)
		case <-ticker.C:
			// keep loop responsive
		}
	}
}

func (cp *ControlPlane) writeEvent(ev map[string]any) {
	cp.clientMu.Lock()
	conn := cp.clientConn
	closed := cp.clientClosed
	cp.clientMu.Unlock()
	if conn == nil || closed {
		return
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	b = append(b, '\n')
	_, _ = conn.Write(b)
	cp.bytesOut.Add(int64(len(b)))
}

func bytesTrimSpace(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k, v := range m {
		if v {
			keys = append(keys, k)
		}
	}
	SortStrings(keys)
	return keys
}

func sortedIntKeys(m map[int]bool) []int {
	keys := make([]int, 0, len(m))
	for k, v := range m {
		if v {
			keys = append(keys, k)
		}
	}
	SortInts(keys)
	return keys
}
