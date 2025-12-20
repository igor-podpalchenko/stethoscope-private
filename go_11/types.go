package main

import (
	"sort"
	"time"
)

type FlowKey struct {
	LocalIP    string
	LocalPort  int
	RemoteIP   string
	RemotePort int
}

func (fk FlowKey) SessionID() int { return fk.LocalPort }

func (fk FlowKey) ToDict() map[string]any {
	return map[string]any{
		"local_ip":    fk.LocalIP,
		"local_port":  fk.LocalPort,
		"remote_ip":   fk.RemoteIP,
		"remote_port": fk.RemotePort,
		"session_id":  fk.SessionID(),
	}
}

type PacketInfo struct {
	TS        time.Time
	Flow      FlowKey
	FromLocal bool
	Seq       uint32
	Ack       uint32
	Flags     uint8
	Win       uint16
	Payload   []byte

	MSSOpt    *int
	WScaleOpt *int
	SackOK    *bool
}

type SessionEvent struct {
	Kind string // open|close|note
	Flow FlowKey
	TS   time.Time
	Data map[string]any
}

type ForwardChunk struct {
	Flow      FlowKey
	TS        time.Time
	Direction string // c2s|s2c
	Data      []byte
}

func utcISO(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

func utcISONow() string { return utcISO(time.Now()) }

// SortStrings/SortInts are small helpers kept as named wrappers
// because earlier iterations referenced them directly.
func SortStrings(xs []string) { sort.Strings(xs) }
func SortInts(xs []int)       { sort.Ints(xs) }
