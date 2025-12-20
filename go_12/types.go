package main

import (
	"net"
	"time"
)

// Direction enumerates stream directions.
type Direction string

const (
	DirClientToServer Direction = "c2s"
	DirServerToClient Direction = "s2c"
)

// Flow identifies a TCP flow.
type Flow struct {
	SrcIP   string `json:"src_ip"`
	SrcPort string `json:"src_port"`
	DstIP   string `json:"dst_ip"`
	DstPort string `json:"dst_port"`
}

// Chunk represents a reassembled data fragment ready for forwarding.
type Chunk struct {
	Flow      Flow
	Direction Direction
	Data      []byte
	SeenAt    time.Time
}

// ConnKey helps identify directions inside the assembler.
type ConnKey struct {
	Network   string
	Transport string
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
}
