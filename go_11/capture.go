package main

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Capture struct {
	iface    string
	bpf      string
	localIP  string
	remoteIP string

	workers []chan PacketInfo
	log     *Logger

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	pcapBufsize *int
}

func NewCapture(iface, bpf, localIP, remoteIP string, workers []chan PacketInfo, log *Logger, parent context.Context, pcapBufsize *int) *Capture {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	return &Capture{
		iface:       iface,
		bpf:         bpf,
		localIP:     localIP,
		remoteIP:    remoteIP,
		workers:     workers,
		log:         log,
		ctx:         ctx,
		cancel:      cancel,
		pcapBufsize: pcapBufsize,
	}
}

// Run blocks and captures packets until Stop() is called or the parent context is canceled.
// The service starts this in a goroutine, matching the Python prototype.
func (c *Capture) Run() error {
	c.run()
	return nil
}

func (c *Capture) Start() error {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.run()
	}()
	return nil
}

func (c *Capture) Stop() {
	c.cancel()
	c.wg.Wait()
}

func (c *Capture) run() {
	c.log.Infof("capture starting iface=%s bpf=%s", c.iface, c.bpf)

	// Use InactiveHandle so we can set buffer size before activation.
	inactive, err := pcap.NewInactiveHandle(c.iface)
	if err != nil {
		c.log.Errorf("pcap inactive handle error: %v", err)
		return
	}
	defer inactive.CleanUp()

	_ = inactive.SetSnapLen(65535)
	_ = inactive.SetPromisc(true)
	_ = inactive.SetTimeout(1 * time.Second) // timed loop for clean shutdown
	if c.pcapBufsize != nil {
		_ = inactive.SetBufferSize(*c.pcapBufsize)
		c.log.Infof("pcap buffer size=%d", *c.pcapBufsize)
	}

	h, err := inactive.Activate()
	if err != nil {
		c.log.Errorf("pcap activate error: %v", err)
		return
	}
	defer h.Close()

	if err := h.SetBPFFilter(c.bpf); err != nil {
		c.log.Errorf("pcap set filter error: %v", err)
		return
	}

	source := gopacket.NewPacketSource(h, h.LinkType())
	packets := source.Packets()

	for {
		select {
		case <-c.ctx.Done():
			c.log.Infof("capture stopped")
			return
		case pkt, ok := <-packets:
			if !ok {
				if errors.Is(c.ctx.Err(), context.Canceled) {
					c.log.Infof("capture stopped")
					return
				}
				// Packet source ended unexpectedly.
				c.log.Warnf("pcap packet source closed")
				return
			}
			c.handlePacket(pkt)
		}
	}
}

func (c *Capture) handlePacket(pkt gopacket.Packet) {
	ip4L := pkt.Layer(layers.LayerTypeIPv4)
	tcpL := pkt.Layer(layers.LayerTypeTCP)
	if ip4L == nil || tcpL == nil {
		return
	}
	ip4, _ := ip4L.(*layers.IPv4)
	tcp, _ := tcpL.(*layers.TCP)
	if ip4 == nil || tcp == nil {
		return
	}

	src := ip4.SrcIP.String()
	dst := ip4.DstIP.String()

	var localPort, remotePort int
	fromLocal := false
	if src == c.localIP && dst == c.remoteIP {
		localPort = int(tcp.SrcPort)
		remotePort = int(tcp.DstPort)
		fromLocal = true
	} else if src == c.remoteIP && dst == c.localIP {
		localPort = int(tcp.DstPort)
		remotePort = int(tcp.SrcPort)
		fromLocal = false
	} else {
		return
	}

	flow := FlowKey{LocalIP: c.localIP, LocalPort: localPort, RemoteIP: c.remoteIP, RemotePort: remotePort}

	payload := tcp.Payload
	mss, wscale, sackOK := parseTCPOpts(tcp)
	pi := PacketInfo{
		TS:        time.Now(), // match Python's monotime-based capture moment
		Flow:      flow,
		FromLocal: fromLocal,
		Seq:       tcp.Seq,
		Ack:       tcp.Ack,
		Flags:     tcpFlagsByte(tcp),
		Win:       tcp.Window,
		Payload:   payload,
		MSSOpt:    mss,
		WScaleOpt: wscale,
		SackOK:    sackOK,
	}

	idx := 0
	if len(c.workers) > 0 {
		idx = flow.SessionID() % len(c.workers)
		if idx < 0 {
			idx = -idx
		}
	}

	select {
	case c.workers[idx] <- pi:
	default:
		// Drop if worker queue is full (prototype behavior).
		return
	}
}

func tcpFlagsByte(tcp *layers.TCP) uint8 {
	var f uint8
	if tcp.FIN {
		f |= 0x01
	}
	if tcp.SYN {
		f |= 0x02
	}
	if tcp.RST {
		f |= 0x04
	}
	if tcp.PSH {
		f |= 0x08
	}
	if tcp.ACK {
		f |= 0x10
	}
	if tcp.URG {
		f |= 0x20
	}
	if tcp.ECE {
		f |= 0x40
	}
	if tcp.CWR {
		f |= 0x80
	}
	return f
}

func parseTCPOpts(tcp *layers.TCP) (*int, *int, *bool) {
	var mss *int
	var wscale *int
	var sackOK *bool
	for _, opt := range tcp.Options {
		switch opt.OptionType {
		case layers.TCPOptionKindMSS:
			if len(opt.OptionData) >= 2 {
				v := int(opt.OptionData[0])<<8 | int(opt.OptionData[1])
				mss = &v
			}
		case layers.TCPOptionKindWindowScale:
			if len(opt.OptionData) >= 1 {
				v := int(opt.OptionData[0])
				wscale = &v
			}
		case layers.TCPOptionKindSACKPermitted:
			b := true
			sackOK = &b
		}
	}
	return mss, wscale, sackOK
}

// Helper used by Service: runtime.workers == 0 => auto.
func autoWorkers(v int) int {
	if v == 0 {
		return runtime.NumCPU()
	}
	return v
}

func (c *Capture) String() string {
	return fmt.Sprintf("Capture(iface=%s,bpf=%s)", c.iface, c.bpf)
}
