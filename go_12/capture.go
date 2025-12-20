package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// Capture drives the pcap loop and TCP reassembly.
type Capture struct {
	cfg       CaptureConfig
	bpf       string
	log       Logger
	assembler *tcpassembly.Assembler
	pool      *tcpassembly.StreamPool
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	outCh     chan<- Chunk
}

func NewCapture(cfg CaptureConfig, bpf string, log Logger, outCh chan<- Chunk) *Capture {
	return &Capture{cfg: cfg, bpf: bpf, log: log, outCh: outCh}
}

func (c *Capture) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	c.ctx = ctx
	c.cancel = cancel

	factory := &streamFactory{cfg: c.cfg, log: c.log, outCh: c.outCh}
	pool := tcpassembly.NewStreamPool(factory)
	c.pool = pool
	c.assembler = tcpassembly.NewAssembler(pool)
	// Disable global buffered page limit to mirror the Python implementation's
	// unbounded reassembly behavior; the field is an integer, not a setter.
	c.assembler.MaxBufferedPagesTotal = 0

	handle, err := pcap.OpenLive(c.cfg.Iface, 65535, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open pcap: %w", err)
	}
	if c.bpf != "" {
		if err := handle.SetBPFFilter(c.bpf); err != nil {
			handle.Close()
			return fmt.Errorf("bpf filter: %w", err)
		}
	}

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		src := gopacket.NewPacketSource(handle, handle.LinkType())
		src.NoCopy = true
		src.Lazy = true
		for {
			select {
			case <-c.ctx.Done():
				handle.Close()
				return
			case pkt, ok := <-src.Packets():
				if !ok {
					handle.Close()
					return
				}
				c.processPacket(pkt)
			}
		}
	}()

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-c.ctx.Done():
				return
			case <-ticker.C:
				c.assembler.FlushWithOptions(tcpassembly.FlushOptions{CloseAll: false})
			}
		}
	}()

	return nil
}

func (c *Capture) processPacket(pkt gopacket.Packet) {
	tcp := pkt.Layer(layers.LayerTypeTCP)
	ip4 := pkt.Layer(layers.LayerTypeIPv4)
	ip6 := pkt.Layer(layers.LayerTypeIPv6)
	if tcp == nil {
		return
	}
	t := tcp.(*layers.TCP)

	var netFlow gopacket.Flow
	var transportFlow gopacket.Flow

	if ip4 != nil {
		v4 := ip4.(*layers.IPv4)
		netFlow = v4.NetworkFlow()
		transportFlow = t.TransportFlow()
	} else if ip6 != nil {
		v6 := ip6.(*layers.IPv6)
		netFlow = v6.NetworkFlow()
		transportFlow = t.TransportFlow()
	} else {
		return
	}

	c.assembler.AssembleWithTimestamp(netFlow, t, pkt.Metadata().Timestamp)
	_ = transportFlow // silence unused warnings if logging is added later
}

func (c *Capture) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
	c.wg.Wait()
	if c.assembler != nil {
		c.assembler.FlushAll()
	}
}

// streamFactory produces new TCP streams for the assembler.
type streamFactory struct {
	cfg   CaptureConfig
	log   Logger
	outCh chan<- Chunk
}

type stream struct {
	netFlow gopacket.Flow
	tcpFlow gopacket.Flow
	reader  tcpreader.ReaderStream
	cfg     CaptureConfig
	log     Logger
	outCh   chan<- Chunk
	dir     Direction
	flow    Flow
}

func (f *streamFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	s := &stream{netFlow: netFlow, tcpFlow: tcpFlow, cfg: f.cfg, log: f.log, outCh: f.outCh}
	s.reader = tcpreader.NewReaderStream()
	s.detectDirection()
	go s.run()
	return &s.reader
}

func (s *stream) detectDirection() {
	src, dst := s.netFlow.Endpoints()
	tcpSrc, tcpDst := s.tcpFlow.Endpoints()
	s.flow = Flow{SrcIP: src.String(), DstIP: dst.String(), SrcPort: tcpSrc.String(), DstPort: tcpDst.String()}

	localIP := net.ParseIP(s.cfg.LocalIP)
	remoteIP := net.ParseIP(s.cfg.RemoteIP)

	if localIP != nil && src.String() == localIP.String() {
		s.dir = DirClientToServer
	} else if remoteIP != nil && src.String() == remoteIP.String() {
		s.dir = DirServerToClient
	} else if s.cfg.LocalPort != 0 {
		if tcpSrc.String() == fmt.Sprint(s.cfg.LocalPort) {
			s.dir = DirClientToServer
		} else {
			s.dir = DirServerToClient
		}
	} else {
		s.dir = DirClientToServer
	}
}

func (s *stream) run() {
	buf := make([]byte, 4096)
	for {
		n, err := s.reader.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			select {
			case s.outCh <- Chunk{Flow: s.flow, Direction: s.dir, Data: data, SeenAt: time.Now()}:
			default:
				s.log.Warnf("dropping chunk; output channel full")
			}
		}
		if err != nil {
			return
		}
	}
}
