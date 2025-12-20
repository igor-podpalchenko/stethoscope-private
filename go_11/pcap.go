package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type pcapWriter interface {
	WritePacket(ci gopacket.CaptureInfo, data []byte) error
}

type pcapWriterMeta struct {
	writer   pcapWriter
	file     *os.File
	path     string
	base     string
	start    time.Time
	linkType layers.LinkType
}

type pcapItem struct {
	flow     FlowKey
	data     []byte
	ci       gopacket.CaptureInfo
	linkType layers.LinkType
}

type PcapSink struct {
	stats PcapStats
	log   *Logger

	queue chan pcapItem

	mu      sync.Mutex
	writers map[string]*pcapWriterMeta
	statsMu sync.Mutex

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewPcapSink(enabled bool, dir, format string, perSession bool, queueSize int, log *Logger) *PcapSink {
	fmtStr := strings.TrimSpace(strings.ToLower(format))
	if fmtStr == "" {
		fmtStr = "pcapng"
	}
	if fmtStr != "pcap" && fmtStr != "pcapng" {
		fmtStr = "pcapng"
	}
	if queueSize <= 0 {
		queueSize = 20000
	}
	return &PcapSink{
		stats: PcapStats{
			Enabled:    enabled,
			Format:     fmtStr,
			PerSession: perSession,
			Dir:        dir,
			QueueSize:  queueSize,
		},
		log:     log,
		queue:   make(chan pcapItem, queueSize),
		writers: map[string]*pcapWriterMeta{},
	}
}

func (p *PcapSink) Start(parent context.Context) error {
	if !p.stats.Enabled {
		return nil
	}
	if parent == nil {
		parent = context.Background()
	}
	p.ctx, p.cancel = context.WithCancel(parent)

	if p.stats.Dir == "" {
		p.log.Warnf("pcap output disabled: missing dir")
		p.stats.Enabled = false
		return nil
	}
	if err := os.MkdirAll(p.stats.Dir, 0o755); err != nil {
		p.log.Warnf("pcap output disabled: cannot create dir=%s err=%v", p.stats.Dir, err)
		p.stats.Enabled = false
		return nil
	}

	p.log.Infof("pcap output enabled format=%s per_session=%v dir=%s queue=%d", p.stats.Format, p.stats.PerSession, p.stats.Dir, p.stats.QueueSize)

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.run()
	}()
	return nil
}

func (p *PcapSink) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
	p.wg.Wait()
}

func (p *PcapSink) Stats() PcapStats {
	p.statsMu.Lock()
	defer p.statsMu.Unlock()
	return p.stats
}

func (p *PcapSink) flowBase(flow FlowKey) string {
	clean := func(s string) string { return strings.ReplaceAll(s, ":", "_") }
	return fmt.Sprintf("%s_%d__%s_%d", clean(flow.LocalIP), flow.LocalPort, clean(flow.RemoteIP), flow.RemotePort)
}

func (p *PcapSink) writerExt() string {
	if p.stats.Format == "pcap" {
		return "pcap"
	}
	return "pcapng"
}

func (p *PcapSink) openWriter(flow FlowKey, lt layers.LinkType, ci gopacket.CaptureInfo) (*pcapWriterMeta, error) {
	ext := p.writerExt()
	base := "capture"
	if p.stats.PerSession {
		base = p.flowBase(flow)
	}
	startMS := ci.Timestamp.UnixMilli()
	fname := fmt.Sprintf("%s__%d__open.%s", base, startMS, ext)
	path := filepath.Join(p.stats.Dir, fname)

	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}

	var w pcapWriter
	if p.stats.Format == "pcapng" {
		ng, err := pcapgo.NewNgWriter(f, lt)
		if err != nil {
			f.Close()
			return nil, err
		}
		w = ng
	} else {
		pw := pcapgo.NewWriter(f)
		if err := pw.WriteFileHeader(uint32(65535), lt); err != nil {
			f.Close()
			return nil, err
		}
		w = pw
	}

	p.statsMu.Lock()
	p.stats.FilesOpened++
	p.statsMu.Unlock()
	return &pcapWriterMeta{writer: w, file: f, path: path, base: base, start: ci.Timestamp, linkType: lt}, nil
}

func (p *PcapSink) closeWriter(meta *pcapWriterMeta, reason string, end time.Time) {
	if meta == nil {
		return
	}
	if ng, ok := meta.writer.(*pcapgo.NgWriter); ok {
		_ = ng.Flush()
	}
	if meta.file != nil {
		_ = meta.file.Sync()
		_ = meta.file.Close()
	}
	p.statsMu.Lock()
	p.stats.FilesClosed++
	p.statsMu.Unlock()

	ext := p.writerExt()
	endMS := end.UnixMilli()
	startMS := meta.start.UnixMilli()
	newPath := filepath.Join(p.stats.Dir, fmt.Sprintf("%s__%d__%d__%s.%s", meta.base, startMS, endMS, reason, ext))
	if meta.path != "" && meta.path != newPath {
		_ = os.Rename(meta.path, newPath)
	}
}

func (p *PcapSink) writeOne(meta *pcapWriterMeta, item pcapItem) bool {
	if meta == nil || meta.writer == nil {
		return false
	}
	if err := meta.writer.WritePacket(item.ci, item.data); err != nil {
		p.statsMu.Lock()
		p.stats.PktsFailed++
		p.statsMu.Unlock()
		return false
	}
	p.statsMu.Lock()
	p.stats.PktsWritten++
	p.stats.BytesWritten += int64(len(item.data))
	p.statsMu.Unlock()
	return true
}

func (p *PcapSink) enqueue(item pcapItem) {
	select {
	case p.queue <- item:
	default:
		p.statsMu.Lock()
		p.stats.PktsDropped++
		p.statsMu.Unlock()
	}
}

func (p *PcapSink) Enqueue(flow FlowKey, pkt gopacket.Packet) {
	if !p.stats.Enabled || p.queue == nil {
		return
	}
	if p.ctx != nil && p.ctx.Err() != nil {
		return
	}

	data := append([]byte(nil), pkt.Data()...)
	ci := pkt.Metadata().CaptureInfo
	lt := layers.LinkTypeEthernet
	if ll := pkt.LinkLayer(); ll != nil {
		lt = linkTypeFromLayer(ll)
	}

	p.enqueue(pcapItem{flow: flow, data: data, ci: ci, linkType: lt})
}

func linkTypeFromLayer(ll gopacket.Layer) layers.LinkType {
	switch ll.LayerType() {
	case layers.LayerTypeEthernet:
		return layers.LinkTypeEthernet
	case layers.LayerTypeLoopback:
		return layers.LinkTypeLoop
	case layers.LayerTypeLinuxSLL:
		return layers.LinkTypeLinuxSLL
	case layers.LayerTypePPP:
		return layers.LinkTypePPP
	default:
		return layers.LinkTypeEthernet
	}
}

func (p *PcapSink) CloseFlow(flow FlowKey, reason string) {
	p.mu.Lock()
	key := p.flowKey(flow)
	meta := p.writers[key]
	if meta != nil {
		delete(p.writers, key)
	}
	p.mu.Unlock()

	if meta != nil {
		p.closeWriter(meta, reason, time.Now())
	}
}

func (p *PcapSink) flowKey(flow FlowKey) string {
	if p.stats.PerSession {
		return p.flowBase(flow)
	}
	return "global"
}

func (p *PcapSink) handleItem(item pcapItem) {
	p.mu.Lock()
	defer p.mu.Unlock()

	key := p.flowKey(item.flow)
	meta := p.writers[key]
	if meta == nil {
		var err error
		meta, err = p.openWriter(item.flow, item.linkType, item.ci)
		if err != nil {
			p.statsMu.Lock()
			p.stats.PktsFailed++
			p.statsMu.Unlock()
			p.log.Warnf("pcap open failed path=%s err=%v", p.stats.Dir, err)
			return
		}
		p.writers[key] = meta
	}

	if meta.linkType != item.linkType {
		p.closeWriter(meta, "linktype_change", item.ci.Timestamp)
		delete(p.writers, key)
		var err error
		meta, err = p.openWriter(item.flow, item.linkType, item.ci)
		if err != nil {
			p.statsMu.Lock()
			p.stats.PktsFailed++
			p.statsMu.Unlock()
			p.log.Warnf("pcap reopen failed path=%s err=%v", p.stats.Dir, err)
			return
		}
		p.writers[key] = meta
	}

	_ = p.writeOne(meta, item)
}

func (p *PcapSink) run() {
	for {
		select {
		case <-p.ctx.Done():
			p.drainAndClose("stop")
			return
		case item := <-p.queue:
			p.handleItem(item)
		}
	}
}

func (p *PcapSink) drainAndClose(reason string) {
	for {
		select {
		case item := <-p.queue:
			p.handleItem(item)
		default:
			p.mu.Lock()
			writers := p.writers
			p.writers = map[string]*pcapWriterMeta{}
			p.mu.Unlock()
			now := time.Now()
			for _, meta := range writers {
				p.closeWriter(meta, reason, now)
			}
			return
		}
	}
}
