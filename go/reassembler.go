package main

import (
	"bytes"
	"sort"
	"time"
)

const MaxOOOSegments = 4096

type TCPReassembler struct {
	NextSeq      *uint32
	Segments     map[uint32][]byte
	EmittedBytes int64

	RetransmitDrop  int64
	RetransmitDup   int64
	OverlapTrim     int64
	OverlapDrop     int64
	OverlapConflict int64
	OOOEvictions    int64
}

func NewTCPReassembler() TCPReassembler {
	return TCPReassembler{Segments: make(map[uint32][]byte)}
}

func (r *TCPReassembler) recomputeNextSeqPreEmit() {
	if r.EmittedBytes != 0 || len(r.Segments) == 0 {
		return
	}
	// min key
	var mn *uint32
	for k := range r.Segments {
		kk := k
		if mn == nil || kk < *mn {
			mn = &kk
		}
	}
	if mn == nil {
		return
	}
	if r.NextSeq == nil || *mn < *r.NextSeq {
		r.NextSeq = mn
	}
}

type segPart struct {
	seq  uint32
	data []byte
	tag  string // old/new
}

func (r *TCPReassembler) mergeUnionConflictSafe(seq uint32, data []byte) {
	union0 := seq
	union1 := seq + uint32(len(data))
	parts := []segPart{{seq: seq, data: data, tag: "new"}}

	changed := true
	for changed {
		changed = false
		for k, v := range r.Segments {
			k0 := k
			k1 := k + uint32(len(v))
			// overlap or adjacency
			overlap := !(union1 < k0 || k1 < union0) && !(union1 == k0 || k1 == union0)
			adj := (union1 == k0) || (k1 == union0)
			if overlap || adj {
				parts = append(parts, segPart{seq: k, data: v, tag: "old"})
				delete(r.Segments, k)
				if k0 < union0 {
					union0 = k0
				}
				if k1 > union1 {
					union1 = k1
				}
				changed = true
			}
		}
	}

	if len(parts) == 1 {
		r.Segments[seq] = data
		return
	}

	buf := make([]byte, int(union1-union0))
	filled := make([]byte, int(union1-union0))

	// old first
	sort.Slice(parts, func(i, j int) bool {
		if parts[i].tag == parts[j].tag {
			return parts[i].seq < parts[j].seq
		}
		return parts[i].tag == "old"
	})

	var conflict int64
	for _, p := range parts {
		off := int(p.seq - union0)
		for i, b := range p.data {
			idx := off + i
			if filled[idx] != 0 {
				if p.tag == "new" && buf[idx] != b {
					conflict++
				}
				continue
			}
			buf[idx] = b
			filled[idx] = 1
		}
	}
	if conflict > 0 {
		r.OverlapConflict += conflict
	}
	// store merged union
	r.Segments[union0] = buf
}

func (r *TCPReassembler) Add(seq uint32, data []byte) {
	if len(data) == 0 {
		return
	}

	if r.NextSeq == nil {
		s := seq
		r.NextSeq = &s
	}

	if r.EmittedBytes > 0 && r.NextSeq != nil {
		next := *r.NextSeq
		if seq+uint32(len(data)) <= next {
			r.RetransmitDrop++
			return
		}
		if seq < next {
			overlap := next - seq
			if overlap >= uint32(len(data)) {
				r.OverlapDrop++
				return
			}
			r.OverlapTrim++
			data = data[overlap:]
			seq = next
		}
	}

	if prev, ok := r.Segments[seq]; ok {
		if bytes.Equal(prev, data) {
			r.RetransmitDup++
			return
		}
		if len(prev) >= len(data) && bytes.Equal(prev[:len(data)], data) {
			r.RetransmitDup++
			return
		}
	}

	r.mergeUnionConflictSafe(seq, data)

	if len(r.Segments) > MaxOOOSegments {
		keys := make([]uint32, 0, len(r.Segments))
		for k := range r.Segments {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] > keys[j] })
		excess := len(keys) - MaxOOOSegments
		for i := 0; i < excess; i++ {
			delete(r.Segments, keys[i])
			r.OOOEvictions++
		}
	}

	r.recomputeNextSeqPreEmit()
}

func (r *TCPReassembler) PopContiguous() []byte {
	if len(r.Segments) == 0 {
		return nil
	}
	if r.NextSeq == nil {
		// min key
		var mn uint32
		first := true
		for k := range r.Segments {
			if first || k < mn {
				mn = k
				first = false
			}
		}
		r.NextSeq = &mn
	}
	if r.EmittedBytes == 0 {
		r.recomputeNextSeqPreEmit()
	}

	out := make([]byte, 0)
	for {
		next := *r.NextSeq
		chunk, ok := r.Segments[next]
		if !ok {
			break
		}
		delete(r.Segments, next)
		out = append(out, chunk...)
		n := next + uint32(len(chunk))
		r.NextSeq = &n
		r.EmittedBytes += int64(len(chunk))
	}
	return out
}

type DirState struct {
	Reasm        TCPReassembler
	LastTS       time.Time
	Pkts         int64
	BytesPayload int64
	MaxPayload   int

	LastAck   *uint32
	LastAckTS time.Time

	MaxRWNDBytes   int
	WScale         *int
	HighestSeqSent uint32
	MaxInflightEst int64

	lastReasmSnapshot [6]int64
}

func NewDirState(now time.Time) DirState {
	return DirState{Reasm: NewTCPReassembler(), LastTS: now, LastAckTS: now}
}

func (ds *DirState) NotePacket(p PacketInfo) {
	ds.LastTS = p.TS
	ds.Pkts++
	plen := len(p.Payload)
	ds.BytesPayload += int64(plen)
	if plen > ds.MaxPayload {
		ds.MaxPayload = plen
	}

	if p.Ack != 0 {
		if ds.LastAck == nil || p.Ack > *ds.LastAck {
			a := p.Ack
			ds.LastAck = &a
			ds.LastAckTS = p.TS
		}
	}

	if p.WScaleOpt != nil {
		ds.WScale = p.WScaleOpt
	}

	scale := 0
	if ds.WScale != nil {
		scale = *ds.WScale
	}
	rwnd := int(p.Win) << int(scale)
	if rwnd > ds.MaxRWNDBytes {
		ds.MaxRWNDBytes = rwnd
	}
}

func (ds *DirState) ReasmDeltas() map[string]int64 {
	r := &ds.Reasm
	snap := [6]int64{r.RetransmitDrop, r.RetransmitDup, r.OverlapTrim, r.OverlapDrop, r.OverlapConflict, r.OOOEvictions}
	prev := ds.lastReasmSnapshot
	ds.lastReasmSnapshot = snap

	keys := []string{"retransmit_drop", "retransmit_dup", "overlap_trim", "overlap_drop", "overlap_conflict", "ooo_evictions"}
	out := map[string]int64{}
	for i, k := range keys {
		if snap[i] != prev[i] {
			out[k] = snap[i] - prev[i]
		}
	}
	return out
}

type SessionState struct {
	Flow        FlowKey
	CreatedTS   time.Time
	LastTS      time.Time
	C2S         DirState
	S2C         DirState
	Closed      bool
	CloseReason string
}

func NewSessionState(flow FlowKey, ts time.Time) *SessionState {
	return &SessionState{Flow: flow, CreatedTS: ts, LastTS: ts, C2S: NewDirState(ts), S2C: NewDirState(ts)}
}

func (s *SessionState) Touch(ts time.Time) { s.LastTS = ts }
