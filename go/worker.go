package main

import (
	"context"
	"fmt"
	"time"
)

type ReassemblyWorker struct {
	id int
	in <-chan PacketInfo

	outChunks chan<- ForwardChunk
	outEvents chan<- SessionEvent

	sessionIdle time.Duration
	ackStall    time.Duration

	sessions map[FlowKey]*SessionState
	lastGC   time.Time
}

func NewReassemblyWorker(id int, in <-chan PacketInfo, outChunks chan<- ForwardChunk, outEvents chan<- SessionEvent, sessionIdle, ackStall time.Duration) *ReassemblyWorker {
	return &ReassemblyWorker{
		id:          id,
		in:          in,
		outChunks:   outChunks,
		outEvents:   outEvents,
		sessionIdle: sessionIdle,
		ackStall:    ackStall,
		sessions:    map[FlowKey]*SessionState{},
		lastGC:      time.Now(),
	}
}

func (w *ReassemblyWorker) emitEvent(ev SessionEvent) {
	select {
	case w.outEvents <- ev:
	default:
		// drop if congested; mirrors bounded asyncio.Queue
	}
}

func (w *ReassemblyWorker) emitChunk(ch ForwardChunk) {
	select {
	case w.outChunks <- ch:
	default:
		// drop if congested
	}
}

func (w *ReassemblyWorker) sessionOpen(flow FlowKey, ts time.Time) *SessionState {
	st := NewSessionState(flow, ts)
	w.sessions[flow] = st
	w.emitEvent(SessionEvent{Kind: "open", Flow: flow, TS: ts, Data: map[string]any{}})
	return st
}

func (w *ReassemblyWorker) sessionClose(st *SessionState, ts time.Time, reason string) {
	if st.Closed {
		return
	}
	st.Closed = true
	st.CloseReason = reason
	w.emitEvent(SessionEvent{Kind: "close", Flow: st.Flow, TS: ts, Data: map[string]any{"reason": reason}})
	delete(w.sessions, st.Flow)
}

func (w *ReassemblyWorker) gc(now time.Time) {
	if now.Sub(w.lastGC) < time.Second {
		return
	}
	w.lastGC = now
	idle := w.sessionIdle
	for _, st := range w.sessions {
		if now.Sub(st.LastTS) > idle {
			reason := fmt.Sprintf("idle_timeout_%ds", int(idle.Seconds()+0.5))
			w.sessionClose(st, now, reason)
			continue
		}
		if w.ackStall > 0 {
			stall := w.ackStall
			if st.C2S.LastAck != nil && now.Sub(st.C2S.LastAckTS) > stall {
				w.emitEvent(SessionEvent{Kind: "note", Flow: st.Flow, TS: now, Data: map[string]any{
					"note":      "ack_stall",
					"direction": "c2s",
					"stall_sec": stall.Seconds(),
					"last_ack":  *st.C2S.LastAck,
				}})
				st.C2S.LastAckTS = now
			}
			if st.S2C.LastAck != nil && now.Sub(st.S2C.LastAckTS) > stall {
				w.emitEvent(SessionEvent{Kind: "note", Flow: st.Flow, TS: now, Data: map[string]any{
					"note":      "ack_stall",
					"direction": "s2c",
					"stall_sec": stall.Seconds(),
					"last_ack":  *st.S2C.LastAck,
				}})
				st.S2C.LastAckTS = now
			}
		}
	}
}

func (w *ReassemblyWorker) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case p, ok := <-w.in:
			if !ok {
				return
			}
			w.handlePacket(p)
		default:
			// idle wait + periodic gc
			time.Sleep(250 * time.Millisecond)
			w.gc(time.Now())
		}
	}
}

func (w *ReassemblyWorker) handlePacket(p PacketInfo) {
	ts := p.TS
	st := w.sessions[p.Flow]
	if st == nil {
		st = w.sessionOpen(p.Flow, ts)
	}
	st.Touch(ts)

	// FIN/RST close
	if p.Flags&0x04 != 0 {
		w.sessionClose(st, ts, "rst")
		return
	}
	if p.Flags&0x01 != 0 {
		w.sessionClose(st, ts, "fin")
		return
	}

	dir := st.S2C
	if p.FromLocal {
		dir = st.C2S
	}
	dir.NotePacket(p)

	if len(p.Payload) > 0 {
		endSeq := uint32(uint64(p.Seq) + uint64(len(p.Payload)))
		if endSeq > dir.HighestSeqSent {
			dir.HighestSeqSent = endSeq
		}
	}

	// inflight estimate from peer ACK
	if p.FromLocal {
		peer := st.S2C
		if p.Ack != 0 && peer.HighestSeqSent != 0 {
			inflight := int64(peer.HighestSeqSent) - int64(p.Ack)
			if inflight < 0 {
				inflight = 0
			}
			if inflight > peer.MaxInflightEst {
				peer.MaxInflightEst = inflight
			}
		}
	} else {
		peer := st.C2S
		if p.Ack != 0 && peer.HighestSeqSent != 0 {
			inflight := int64(peer.HighestSeqSent) - int64(p.Ack)
			if inflight < 0 {
				inflight = 0
			}
			if inflight > peer.MaxInflightEst {
				peer.MaxInflightEst = inflight
			}
		}
	}

	if len(p.Payload) > 0 {
		dir.Reasm.Add(p.Seq, p.Payload)
		deltas := dir.ReasmDeltas()
		if len(deltas) > 0 {
			direction := "s2c"
			if p.FromLocal {
				direction = "c2s"
			}
			w.emitEvent(SessionEvent{Kind: "note", Flow: st.Flow, TS: ts, Data: map[string]any{
				"note":      "tcp_reassembly",
				"direction": direction,
				"deltas":    deltas,
			}})
		}
		out := dir.Reasm.PopContiguous()
		if len(out) > 0 {
			direction := "s2c"
			if p.FromLocal {
				direction = "c2s"
			}
			w.emitChunk(ForwardChunk{Flow: p.Flow, TS: ts, Direction: direction, Data: out})
		}
	}

	w.gc(time.Now())
}
