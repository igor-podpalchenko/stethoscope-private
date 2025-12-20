package main

import "time"

type EventRouter struct {
	Log *Logger
	CP  *ControlPlane
}

func (r *EventRouter) Emit(cat, event, level string, payload map[string]any, cp bool) {
	// Local logs always (subject to handler levels)
	lvl := LevelInfo
	switch level {
	case "debug":
		lvl = LevelDebug
	case "warning":
		lvl = LevelWarn
	case "error":
		lvl = LevelError
	default:
		lvl = LevelInfo
	}
	if r.Log != nil {
		r.Log.LogPayload(lvl, cat+"."+event, payload)
	}

	if !cp || r.CP == nil {
		return
	}
	if !r.CP.Enabled() {
		return
	}

	// session_id extraction for flow gating
	var sessionID *int
	if flowRaw, ok := payload["flow"]; ok {
		if flow, ok2 := flowRaw.(map[string]any); ok2 {
			if sidRaw, ok3 := flow["session_id"]; ok3 {
				sid := ToInt(sidRaw, -1)
				if sid >= 0 {
					sessionID = &sid
				}
			}
		}
	}

	if cat == "flow" {
		if sessionID == nil || !r.CP.FlowEnabledFor(sessionID) {
			return
		}
	}

	if !r.CP.CatEnabled(cat) {
		return
	}

	out := make(map[string]any, len(payload)+3)
	out["ts"] = utcISO(time.Now())
	out["cat"] = cat
	out["event"] = event
	for k, v := range payload {
		out[k] = v
	}
	r.CP.EmitRaw(out)
}
