package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Config models the user-provided configuration file.
type Config struct {
	IO      IOConfig      `json:"io"`
	Control ControlConfig `json:"control"`
	Logging LoggingConfig `json:"logging"`
}

// IOConfig holds input/output configuration.
type IOConfig struct {
	Input  InputConfig  `json:"input"`
	Output OutputConfig `json:"output"`
}

// InputConfig wraps capture parameters.
type InputConfig struct {
	Capture CaptureConfig `json:"capture"`
}

// CaptureConfig describes the sniffing interface and filters.
type CaptureConfig struct {
	Iface          string  `json:"iface"`
	BPFFilter      string  `json:"bpf-filter"`
	LocalIP        string  `json:"local_ip"`
	RemoteIP       string  `json:"remote_ip"`
	RemotePort     int     `json:"remote_port"`
	LocalPort      int     `json:"local_port"`
	BufferBytes    int     `json:"buffer_bytes"`
	SessionIdleSec float64 `json:"session_idle_sec"`
}

// OutputConfig includes forwarding targets.
type OutputConfig struct {
	RemoteHost RemoteOutputConfig `json:"remote-host"`
	Listener   ListenerConfig     `json:"listner"`
}

// RemoteOutputConfig forwards streams to a remote TCP host.
type RemoteOutputConfig struct {
	Enabled       bool          `json:"enabled"`
	Host          string        `json:"host"`
	RequestsPort  int           `json:"requests_port"`
	ResponsesPort int           `json:"responses_port"`
	Timeouts      TimeoutConfig `json:"timeouts"`
}

// ListenerConfig models the local listener output. Only the required fields are retained.
type ListenerConfig struct {
	Enabled            bool           `json:"enabled"`
	BindIP             string         `json:"bind_ip"`
	BindInterface      string         `json:"bind_interface"`
	FirstRequestsPort  int            `json:"first_requests_port"`
	FirstResponsesPort int            `json:"first_responses_port"`
	PortRangeStart     int            `json:"port_range_start"`
	PortRangeEnd       int            `json:"port_range_end"`
	Timeouts           map[string]any `json:"timeouts"`
}

// TimeoutConfig holds small connection timing knobs.
type TimeoutConfig struct {
	Connect    int `json:"connect"`
	RetryEvery int `json:"retry-every"`
}

// ControlConfig is currently unused in the Go port but preserved for completeness.
type ControlConfig struct {
	BindIP     string `json:"bind_ip"`
	ListenPort int    `json:"listen_port"`
}

// LoggingConfig captures optional logging overrides.
type LoggingConfig struct {
	Console map[string]any `json:"console"`
	File    map[string]any `json:"file"`
}

var (
	keyRe          = regexp.MustCompile(`(?m)(^|\s|[{,])([A-Za-z_][A-Za-z0-9_-]*)(\s*):`)
	trailingComma  = regexp.MustCompile(`,(\s*[}\]])`)
	lineCommentRe  = regexp.MustCompile(`(?m)^\s*(//|#).*$`)
	blockCommentRe = regexp.MustCompile(`/\*.*?\*/`)
)

// LoadConfig parses json-ish configuration files by first normalizing into strict JSON.
func LoadConfig(path string) (Config, error) {
	var cfg Config
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}

	normalized := normalizeJSONish(string(raw))
	if err := json.Unmarshal([]byte(normalized), &cfg); err != nil {
		return cfg, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

// normalizeJSONish adds quoted keys, strips comments, and removes trailing commas.
func normalizeJSONish(text string) string {
	text = blockCommentRe.ReplaceAllString(text, "")
	text = lineCommentRe.ReplaceAllString(text, "")
	text = keyRe.ReplaceAllString(text, `${1}"${2}"${3}:`)
	text = trailingComma.ReplaceAllString(text, `$1`)
	return strings.TrimSpace(text)
}
