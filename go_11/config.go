package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Config is a dynamic JSON tree (maps + slices) matching the Python prototype behavior.
type Config map[string]any

var (
	jsonishKeyRe         = regexp.MustCompile(`(?m)(^|\s|[{,])([A-Za-z_][A-Za-z0-9_-]*)(\s*):`)
	jsonishTrailingComma = regexp.MustCompile(`,(\s*[}\]])`)
	jsonishLineComment   = regexp.MustCompile(`(?m)^\s*(//|#).*$`)
	jsonishBlockComment  = regexp.MustCompile(`(?s)/\*.*?\*/`)
)

func jsonishToJSON(text string) string {
	text = jsonishBlockComment.ReplaceAllString(text, "")
	text = jsonishLineComment.ReplaceAllString(text, "")

	// Quote unquoted keys: { foo: 1 } -> { "foo": 1 }
	text = jsonishKeyRe.ReplaceAllString(text, `$1"$2"$3:`)

	// Remove trailing commas before } or ]
	text = jsonishTrailingComma.ReplaceAllString(text, `$1`)
	return text
}

func LoadConfig(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	raw, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err == nil {
		return Config(m), nil
	}

	norm := jsonishToJSON(string(raw))
	dec2 := json.NewDecoder(strings.NewReader(norm))
	dec2.UseNumber()
	if err2 := dec2.Decode(&m); err2 != nil {
		return nil, fmt.Errorf("config parse error for %s: %v\n\nnormalized text:\n%s", path, err2, norm)
	}
	return Config(m), nil
}

func GetPath(cfg any, path string, def any) any {
	cur := cfg
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			if cm, ok2 := cur.(Config); ok2 {
				m = map[string]any(cm)
				ok = true
			}
		}
		if !ok {
			return def
		}
		v, ok := m[part]
		if !ok {
			return def
		}
		cur = v
	}
	return cur
}

func GetMap(cfg any, path string) map[string]any {
	v := GetPath(cfg, path, nil)
	if v == nil {
		return map[string]any{}
	}
	if m, ok := v.(map[string]any); ok {
		return m
	}
	if cm, ok := v.(Config); ok {
		return map[string]any(cm)
	}
	return map[string]any{}
}

func GetString(cfg any, path string, def string) string {
	v := GetPath(cfg, path, nil)
	if v == nil {
		return def
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case json.Number:
		return t.String()
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", v))
	}
}

func GetBool(cfg any, path string, def bool) bool {
	v := GetPath(cfg, path, nil)
	if v == nil {
		return def
	}
	switch t := v.(type) {
	case bool:
		return t
	case string:
		s := strings.ToLower(strings.TrimSpace(t))
		if s == "true" || s == "1" || s == "yes" || s == "y" || s == "on" {
			return true
		}
		if s == "false" || s == "0" || s == "no" || s == "n" || s == "off" {
			return false
		}
	case json.Number:
		i, err := t.Int64()
		if err == nil {
			return i != 0
		}
	}
	return def
}

// GetBoolPath is a compatibility wrapper used across the codebase.
// It matches the naming used in the Python prototype port.
func GetBoolPath(cfg any, path string, def bool) bool {
	return GetBool(cfg, path, def)
}

func ToInt(v any, def int) int {
	if v == nil {
		return def
	}
	switch t := v.(type) {
	case int:
		return t
	case int32:
		return int(t)
	case int64:
		return int(t)
	case float64:
		return int(t)
	case float32:
		return int(t)
	case json.Number:
		i, err := t.Int64()
		if err == nil {
			return int(i)
		}
		f, err2 := t.Float64()
		if err2 == nil {
			return int(f)
		}
	case string:
		i, err := strconv.Atoi(strings.TrimSpace(t))
		if err == nil {
			return i
		}
	}
	i, err := strconv.Atoi(fmt.Sprintf("%v", v))
	if err == nil {
		return i
	}
	return def
}

func GetInt(cfg any, path string, def int) int {
	return ToInt(GetPath(cfg, path, nil), def)
}

func ToFloat64(v any, def float64) float64 {
	if v == nil {
		return def
	}
	switch t := v.(type) {
	case float64:
		return t
	case float32:
		return float64(t)
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case json.Number:
		f, err := t.Float64()
		if err == nil {
			return f
		}
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		if err == nil {
			return f
		}
	}
	f, err := strconv.ParseFloat(fmt.Sprintf("%v", v), 64)
	if err == nil {
		return f
	}
	return def
}

func ClampInt(v any, def, lo, hi int) int {
	iv := ToInt(v, def)
	if iv < lo {
		return lo
	}
	if iv > hi {
		return hi
	}
	return iv
}
