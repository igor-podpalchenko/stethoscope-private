package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// utcISO returns a UTC timestamp in ISO-like format.
func utcISO(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

// utcISONow is a convenience wrapper for the current time.
func utcISONow() string { return utcISO(time.Now()) }

// SortStrings/SortInts mirror earlier helpers used throughout the codebase.
func SortStrings(xs []string) { sort.Strings(xs) }
func SortInts(xs []int)       { sort.Ints(xs) }

// ToInt converts common numeric/string types into an int with a fallback.
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
