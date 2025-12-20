package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// Logger is a leveled logger with optional console and file outputs.
type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
	Close()
	LogPayload(level LogLevel, prefix string, payload map[string]any)
}

// leveledLogger implements Logger with separate console/file thresholds.
type leveledLogger struct {
	mu           sync.Mutex
	consoleLevel LogLevel
	fileLevel    LogLevel
	console      *log.Logger
	file         *log.Logger
	fileCloser   io.Closer
}

// LogLevel controls console/file verbosity.
type LogLevel int

const (
	LevelDebug LogLevel = 10
	LevelInfo  LogLevel = 20
	LevelWarn  LogLevel = 30
	LevelError LogLevel = 40
)

func ParseLevel(s any, def LogLevel) LogLevel {
	if s == nil {
		return def
	}
	name := strings.ToUpper(strings.TrimSpace(fmt.Sprintf("%v", s)))
	switch name {
	case "DEBUG":
		return LevelDebug
	case "INFO":
		return LevelInfo
	case "WARNING", "WARN":
		return LevelWarn
	case "ERROR":
		return LevelError
	default:
		return def
	}
}

func (l *leveledLogger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fileCloser != nil {
		_ = l.fileCloser.Close()
		l.fileCloser = nil
	}
}

func (l *leveledLogger) logf(level LogLevel, levelName string, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	ts := time.Now().Format("2006-01-02 15:04:05")
	line := fmt.Sprintf("%s %s %s", ts, levelName, msg)

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.console != nil && level >= l.consoleLevel {
		l.console.Println(line)
	}
	if l.file != nil && level >= l.fileLevel {
		l.file.Println(line)
	}
}

func (l *leveledLogger) Debugf(format string, args ...any) {
	l.logf(LevelDebug, "DEBUG", format, args...)
}
func (l *leveledLogger) Infof(format string, args ...any) { l.logf(LevelInfo, "INFO", format, args...) }
func (l *leveledLogger) Warnf(format string, args ...any) {
	l.logf(LevelWarn, "WARNING", format, args...)
}
func (l *leveledLogger) Errorf(format string, args ...any) {
	l.logf(LevelError, "ERROR", format, args...)
}

func (l *leveledLogger) LogPayload(level LogLevel, prefix string, payload map[string]any) {
	b, err := json.Marshal(payload)
	if err != nil {
		l.logf(level, levelName(level), "%s %v", prefix, payload)
		return
	}
	l.logf(level, levelName(level), "%s %s", prefix, string(b))
}

func levelName(level LogLevel) string {
	switch level {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARNING"
	case LevelError:
		return "ERROR"
	default:
		return "INFO"
	}
}

func SetupLoggingFromConfig(cfg Config, cliLevel string) (Logger, error) {
	consoleCfg := cfg.Logging.Console
	fileCfg := cfg.Logging.File
	if consoleCfg == nil {
		consoleCfg = map[string]any{}
	}
	if fileCfg == nil {
		fileCfg = map[string]any{}
	}

	consoleLevel := ParseLevel(consoleCfg["verbosity"], LevelInfo)
	if strings.TrimSpace(cliLevel) != "" {
		consoleLevel = ParseLevel(cliLevel, consoleLevel)
	}

	var console *log.Logger
	if BoolFromMap(consoleCfg, "enabled", true) {
		console = log.New(os.Stdout, "", 0)
	}

	l := &leveledLogger{
		consoleLevel: consoleLevel,
		fileLevel:    ParseLevel(fileCfg["verbosity"], LevelInfo),
		console:      console,
	}

	if BoolFromMap(fileCfg, "enabled", false) {
		path := stringFromMap(fileCfg, "path", "stethoscope.log")
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, err
		}
		l.file = log.New(f, "", 0)
		l.fileCloser = f
	}

	return l, nil
}

// BoolFromMap reads a boolean-ish value from a map (used for logging config).
func BoolFromMap(m map[string]any, key string, def bool) bool {
	v, ok := m[key]
	if !ok {
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
	}
	return def
}

// stringFromMap fetches a string value, returning a default when missing/blank.
func stringFromMap(m map[string]any, key, def string) string {
	v, ok := m[key]
	if !ok {
		return def
	}
	s, ok := v.(string)
	if !ok {
		return def
	}
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
