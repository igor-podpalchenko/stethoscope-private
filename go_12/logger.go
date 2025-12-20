package main

import (
	"log"
	"os"
	"strings"
)

// Logger is a tiny leveled wrapper around the stdlib logger.
type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

// stdLogger implements Logger with basic severity gating.
type stdLogger struct {
	lvl LogLevel
	l   *log.Logger
}

// LogLevel controls console verbosity.
type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarn
	LevelError
)

func newLogger(level string) Logger {
	return &stdLogger{lvl: parseLevel(level), l: log.New(os.Stdout, "", log.LstdFlags)}
}

func parseLevel(s string) LogLevel {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "DEBUG":
		return LevelDebug
	case "INFO":
		return LevelInfo
	case "WARN", "WARNING":
		return LevelWarn
	case "ERROR":
		return LevelError
	default:
		return LevelInfo
	}
}

func (l *stdLogger) logf(level LogLevel, prefix, format string, args ...any) {
	if level < l.lvl {
		return
	}
	l.l.Printf(prefix+format, args...)
}

func (l *stdLogger) Debugf(format string, args ...any) { l.logf(LevelDebug, "DEBUG ", format, args...) }
func (l *stdLogger) Infof(format string, args ...any)  { l.logf(LevelInfo, "INFO  ", format, args...) }
func (l *stdLogger) Warnf(format string, args ...any)  { l.logf(LevelWarn, "WARN  ", format, args...) }
func (l *stdLogger) Errorf(format string, args ...any) { l.logf(LevelError, "ERROR ", format, args...) }
