package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	cfgPath := flag.String("config", "", "Path to config file")
	logLevel := flag.String("log-level", "", "Optional console override: DEBUG/INFO/WARN/ERROR")
	flag.Parse()

	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "--config is required")
		os.Exit(1)
	}

	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	log, err := SetupLoggingFromConfig(cfg, *logLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logging error: %v\n", err)
		os.Exit(1)
	}
	defer log.Close()

	svc, err := NewService(cfg, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "service init error: %v\n", err)
		os.Exit(1)
	}

	if err := svc.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "start error: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	<-ctx.Done()
	log.Infof("stopping capture")
	svc.Stop()
}
