package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	cfgPath := flag.String("config", "", "Path to JSON (or json-ish) config file")
	cliLevel := flag.String("log-level", "", "Optional console override: DEBUG/INFO/WARNING/ERROR")
	flag.Parse()

	if *cfgPath == "" {
		flag.Usage()
		os.Exit(2)
	}

	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		_, _ = os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}

	log, err := SetupLoggingFromConfig(cfg, *cliLevel)
	if err != nil {
		_, _ = os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
	defer log.Close()

	svc, err := NewService(cfg, log)
	if err != nil {
		log.Errorf("init error: %v", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	if err := svc.Start(ctx); err != nil {
		log.Errorf("start error: %v", err)
		os.Exit(1)
	}

	<-ctx.Done()

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopCancel()
	if err := svc.Stop(stopCtx); err != nil {
		// Hard termination mirrors Python prototype behavior under sudo/pcap weirdness.
		HardKillAll(0)
	}

	// Let goroutines settle (best-effort).
	time.Sleep(0)
}
