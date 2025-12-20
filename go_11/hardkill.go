package main

import (
	"os"
	"syscall"
	"time"
)

func HardKillAll(exitCode int) {
	// Best-effort immediate shutdown: terminate process group, then hard exit.
	pid := os.Getpid()
	pgid, _ := syscall.Getpgid(pid)

	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL} {
		if pgid > 0 {
			_ = syscall.Kill(-pgid, sig)
		}
		time.Sleep(400 * time.Millisecond)
	}

	_ = syscall.Kill(pid, syscall.SIGKILL)
	os.Exit(exitCode)
}
