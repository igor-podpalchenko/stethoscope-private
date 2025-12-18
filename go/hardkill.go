package main

import (
	"bytes"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func HardKillAll(exitCode int) {
	// Best-effort "make it stop now" (mirrors Python prototype intent).
	// SIGTERM then SIGKILL to:
	// - process group
	// - descendants
	// - parent chain
	// then os.Exit.
	pid := os.Getpid()
	pgid, _ := syscall.Getpgid(pid)

	ppidByPid := map[int]int{}
	children := map[int][]int{}

	out, err := exec.Command("ps", "-Ao", "pid=,ppid=,pgid=").Output()
	if err == nil {
		lines := bytes.Split(out, []byte("\n"))
		for _, ln := range lines {
			fields := strings.Fields(string(ln))
			if len(fields) != 3 {
				continue
			}
			p, err1 := strconv.Atoi(fields[0])
			pp, err2 := strconv.Atoi(fields[1])
			if err1 != nil || err2 != nil {
				continue
			}
			ppidByPid[p] = pp
			children[pp] = append(children[pp], p)
		}
	}

	// Descendants
	desc := map[int]bool{}
	stack := []int{pid}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, ch := range children[cur] {
			if ch == pid {
				continue
			}
			if !desc[ch] {
				desc[ch] = true
				stack = append(stack, ch)
			}
		}
	}

	// Ancestors
	ancestors := []int{}
	cur := os.Getppid()
	seen := map[int]bool{}
	for cur > 1 && !seen[cur] {
		seen[cur] = true
		ancestors = append(ancestors, cur)
		nxt, ok := ppidByPid[cur]
		if !ok || nxt <= 1 {
			break
		}
		cur = nxt
	}

	// Kill order: descendants first, then ancestors.
	targets := []int{}
	for p := range desc {
		targets = append(targets, p)
	}
	targets = append(targets, ancestors...)

	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL} {
		// Process group
		if pgid > 0 {
			_ = syscall.Kill(-pgid, sig)
		}
		for _, p := range targets {
			_ = syscall.Kill(p, sig)
		}
		time.Sleep(400 * time.Millisecond)
	}

	// Finally, ourselves.
	_ = syscall.Kill(pid, syscall.SIGKILL)
	os.Exit(exitCode)
}
