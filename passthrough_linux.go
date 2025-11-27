//go:build linux

package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// getProcessName returns the executable name for a given PID.
func getProcessName(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// getParentPID returns the parent PID for a given PID.
func getParentPID(pid int) (int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	// Format: pid (comm) state ppid ...
	// comm can contain spaces and parens, so find the last ) first
	s := string(data)
	closeParenIdx := strings.LastIndex(s, ")")
	if closeParenIdx == -1 {
		return 0, fmt.Errorf("invalid /proc/stat format")
	}
	rest := strings.Fields(s[closeParenIdx+1:])
	if len(rest) < 2 {
		return 0, fmt.Errorf("invalid /proc/stat format")
	}
	// rest[0] is state, rest[1] is ppid
	return strconv.Atoi(rest[1])
}

