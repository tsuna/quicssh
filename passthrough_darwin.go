//go:build darwin

package main

import (
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// getProcessName returns the executable name for a given PID.
func getProcessName(pid int) (string, error) {
	cmd := exec.Command("ps", "-o", "comm=", "-p", strconv.Itoa(pid))
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	// ps on macOS returns full path, get just the basename
	name := strings.TrimSpace(string(output))
	return filepath.Base(name), nil
}

// getParentPID returns the parent PID for a given PID.
func getParentPID(pid int) (int, error) {
	cmd := exec.Command("ps", "-o", "ppid=", "-p", strconv.Itoa(pid))
	output, err := cmd.Output()
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(output)))
}

