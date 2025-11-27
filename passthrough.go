//go:build darwin || linux

package main

import "os"

// passthroughCommands are commands where bypassing QUIC for direct SSH
// is preferred - either bulk transfers (scp, rsync, sftp) or programs
// with their own connection resilience (mosh).
var passthroughCommands = map[string]bool{
	"scp":         true,
	"rsync":       true,
	"sftp":        true,
	"mosh":        true, // wrapper script
	"mosh-client": true, // actual client binary
}

// isBulkTransferParent walks up the process tree to detect if we're being
// invoked by a bulk transfer tool (scp, rsync, sftp). Returns true and the
// command name if found.
func isBulkTransferParent() (bool, string) {
	pid := os.Getppid()
	// Walk up to 10 levels (should be enough to find scp/rsync)
	for i := 0; i < 10 && pid > 1; i++ {
		name, err := getProcessName(pid)
		if err != nil {
			break
		}
		if passthroughCommands[name] {
			return true, name
		}
		ppid, err := getParentPID(pid)
		if err != nil || ppid == pid {
			break
		}
		pid = ppid
	}
	return false, ""
}
