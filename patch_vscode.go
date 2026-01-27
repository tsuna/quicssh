package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	cli "github.com/urfave/cli/v2"
)

// patchSpec describes a string replacement to make in a file
type patchSpec struct {
	filename     string // just the filename within the extension's out/ directory
	searchPrefix string // context bytes before the value
	searchSuffix string // context bytes after the value
	oldValue     string // the original value to replace
	newValue     string // the replacement value
	description  string // human-readable description
}

var patchSpecs = []patchSpec{
	{
		filename:     "extension.js",
		searchPrefix: `Promise.race([t.cnx.call("ping",{}).then((()=>!0)),new Promise((e=>setTimeout((()=>e(!1)),`,
		searchSuffix: `)))]))return`,
		oldValue:     "3e3",
		newValue:     "9e7",
		description:  "ExecServerCache ping timeout (3s -> 25h)",
	},
	{
		filename:     "localServer.js",
		searchPrefix: `this.shutdownTimer=setTimeout((()=>{this.dispose(),S(),f("Timed out"),process.exit(0)}),`,
		searchSuffix: `)}killRemote`,
		oldValue:     "5e3",
		newValue:     "9e7",
		description:  "Local server dead man's switch (5s -> 25h)",
	},
}

func patchVSCodeRemoteSSH(c *cli.Context) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	// Find the VS Code Remote-SSH extension directory
	// Use a specific pattern to avoid matching remote-ssh-edit-* extensions
	extensionsDir := filepath.Join(homeDir, ".vscode", "extensions")
	matches, err := filepath.Glob(filepath.Join(extensionsDir, "ms-vscode-remote.remote-ssh-0.*"))
	if err != nil {
		return fmt.Errorf("failed to search for extension: %w", err)
	}

	if len(matches) == 0 {
		return fmt.Errorf("VS Code Remote-SSH extension not found in %s", extensionsDir)
	}

	// Patch all versions found
	for _, extDir := range matches {
		outDir := filepath.Join(extDir, "out")
		fmt.Printf("Patching VS Code Remote-SSH extension: %s\n", filepath.Base(extDir))

		// Apply each patch
		for _, spec := range patchSpecs {
			filePath := filepath.Join(outDir, spec.filename)
			if err := applyPatch(filePath, spec); err != nil {
				return fmt.Errorf("failed to patch %s in %s: %w", spec.filename, filepath.Base(extDir), err)
			}
		}
	}

	fmt.Println("\nPatching complete! Please restart VS Code for changes to take effect.")
	fmt.Println("Original files have been backed up with .orig extension.")
	return nil
}

func applyPatch(filePath string, spec patchSpec) error {
	// Read the file
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Build the search pattern
	oldPattern := spec.searchPrefix + spec.oldValue + spec.searchSuffix
	newPattern := spec.searchPrefix + spec.newValue + spec.searchSuffix

	// Check if already patched
	if bytes.Contains(content, []byte(newPattern)) {
		fmt.Printf("  %s: already patched (%s)\n", spec.filename, spec.description)
		return nil
	}

	// Check if the pattern exists
	if !bytes.Contains(content, []byte(oldPattern)) {
		// Maybe it was patched with a different value? Check for prefix+suffix
		checkPattern := spec.searchPrefix
		if !bytes.Contains(content, []byte(checkPattern)) {
			return fmt.Errorf("pattern not found - file may have been updated or has unexpected format")
		}
		// Pattern prefix exists but with different value
		return fmt.Errorf("pattern found but with unexpected value (not %s or %s) - file may have been manually modified",
			spec.oldValue, spec.newValue)
	}

	// Create backup if it doesn't exist
	backupPath := filePath + ".orig"
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		if err := os.WriteFile(backupPath, content, 0644); err != nil {
			return fmt.Errorf("failed to create backup: %w", err)
		}
		fmt.Printf("  %s: created backup at %s\n", spec.filename, filepath.Base(backupPath))
	}

	// Apply the patch
	newContent := bytes.Replace(content, []byte(oldPattern), []byte(newPattern), 1)

	// Verify exactly one replacement was made
	if bytes.Equal(content, newContent) {
		return fmt.Errorf("replacement failed - content unchanged")
	}

	// Check that the old pattern no longer exists (only one occurrence)
	if bytes.Contains(newContent, []byte(oldPattern)) {
		return fmt.Errorf("multiple occurrences of pattern found - please patch manually")
	}

	// Write the patched content
	if err := os.WriteFile(filePath, newContent, 0644); err != nil {
		return fmt.Errorf("failed to write patched file: %w", err)
	}

	fmt.Printf("  %s: patched %s -> %s (%s)\n", spec.filename, spec.oldValue, spec.newValue, spec.description)
	return nil
}

// unpatchVSCodeRemoteSSH restores the original files from backups
func unpatchVSCodeRemoteSSH(c *cli.Context) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	// Use a specific pattern to avoid matching remote-ssh-edit-* extensions
	extensionsDir := filepath.Join(homeDir, ".vscode", "extensions")
	matches, err := filepath.Glob(filepath.Join(extensionsDir, "ms-vscode-remote.remote-ssh-0.*"))
	if err != nil {
		return fmt.Errorf("failed to search for extension: %w", err)
	}

	if len(matches) == 0 {
		return fmt.Errorf("VS Code Remote-SSH extension not found in %s", extensionsDir)
	}

	totalRestored := 0
	for _, extDir := range matches {
		outDir := filepath.Join(extDir, "out")
		fmt.Printf("Restoring VS Code Remote-SSH extension: %s\n", filepath.Base(extDir))

		for _, spec := range patchSpecs {
			filePath := filepath.Join(outDir, spec.filename)
			backupPath := filePath + ".orig"

			if _, err := os.Stat(backupPath); os.IsNotExist(err) {
				fmt.Printf("  %s: no backup found, skipping\n", spec.filename)
				continue
			}

			// Read backup
			backup, err := os.ReadFile(backupPath)
			if err != nil {
				return fmt.Errorf("failed to read backup %s: %w", backupPath, err)
			}

			// Restore
			if err := os.WriteFile(filePath, backup, 0644); err != nil {
				return fmt.Errorf("failed to restore %s: %w", spec.filename, err)
			}

			// Remove backup
			if err := os.Remove(backupPath); err != nil {
				fmt.Printf("  Warning: failed to remove backup %s: %v\n", backupPath, err)
			}

			fmt.Printf("  %s: restored from backup\n", spec.filename)
			totalRestored++
		}
	}

	if totalRestored > 0 {
		fmt.Println("\nRestore complete! Please restart VS Code for changes to take effect.")
	} else {
		fmt.Println("\nNo backups found - nothing to restore.")
	}
	return nil
}
