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
	optional     bool   // if true, skip silently when the pattern is not found
}

const (
	extensionJS = "extension.js"
	resolverJS  = "resolver.js"
)

var patchSpecs = []patchSpec{
	// Patterns below match remote-ssh 0.124.0. The extension code is the same
	// as before, but the minifier no longer wraps arrow functions in redundant
	// parentheses, and the bundle is now duplicated into resolver.js (not
	// referenced by package.json, but patched anyway in case it's loaded).
	{
		filename:     extensionJS,
		searchPrefix: `Promise.race([t.cnx.call("ping",{}).then(()=>!0),new Promise(e=>setTimeout(()=>e(!1),`,
		searchSuffix: `))]))return`,
		oldValue:     "3e3",
		newValue:     "9e7",
		description:  "ExecServerCache ping timeout (3s -> 25h)",
	},
	{
		filename:     resolverJS,
		searchPrefix: `Promise.race([t.cnx.call("ping",{}).then(()=>!0),new Promise(e=>setTimeout(()=>e(!1),`,
		searchSuffix: `))]))return`,
		oldValue:     "3e3",
		newValue:     "9e7",
		description:  "ExecServerCache ping timeout (3s -> 25h)",
	},
	{
		filename:    extensionJS,
		oldValue:    `async function E(e,t){try{const n=await(0,g.httpGet)(void 0,{socketPath:e,path:"/delay-shutdown"},t);return"OK"===n||t.debug("Got unexpected result from running connection server: "+n),!0}catch(e){return t.debug("Server delay-shutdown request failed: "+e.message),!1}}`,
		newValue:    `async function E(e,t){return!0}`,
		description: "Disable delay-shutdown keepalive HTTP requests",
		optional:    true,
	},
	{
		filename:    extensionJS,
		oldValue:    `async function E(e,t){try{const n=await(0,g.httpGet)(void 0,{socketPath:e,path:"/delay-shutdown"},t);return"OK"===n||t.debug("Got unexpected result from running connection server: "+n),!0}catch(e){return t.debug("Server delay-shutdown request failed: "+e.message),!0}}`,
		newValue:    `async function E(e,t){return!0}`,
		description: "Disable delay-shutdown keepalive HTTP requests (from prior partial patch)",
	},
	{
		filename:    resolverJS,
		oldValue:    `async function _(e,t){try{const n=await(0,g.httpGet)(void 0,{socketPath:e,path:"/delay-shutdown"},t);return"OK"===n||t.debug("Got unexpected result from running connection server: "+n),!0}catch(e){return t.debug("Server delay-shutdown request failed: "+e.message),!1}}`,
		newValue:    `async function _(e,t){return!0}`,
		description: "Disable delay-shutdown keepalive HTTP requests",
		optional:    true,
	},
	{
		filename:    resolverJS,
		oldValue:    `async function _(e,t){try{const n=await(0,g.httpGet)(void 0,{socketPath:e,path:"/delay-shutdown"},t);return"OK"===n||t.debug("Got unexpected result from running connection server: "+n),!0}catch(e){return t.debug("Server delay-shutdown request failed: "+e.message),!0}}`,
		newValue:    `async function _(e,t){return!0}`,
		description: "Disable delay-shutdown keepalive HTTP requests (from prior partial patch)",
	},
	{
		filename:     extensionJS,
		searchPrefix: `0===this.connectionCount&&this.delayShutdown(`,
		searchSuffix: `)}static readArgsFromEnvironment`,
		oldValue:     "3e4",
		newValue:     "9e7",
		description:  "TunnelProxyServer idle shutdown (30s -> 25h)",
	},
	{
		filename:     extensionJS,
		searchPrefix: `this.startSavingRunningInfo(),this.delayShutdown(`,
		searchSuffix: `)}incrementConnectionCount`,
		oldValue:     "9e4",
		newValue:     "9e7",
		description:  "TunnelProxyServer startup shutdown (90s -> 25h)",
	},
	{
		filename:     extensionJS,
		searchPrefix: `delayShutdown(e=`,
		searchSuffix: `){this.shutdownTimer&&clearTimeout`,
		oldValue:     "3e4",
		newValue:     "9e7",
		description:  "TunnelProxyServer default shutdown (30s -> 25h)",
	},
	{
		filename:     resolverJS,
		searchPrefix: `0===this.connectionCount&&this.delayShutdown(`,
		searchSuffix: `)}static readArgsFromEnvironment`,
		oldValue:     "3e4",
		newValue:     "9e7",
		description:  "TunnelProxyServer idle shutdown (30s -> 25h)",
	},
	{
		filename:     resolverJS,
		searchPrefix: `this.startSavingRunningInfo(),this.delayShutdown(`,
		searchSuffix: `)}incrementConnectionCount`,
		oldValue:     "9e4",
		newValue:     "9e7",
		description:  "TunnelProxyServer startup shutdown (90s -> 25h)",
	},
	{
		filename:     resolverJS,
		searchPrefix: `delayShutdown(e=`,
		searchSuffix: `){this.shutdownTimer&&clearTimeout`,
		oldValue:     "3e4",
		newValue:     "9e7",
		description:  "TunnelProxyServer default shutdown (30s -> 25h)",
	},
	{
		filename:     "localServer.js",
		searchPrefix: `this.shutdownTimer=setTimeout(()=>{this.dispose(),S(),f("Timed out"),process.exit(0)},`,
		searchSuffix: `)}killRemote`,
		oldValue:     "5e3",
		newValue:     "9e7",
		description:  "Local server dead man's switch (5s -> 25h)",
	},
}

// devContainersPatchSpecs match the Dev Containers extension (0.469.0).
//
// The extension records the port of the VS Code Server it starts inside a
// container in ~/.vscode-server/data/Machine/.devport-<commit>. When several
// containers bind-mount the same ~/.vscode-server (typical for "attach to
// running container" setups that mount the user's home), they all share that
// file, so whichever server started last overwrites the port. On the next
// reload of a window attached to another container, the extension finds its
// server "already running", reads the other container's port, gets
// ECONNREFUSED on every forwarded connection, and the window fails with
// "WebSocket close with status code 1006" until the server is killed.
//
// The patch appends the container's mount namespace id (already collected by
// the extension in the same function, unique per live container and stable for
// its lifetime) to the file name, keeping it in the same directory so no
// assumption is made about /tmp or any other location.
var devContainersPatchSpecs = []patchSpec{
	{
		filename:     extensionJS,
		searchPrefix: "O=Ne.posix.join(Mi(t),`.devport-${b}${k===\"stable\"?\"\":`-${k}`}${e.web?\"-web\":\"\"}",
		searchSuffix: "`);if(w.length)",
		oldValue:     "${t.legacy?\"-legacy\":\"\"}",
		newValue:     "${t.legacy?\"-legacy\":\"\"}${m?`-${m.replace(/\\D/g,\"\")}`:\"\"}",
		description:  "Make .devport file name container-specific (append mount namespace id)",
	},
}

// extensionTarget describes a VS Code extension whose bundled JavaScript
// quicssh knows how to patch.
type extensionTarget struct {
	name   string      // human-readable name
	glob   string      // directory glob under ~/.vscode/extensions
	subdir string      // directory holding the bundled JavaScript, relative to the extension root
	specs  []patchSpec // patches to apply
}

var extensionTargets = []extensionTarget{
	{
		name: "Remote-SSH",
		// Use a specific pattern to avoid matching remote-ssh-edit-* extensions
		glob:   "ms-vscode-remote.remote-ssh-0.*",
		subdir: "out",
		specs:  patchSpecs,
	},
	{
		name:   "Dev Containers",
		glob:   "ms-vscode-remote.remote-containers-0.*",
		subdir: filepath.Join("dist", "extension"),
		specs:  devContainersPatchSpecs,
	},
}

func (t extensionTarget) findExtensionDirs() ([]string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}
	extensionsDir := filepath.Join(homeDir, ".vscode", "extensions")
	matches, err := filepath.Glob(filepath.Join(extensionsDir, t.glob))
	if err != nil {
		return nil, fmt.Errorf("failed to search for extension: %w", err)
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("VS Code %s extension not found in %s", t.name, extensionsDir)
	}
	return matches, nil
}

// patchStatus represents the patch state of a file
type patchStatus int

const (
	patchStatusUnpatched patchStatus = iota // Needs patching (has old value)
	patchStatusPatched                      // Already patched (has new value)
	patchStatusUnknown                      // Pattern not found or unexpected value
	patchStatusError                        // Error reading file
)

// checkPatchStatus checks whether a file needs patching for a given spec.
func checkPatchStatus(filePath string, spec patchSpec) patchStatus {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return patchStatusError
	}

	if spec.searchPrefix == "" && spec.searchSuffix == "" {
		if bytes.Contains(content, []byte(spec.newValue)) {
			return patchStatusPatched
		}
		if bytes.Contains(content, []byte(spec.oldValue)) {
			return patchStatusUnpatched
		}
		return patchStatusUnknown
	}

	oldPattern := spec.searchPrefix + spec.oldValue + spec.searchSuffix
	newPattern := spec.searchPrefix + spec.newValue + spec.searchSuffix

	if bytes.Contains(content, []byte(newPattern)) {
		return patchStatusPatched
	}

	if bytes.Contains(content, []byte(oldPattern)) {
		return patchStatusUnpatched
	}

	return patchStatusUnknown
}

// findUnpatchedVSCodeExtensions returns paths to installed VS Code extensions
// that have at least one file needing patching.
func findUnpatchedVSCodeExtensions() []string {
	var unpatched []string
	for _, target := range extensionTargets {
		extDirs, err := target.findExtensionDirs()
		if err != nil {
			continue
		}
		for _, extDir := range extDirs {
			bundleDir := filepath.Join(extDir, target.subdir)
			for _, spec := range target.specs {
				filePath := filepath.Join(bundleDir, spec.filename)
				if checkPatchStatus(filePath, spec) == patchStatusUnpatched {
					unpatched = append(unpatched, extDir)
					break // Only need to find one unpatched file per extension
				}
			}
		}
	}
	return unpatched
}

// warnUnpatchedVSCodeExtensions prints a warning to stderr if any unpatched
// VS Code extensions are found.
func warnUnpatchedVSCodeExtensions() {
	unpatched := findUnpatchedVSCodeExtensions()
	if len(unpatched) == 0 {
		return
	}

	fmt.Fprintf(os.Stderr, "quicssh: warning: detected unpatched VS Code extension(s) at:\n")
	for _, extPath := range unpatched {
		fmt.Fprintf(os.Stderr, "  - %s\n", extPath)
	}
	fmt.Fprintf(os.Stderr, "Run `%s patch-vscode` to patch and get the full benefits of quicssh with VS Code.\n", os.Args[0])
}

// patchVSCode applies the patches for every known VS Code extension that is
// installed. It only fails if no known extension is installed at all.
func patchVSCode(_ *cli.Context) error {
	found := false
	for _, target := range extensionTargets {
		if _, err := target.findExtensionDirs(); err != nil {
			fmt.Printf("Skipping VS Code %s extension: %v\n", target.name, err)
			continue
		}
		found = true
		if err := patchExtension(target); err != nil {
			return err
		}
	}
	if !found {
		return fmt.Errorf("no known VS Code extension found")
	}
	fmt.Println("\nPatching complete! Please restart VS Code for changes to take effect.")
	fmt.Println("Original files have been backed up with .orig extension.")
	return nil
}

// unpatchVSCode restores the original files of every known VS Code extension
// that is installed.
func unpatchVSCode(_ *cli.Context) error {
	found := false
	totalRestored := 0
	for _, target := range extensionTargets {
		if _, err := target.findExtensionDirs(); err != nil {
			fmt.Printf("Skipping VS Code %s extension: %v\n", target.name, err)
			continue
		}
		found = true
		n, err := unpatchExtension(target)
		if err != nil {
			return err
		}
		totalRestored += n
	}
	if !found {
		return fmt.Errorf("no known VS Code extension found")
	}
	if totalRestored > 0 {
		fmt.Println("\nRestore complete! Please restart VS Code for changes to take effect.")
	} else {
		fmt.Println("\nNo backups found - nothing to restore.")
	}
	return nil
}

// patchExtension applies all of the target's patches to every installed
// version of the extension.
func patchExtension(target extensionTarget) error {
	extDirs, err := target.findExtensionDirs()
	if err != nil {
		return err
	}

	for _, extDir := range extDirs {
		bundleDir := filepath.Join(extDir, target.subdir)
		fmt.Printf("Patching VS Code %s extension: %s\n", target.name, filepath.Base(extDir))

		for _, spec := range target.specs {
			filePath := filepath.Join(bundleDir, spec.filename)
			if err := applyPatch(filePath, spec); err != nil {
				return fmt.Errorf("failed to patch %s in %s: %w", spec.filename, filepath.Base(extDir), err)
			}
		}
	}
	return nil
}

func applyPatch(filePath string, spec patchSpec) error {
	// Read the file
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	if spec.searchPrefix == "" && spec.searchSuffix == "" {
		return applyFullReplacePatch(filePath, content, spec)
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

	return writePatchedContent(filePath, content, oldPattern, newPattern, spec)
}

func applyFullReplacePatch(filePath string, content []byte, spec patchSpec) error {
	if bytes.Contains(content, []byte(spec.newValue)) {
		fmt.Printf("  %s: already patched (%s)\n", spec.filename, spec.description)
		return nil
	}

	if !bytes.Contains(content, []byte(spec.oldValue)) {
		if spec.optional {
			return nil
		}
		return fmt.Errorf("pattern not found - file may have been updated or has unexpected format")
	}

	return writePatchedContent(filePath, content, spec.oldValue, spec.newValue, spec)
}

func writePatchedContent(filePath string, content []byte, oldPattern, newPattern string, spec patchSpec) error {
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

// unpatchExtension restores the original files from backups and returns the
// number of files restored.
func unpatchExtension(target extensionTarget) (int, error) {
	extDirs, err := target.findExtensionDirs()
	if err != nil {
		return 0, err
	}

	totalRestored := 0
	for _, extDir := range extDirs {
		bundleDir := filepath.Join(extDir, target.subdir)
		fmt.Printf("Restoring VS Code %s extension: %s\n", target.name, filepath.Base(extDir))

		restored := map[string]bool{}
		for _, spec := range target.specs {
			if restored[spec.filename] {
				continue
			}
			filePath := filepath.Join(bundleDir, spec.filename)
			backupPath := filePath + ".orig"

			if _, err := os.Stat(backupPath); os.IsNotExist(err) {
				fmt.Printf("  %s: no backup found, skipping\n", spec.filename)
				restored[spec.filename] = true
				continue
			}

			// Read backup
			backup, err := os.ReadFile(backupPath)
			if err != nil {
				return totalRestored, fmt.Errorf("failed to read backup %s: %w", backupPath, err)
			}

			// Restore
			if err := os.WriteFile(filePath, backup, 0644); err != nil {
				return totalRestored, fmt.Errorf("failed to restore %s: %w", spec.filename, err)
			}

			// Remove backup
			if err := os.Remove(backupPath); err != nil {
				fmt.Printf("  Warning: failed to remove backup %s: %v\n", backupPath, err)
			}

			fmt.Printf("  %s: restored from backup\n", spec.filename)
			restored[spec.filename] = true
			totalRestored++
		}
	}

	return totalRestored, nil
}
