package main

import (
	"os"
	"path/filepath"
	"testing"
)

// devportOriginal is the relevant excerpt of dist/extension/extension.js from
// Dev Containers 0.469.0.
const devportOriginal = `let{commit:b,quality:k}=e.product,I=Ne.posix.join(Mi(t),` + "`" + `.connection-token-${b}${k==="stable"?"":` + "`" + `-${k}` + "`" + `}${e.web?"-web":""}${t.legacy?"-legacy":""}` + "`" + `),O=Ne.posix.join(Mi(t),` + "`" + `.devport-${b}${k==="stable"?"":` + "`" + `-${k}` + "`" + `}${e.web?"-web":""}${t.legacy?"-legacy":""}` + "`" + `);if(w.length){e.output.write(` + "`" + `Extension host agent is already running.\r`

const devportPatched = `let{commit:b,quality:k}=e.product,I=Ne.posix.join(Mi(t),` + "`" + `.connection-token-${b}${k==="stable"?"":` + "`" + `-${k}` + "`" + `}${e.web?"-web":""}${t.legacy?"-legacy":""}` + "`" + `),O=Ne.posix.join(Mi(t),` + "`" + `.devport-${b}${k==="stable"?"":` + "`" + `-${k}` + "`" + `}${e.web?"-web":""}${t.legacy?"-legacy":""}${m?` + "`" + `-${m.replace(/\D/g,"")}` + "`" + `:""}` + "`" + `);if(w.length){e.output.write(` + "`" + `Extension host agent is already running.\r`

func TestDevContainersDevportPatch(t *testing.T) {
	if len(devContainersPatchSpecs) != 1 {
		t.Fatalf("expected 1 spec, got %d", len(devContainersPatchSpecs))
	}
	spec := devContainersPatchSpecs[0]
	path := filepath.Join(t.TempDir(), spec.filename)
	if err := os.WriteFile(path, []byte(devportOriginal), 0644); err != nil {
		t.Fatal(err)
	}

	if got := checkPatchStatus(path, spec); got != patchStatusUnpatched {
		t.Fatalf("status before patch = %v, want unpatched", got)
	}
	if err := applyPatch(path, spec); err != nil {
		t.Fatalf("applyPatch: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != devportPatched {
		t.Fatalf("patched content mismatch\n got: %s\nwant: %s", got, devportPatched)
	}
	if st := checkPatchStatus(path, spec); st != patchStatusPatched {
		t.Fatalf("status after patch = %v, want patched", st)
	}
	// Idempotent.
	if err := applyPatch(path, spec); err != nil {
		t.Fatalf("second applyPatch: %v", err)
	}
	backup, err := os.ReadFile(path + ".orig")
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	if string(backup) != devportOriginal {
		t.Fatal("backup does not match original")
	}
}

// TestDevContainersPatchAgainstInstalledExtension checks the spec still matches
// the extension actually installed on this machine, when present.
func TestDevContainersPatchAgainstInstalledExtension(t *testing.T) {
	target := extensionTargets[1]
	extDirs, err := target.findExtensionDirs()
	if err != nil {
		t.Skip(err)
	}
	for _, extDir := range extDirs {
		for _, spec := range target.specs {
			path := filepath.Join(extDir, target.subdir, spec.filename)
			if st := checkPatchStatus(path, spec); st == patchStatusUnknown || st == patchStatusError {
				t.Errorf("%s: pattern not found (status %v)", path, st)
			}
		}
	}
}
