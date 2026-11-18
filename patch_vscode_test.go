package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// devportExcerpt469 is the relevant excerpt of dist/extension/extension.js
// from Dev Containers 0.469.0; devportExcerpt475 is the same from 0.475.0,
// where only the minified identifiers changed.
const devportExcerpt469 = `let{commit:b,quality:k}=e.product,I=Ne.posix.join(Mi(t),` + "`" + `.connection-token-${b}${k==="stable"?"":` + "`" + `-${k}` + "`" + `}${e.web?"-web":""}${t.legacy?"-legacy":""}` + "`" + `),O=Ne.posix.join(Mi(t),` + "`" + `.devport-${b}${k==="stable"?"":` + "`" + `-${k}` + "`" + `}${e.web?"-web":""}${t.legacy?"-legacy":""}` + "`" + `);if(w.length){e.output.write(` + "`" + `Extension host agent is already running.\r`

const devportExcerpt475 = `let{commit:b,quality:T}=e.product,I=Le.posix.join(Bi(t),` + "`" + `.connection-token-${b}${T==="stable"?"":` + "`" + `-${T}` + "`" + `}${e.web?"-web":""}${t.legacy?"-legacy":""}` + "`" + `),M=Le.posix.join(Bi(t),` + "`" + `.devport-${b}${T==="stable"?"":` + "`" + `-${T}` + "`" + `}${e.web?"-web":""}${t.legacy?"-legacy":""}` + "`" + `);if(w.length){e.output.write(` + "`" + `Extension host agent is already running.\r`

// devportPatched returns the expected result of patching excerpt: only the
// .devport- path (the second occurrence of the legacy suffix) gains the mount
// namespace id.
func devportPatched(excerpt string) string {
	const legacy = `${t.legacy?"-legacy":""}`
	i := strings.LastIndex(excerpt, legacy) + len(legacy)
	return excerpt[:i] + `${m?` + "`" + `-${m.replace(/\D/g,"")}` + "`" + `:""}` + excerpt[i:]
}

func TestDevContainersDevportPatch(t *testing.T) {
	if len(devContainersPatchSpecs) != 1 {
		t.Fatalf("expected 1 spec, got %d", len(devContainersPatchSpecs))
	}
	spec := devContainersPatchSpecs[0]
	for _, tc := range []struct{ version, original string }{
		{"0.469.0", devportExcerpt469},
		{"0.475.0", devportExcerpt475},
	} {
		t.Run(tc.version, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), spec.filename)
			if err := os.WriteFile(path, []byte(tc.original), 0644); err != nil {
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
			if want := devportPatched(tc.original); string(got) != want {
				t.Fatalf("patched content mismatch\n got: %s\nwant: %s", got, want)
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
			if string(backup) != tc.original {
				t.Fatal("backup does not match original")
			}
		})
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
