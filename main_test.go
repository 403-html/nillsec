package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/403-html/nillsec/vault"
)

const editTestPassword = "edit-test-password"

// makeTestVault initialises a vault at path and optionally seeds it with secrets.
func makeTestVault(t *testing.T, path string, secrets map[string]string) {
	t.Helper()
	if err := vault.Init(path, []byte(editTestPassword)); err != nil {
		t.Fatalf("vault.Init: %v", err)
	}
	if len(secrets) == 0 {
		return
	}
	v, err := vault.Load(path, []byte(editTestPassword))
	if err != nil {
		t.Fatalf("vault.Load: %v", err)
	}
	for k, val := range secrets {
		v.Set(k, val)
	}
	if err := vault.Save(path, []byte(editTestPassword), v); err != nil {
		t.Fatalf("vault.Save: %v", err)
	}
}

// fakeEditor writes a shell script that replaces its first argument with
// the content of newContentFile, and then records the path it was given in
// pathRecordFile (if non-empty).  Returns the path to the script.
func fakeEditor(t *testing.T, dir, newContentFile, pathRecordFile string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake editor not supported on Windows")
	}
	var sb strings.Builder
	sb.WriteString("#!/bin/sh\n")
	if pathRecordFile != "" {
		sb.WriteString("echo \"$1\" > \"" + pathRecordFile + "\"\n")
	}
	sb.WriteString("cp \"" + newContentFile + "\" \"$1\"\n")
	script := filepath.Join(dir, "fake-editor.sh")
	if err := os.WriteFile(script, []byte(sb.String()), 0700); err != nil {
		t.Fatalf("write fake editor: %v", err)
	}
	return script
}

// TestCmdEditRoundTrip verifies that cmdEdit reads the vault, passes it to the
// editor, and re-encrypts the edited content back into the vault file.
func TestCmdEditRoundTrip(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake editor not supported on Windows")
	}
	dir := t.TempDir()
	vaultFile := filepath.Join(dir, "test.vault")
	makeTestVault(t, vaultFile, map[string]string{"existing": "original"})

	// New content the fake editor will write.
	newContent := `{"version":1,"secrets":{"existing":"original","added_key":"added_value"}}`
	newContentFile := filepath.Join(dir, "new-content.json")
	if err := os.WriteFile(newContentFile, []byte(newContent), 0600); err != nil {
		t.Fatalf("write new content file: %v", err)
	}

	editor := fakeEditor(t, dir, newContentFile, "")

	t.Setenv("NILLSEC_VAULT", vaultFile)
	t.Setenv("NILLSEC_PASSWORD", editTestPassword)
	t.Setenv("EDITOR", editor)

	if err := cmdEdit(nil); err != nil {
		t.Fatalf("cmdEdit: %v", err)
	}

	v, err := vault.Load(vaultFile, []byte(editTestPassword))
	if err != nil {
		t.Fatalf("vault.Load after edit: %v", err)
	}
	if val, ok := v.Get("added_key"); !ok || val != "added_value" {
		t.Errorf("added_key = %q, %v; want %q, true", val, ok, "added_value")
	}
	if val, ok := v.Get("existing"); !ok || val != "original" {
		t.Errorf("existing = %q, %v; want %q, true", val, ok, "original")
	}
}

// TestCmdEditCleansUpEditorFile verifies that the editor file is removed once
// cmdEdit returns, regardless of success or failure.
func TestCmdEditCleansUpEditorFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake editor not supported on Windows")
	}
	dir := t.TempDir()
	vaultFile := filepath.Join(dir, "test.vault")
	makeTestVault(t, vaultFile, nil)

	newContent := `{"version":1,"secrets":{"k":"v"}}`
	newContentFile := filepath.Join(dir, "new-content.json")
	if err := os.WriteFile(newContentFile, []byte(newContent), 0600); err != nil {
		t.Fatalf("write new content file: %v", err)
	}

	pathRecordFile := filepath.Join(dir, "editor-path.txt")
	editor := fakeEditor(t, dir, newContentFile, pathRecordFile)

	t.Setenv("NILLSEC_VAULT", vaultFile)
	t.Setenv("NILLSEC_PASSWORD", editTestPassword)
	t.Setenv("EDITOR", editor)

	if err := cmdEdit(nil); err != nil {
		t.Fatalf("cmdEdit: %v", err)
	}

	raw, err := os.ReadFile(pathRecordFile)
	if err != nil {
		t.Fatalf("read path record file: %v", err)
	}
	editorPath := strings.TrimRight(string(raw), "\n\r")

	if _, err := os.Stat(editorPath); !os.IsNotExist(err) {
		t.Errorf("editor file %q still exists after cmdEdit completed; expected it to be removed", editorPath)
	}
}

// TestCmdEditUsesDevShm verifies that on Linux (where /dev/shm is available)
// the editor file is placed in /dev/shm so that the plaintext never reaches a
// physical disk.
func TestCmdEditUsesDevShm(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only: /dev/shm memory-backed storage test")
	}
	if _, err := os.Stat("/dev/shm"); err != nil {
		t.Skip("/dev/shm not available on this system")
	}

	dir := t.TempDir()
	vaultFile := filepath.Join(dir, "test.vault")
	makeTestVault(t, vaultFile, nil)

	newContent := `{"version":1,"secrets":{"k":"v"}}`
	newContentFile := filepath.Join(dir, "new-content.json")
	if err := os.WriteFile(newContentFile, []byte(newContent), 0600); err != nil {
		t.Fatalf("write new content file: %v", err)
	}

	pathRecordFile := filepath.Join(dir, "editor-path.txt")
	editor := fakeEditor(t, dir, newContentFile, pathRecordFile)

	t.Setenv("NILLSEC_VAULT", vaultFile)
	t.Setenv("NILLSEC_PASSWORD", editTestPassword)
	t.Setenv("EDITOR", editor)

	if err := cmdEdit(nil); err != nil {
		t.Fatalf("cmdEdit: %v", err)
	}

	raw, err := os.ReadFile(pathRecordFile)
	if err != nil {
		t.Fatalf("read path record file: %v", err)
	}
	editorPath := strings.TrimRight(string(raw), "\n\r")

	if !strings.HasPrefix(editorPath, "/dev/shm/") {
		t.Errorf("editor file path %q does not start with /dev/shm/; plaintext may have been written to disk", editorPath)
	}
}
