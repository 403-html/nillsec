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
// cmdEdit returns after a successful edit.
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

// TestCmdEditCleansUpEditorFileOnEditorError verifies that the editor file is
// removed even when the editor exits with a non-zero status.
func TestCmdEditCleansUpEditorFileOnEditorError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake editor not supported on Windows")
	}
	dir := t.TempDir()
	vaultFile := filepath.Join(dir, "test.vault")
	makeTestVault(t, vaultFile, nil)

	pathRecordFile := filepath.Join(dir, "editor-path.txt")

	// A script that records the editor-file path but exits with an error.
	script := filepath.Join(dir, "fail-editor.sh")
	scriptContent := "#!/bin/sh\necho \"$1\" > \"" + pathRecordFile + "\"\nexit 1\n"
	if err := os.WriteFile(script, []byte(scriptContent), 0700); err != nil {
		t.Fatalf("write fail editor: %v", err)
	}

	t.Setenv("NILLSEC_VAULT", vaultFile)
	t.Setenv("NILLSEC_PASSWORD", editTestPassword)
	t.Setenv("EDITOR", script)

	if err := cmdEdit(nil); err == nil {
		t.Fatal("cmdEdit: expected error from failing editor, got nil")
	}

	raw, err := os.ReadFile(pathRecordFile)
	if err != nil {
		t.Fatalf("read path record file: %v", err)
	}
	editorPath := strings.TrimRight(string(raw), "\n\r")

	if _, err := os.Stat(editorPath); !os.IsNotExist(err) {
		t.Errorf("editor file %q still exists after cmdEdit returned error; expected it to be removed", editorPath)
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

// TestCmdExecInjectsSecrets verifies that cmdExec injects vault secrets as
// environment variables into the child process.
func TestCmdExecInjectsSecrets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script subprocess not supported on Windows")
	}

	dir := t.TempDir()
	vaultFile := filepath.Join(dir, "test.vault")
	makeTestVault(t, vaultFile, map[string]string{
		"my_secret": "hunter2",
		"api_token": "tok-abc",
	})

	// Script that writes the value of MY_SECRET to a file.
	outFile := filepath.Join(dir, "out.txt")
	script := filepath.Join(dir, "check-env.sh")
	scriptContent := "#!/bin/sh\necho \"$MY_SECRET\" > \"" + outFile + "\"\n"
	if err := os.WriteFile(script, []byte(scriptContent), 0700); err != nil {
		t.Fatalf("write script: %v", err)
	}

	t.Setenv("NILLSEC_VAULT", vaultFile)
	t.Setenv("NILLSEC_PASSWORD", editTestPassword)

	if err := cmdExec([]string{"--", script}); err != nil {
		t.Fatalf("cmdExec: %v", err)
	}

	raw, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read out file: %v", err)
	}
	got := strings.TrimRight(string(raw), "\n\r")
	if got != "hunter2" {
		t.Errorf("MY_SECRET = %q; want %q", got, "hunter2")
	}
}

// TestCmdExecWithoutDoubleDash verifies that the "--" separator is optional.
func TestCmdExecWithoutDoubleDash(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script subprocess not supported on Windows")
	}

	dir := t.TempDir()
	vaultFile := filepath.Join(dir, "test.vault")
	makeTestVault(t, vaultFile, map[string]string{"token": "secret-value"})

	outFile := filepath.Join(dir, "out.txt")
	script := filepath.Join(dir, "check-env.sh")
	scriptContent := "#!/bin/sh\necho \"$TOKEN\" > \"" + outFile + "\"\n"
	if err := os.WriteFile(script, []byte(scriptContent), 0700); err != nil {
		t.Fatalf("write script: %v", err)
	}

	t.Setenv("NILLSEC_VAULT", vaultFile)
	t.Setenv("NILLSEC_PASSWORD", editTestPassword)

	// No "--" separator.
	if err := cmdExec([]string{script}); err != nil {
		t.Fatalf("cmdExec: %v", err)
	}

	raw, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read out file: %v", err)
	}
	got := strings.TrimRight(string(raw), "\n\r")
	if got != "secret-value" {
		t.Errorf("TOKEN = %q; want %q", got, "secret-value")
	}
}

// TestCmdExecDoubleDashPassthrough verifies that a "--" that is NOT the first
// argument is passed through to the child command unchanged.  For example:
//
//	nillsec exec some-tool -- --flag
//
// should invoke some-tool with the arguments ["--", "--flag"], not strip the
// "--" and try to run "--flag" as the command.
func TestCmdExecDoubleDashPassthrough(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script subprocess not supported on Windows")
	}

	dir := t.TempDir()
	vaultFile := filepath.Join(dir, "test.vault")
	makeTestVault(t, vaultFile, nil)

	// Script that writes its first argument to a file so we can verify it
	// received "--" intact.
	outFile := filepath.Join(dir, "out.txt")
	script := filepath.Join(dir, "record-arg.sh")
	scriptContent := "#!/bin/sh\necho \"$1\" > \"" + outFile + "\"\n"
	if err := os.WriteFile(script, []byte(scriptContent), 0700); err != nil {
		t.Fatalf("write script: %v", err)
	}

	t.Setenv("NILLSEC_VAULT", vaultFile)
	t.Setenv("NILLSEC_PASSWORD", editTestPassword)

	// Pass "--" as an argument to the script, not as a separator.
	if err := cmdExec([]string{script, "--", "--flag"}); err != nil {
		t.Fatalf("cmdExec: %v", err)
	}

	raw, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read out file: %v", err)
	}
	got := strings.TrimRight(string(raw), "\n\r")
	if got != "--" {
		t.Errorf("first arg = %q; want %q (-- should not be consumed when not the first arg)", got, "--")
	}
}

// TestCmdExecNoArgs verifies that an error is returned when no command is given.
func TestCmdExecNoArgs(t *testing.T) {
	dir := t.TempDir()
	vaultFile := filepath.Join(dir, "test.vault")
	makeTestVault(t, vaultFile, nil)

	t.Setenv("NILLSEC_VAULT", vaultFile)
	t.Setenv("NILLSEC_PASSWORD", editTestPassword)

	if err := cmdExec([]string{"--"}); err == nil {
		t.Fatal("cmdExec with no command: expected error, got nil")
	}

	if err := cmdExec([]string{}); err == nil {
		t.Fatal("cmdExec with empty args: expected error, got nil")
	}
}

// TestCmdExecExitCodePropagation verifies that a non-zero exit from the child
// process causes osExitFn to be called with the matching code.
func TestCmdExecExitCodePropagation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script subprocess not supported on Windows")
	}

	dir := t.TempDir()
	vaultFile := filepath.Join(dir, "test.vault")
	makeTestVault(t, vaultFile, nil)

	// Script that exits with code 42.
	script := filepath.Join(dir, "fail.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 42\n"), 0700); err != nil {
		t.Fatalf("write script: %v", err)
	}

	t.Setenv("NILLSEC_VAULT", vaultFile)
	t.Setenv("NILLSEC_PASSWORD", editTestPassword)

	var capturedCode int
	origOsExitFn := osExitFn
	t.Cleanup(func() { osExitFn = origOsExitFn })
	osExitFn = func(code int) { capturedCode = code }

	if err := cmdExec([]string{"--", script}); err != nil {
		t.Fatalf("cmdExec: unexpected error: %v", err)
	}

	if capturedCode != 42 {
		t.Errorf("exit code = %d; want 42", capturedCode)
	}
}
