package main

import (
	"bufio"
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
	t.Setenv("VISUAL", "")
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
	t.Setenv("VISUAL", "")
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
	t.Setenv("VISUAL", "")
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

func TestWipeFileDoesNotFollowSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "important.txt")
	content := []byte("must remain intact")
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	link := filepath.Join(dir, "editor.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	wipeFile(link)
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("wipeFile followed symlink and changed target: %q", got)
	}
}

func TestEditorFileReadRejectsSymlinkWithoutTouchingTarget(t *testing.T) {
	target := filepath.Join(t.TempDir(), "important.json")
	content := []byte(`{"version":1,"secrets":{"important":"untouched"}}`)
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	ef, err := newEditorFile([]byte(`{"version":1,"secrets":{}}`))
	if err != nil {
		t.Fatalf("newEditorFile: %v", err)
	}
	path := ef.path()
	t.Cleanup(ef.discard)
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove editor file: %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if _, err := ef.readAndClose(); err == nil {
		t.Fatal("readAndClose accepted symlink")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile target: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("editor cleanup changed symlink target: %q", got)
	}
}

func TestEditorFileReadDoesNotWipeReplacementHardLink(t *testing.T) {
	target := filepath.Join(t.TempDir(), "important.json")
	content := []byte(`{"version":1,"secrets":{"important":"untouched"}}`)
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	ef, err := newEditorFile([]byte(`{"version":1,"secrets":{}}`))
	if err != nil {
		t.Fatalf("newEditorFile: %v", err)
	}
	path := ef.path()
	t.Cleanup(ef.discard)
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove editor file: %v", err)
	}
	if err := os.Link(target, path); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}

	gotEditor, err := ef.readAndClose()
	if err != nil {
		t.Fatalf("readAndClose: %v", err)
	}
	if string(gotEditor) != string(content) {
		t.Fatalf("editor content = %q; want replacement content", gotEditor)
	}
	wipeBytes(gotEditor)
	gotTarget, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile target: %v", err)
	}
	if string(gotTarget) != string(content) {
		t.Fatalf("editor cleanup wiped hard-link target: %q", gotTarget)
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
	t.Setenv("VISUAL", "")
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

// TestBuildChildEnvWindowsNormalization verifies that when normalizeKeys is
// true (simulating Windows), inherited env keys are upper-cased before the
// merge so that vault values deterministically override mixed-case entries
// (e.g. "Path" from Windows' os.Environ() is overridden by vault key "path"
// which is stored as "PATH").
func TestBuildChildEnvWindowsNormalization(t *testing.T) {
	dir := t.TempDir()
	vaultFile := filepath.Join(dir, "test.vault")
	makeTestVault(t, vaultFile, map[string]string{
		"path": "/vault/bin",
		"foo":  "vaultfoo",
	})

	v, err := vault.Load(vaultFile, []byte(editTestPassword))
	if err != nil {
		t.Fatalf("vault.Load: %v", err)
	}

	// Simulate Windows inherited env: mixed-case keys.
	inherited := []string{
		"Path=C:\\Windows\\System32",
		"Foo=inheritfoo",
		"TEMP=C:\\Temp",
	}

	env := buildChildEnv(inherited, v, true /* normalizeKeys = Windows */)

	got := make(map[string]string, len(env))
	for _, e := range env {
		k, val, _ := strings.Cut(e, "=")
		got[k] = val
	}

	// Vault "path" (→ "PATH") must override inherited "Path".
	if got["PATH"] != "/vault/bin" {
		t.Errorf("PATH = %q; want %q", got["PATH"], "/vault/bin")
	}
	// Mixed-case key must not survive; only upper-case form exists.
	if _, exists := got["Path"]; exists {
		t.Error("envMap still contains mixed-case key 'Path'; expected it to be normalized to 'PATH'")
	}
	// Vault "foo" (→ "FOO") must override inherited "Foo".
	if got["FOO"] != "vaultfoo" {
		t.Errorf("FOO = %q; want %q", got["FOO"], "vaultfoo")
	}
	if _, exists := got["Foo"]; exists {
		t.Error("envMap still contains mixed-case key 'Foo'; expected it to be normalized to 'FOO'")
	}
	// Non-conflicting inherited key normalized to upper.
	if got["TEMP"] != "C:\\Temp" {
		t.Errorf("TEMP = %q; want %q", got["TEMP"], "C:\\Temp")
	}
}

// TestBuildChildEnvNoNormalization verifies that when normalizeKeys is false
// (non-Windows), mixed-case inherited keys are preserved as-is, and vault
// values are stored under their upper-cased names without affecting other keys.
func TestBuildChildEnvNoNormalization(t *testing.T) {
	dir := t.TempDir()
	vaultFile := filepath.Join(dir, "test.vault")
	makeTestVault(t, vaultFile, map[string]string{"secret": "vaultval"})

	v, err := vault.Load(vaultFile, []byte(editTestPassword))
	if err != nil {
		t.Fatalf("vault.Load: %v", err)
	}

	inherited := []string{
		"existing=inherit",
		"SECRET=will-be-overridden",
	}

	env := buildChildEnv(inherited, v, false /* normalizeKeys = non-Windows */)

	got := make(map[string]string, len(env))
	for _, e := range env {
		k, val, _ := strings.Cut(e, "=")
		got[k] = val
	}

	// "existing" preserved with original case.
	if got["existing"] != "inherit" {
		t.Errorf("existing = %q; want %q", got["existing"], "inherit")
	}
	// Vault "secret" (→ "SECRET") overrides inherited "SECRET".
	if got["SECRET"] != "vaultval" {
		t.Errorf("SECRET = %q; want %q", got["SECRET"], "vaultval")
	}
}

func TestBuildChildEnvStripsMasterPassword(t *testing.T) {
	dir := t.TempDir()
	vaultFile := filepath.Join(dir, "test.vault")
	makeTestVault(t, vaultFile, map[string]string{"api_key": "secret"})
	v, err := vault.Load(vaultFile, []byte(editTestPassword))
	if err != nil {
		t.Fatalf("vault.Load: %v", err)
	}

	env := buildChildEnv([]string{
		"PATH=/usr/bin",
		"NILLSEC_PASSWORD=master-password",
	}, v, false)
	for _, entry := range env {
		if strings.HasPrefix(entry, "NILLSEC_PASSWORD=") {
			t.Fatalf("child environment leaked master password: %q", entry)
		}
	}
}

func TestStripSensitiveEnvHonorsWindowsCaseInsensitivity(t *testing.T) {
	env := stripSensitiveEnv([]string{
		"Path=C:\\Windows",
		"nillsec_password=master-password",
		"SAFE=value",
	}, true)
	got := strings.Join(env, "\n")
	if strings.Contains(strings.ToUpper(got), "NILLSEC_PASSWORD=") {
		t.Fatalf("sanitized environment leaked master password: %q", got)
	}
	if !strings.Contains(got, "SAFE=value") {
		t.Fatalf("sanitized environment dropped safe value: %q", got)
	}
}

func TestValidateEnvironmentRejectsAmbiguousOrInvalidEntries(t *testing.T) {
	tests := []struct {
		name    string
		secrets map[string]string
		want    string
	}{
		{"case collision", map[string]string{"token": "one", "TOKEN": "two"}, "both export as"},
		{"invalid key", map[string]string{"not-valid": "value"}, "invalid vault key"},
		{"reserved key", map[string]string{"nillsec_password": "value"}, "reserved"},
		{"nul value", map[string]string{"valid": "before\x00after"}, "NUL byte"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "test.vault")
			makeTestVault(t, path, tt.secrets)
			v, err := vault.Load(path, []byte(editTestPassword))
			if err != nil {
				t.Fatalf("vault.Load: %v", err)
			}
			err = validateEnvironment(v)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validateEnvironment() error = %v; want text %q", err, tt.want)
			}
		})
	}
}

func TestCmdAddReadsSecretFromStdin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.vault")
	makeTestVault(t, path, nil)
	t.Setenv("NILLSEC_VAULT", path)
	t.Setenv("NILLSEC_PASSWORD", editTestPassword)

	originalReader := stdinReader
	t.Cleanup(func() { stdinReader = originalReader })
	stdinReader = bufio.NewReader(strings.NewReader("secret from stdin\n"))

	if err := cmdAdd([]string{"api_key"}, false); err != nil {
		t.Fatalf("cmdAdd: %v", err)
	}
	v, err := vault.Load(path, []byte(editTestPassword))
	if err != nil {
		t.Fatalf("vault.Load: %v", err)
	}
	if got, ok := v.Get("api_key"); !ok || got != "secret from stdin" {
		t.Fatalf("api_key = %q, %v; want stdin value", got, ok)
	}
}

func TestEnvShellFormatting(t *testing.T) {
	tests := []struct {
		shell, key, value, want string
	}{
		{"sh", "API_KEY", "it's safe", "export API_KEY='it'\\''s safe'"},
		{"powershell", "API_KEY", "it's safe", "$env:API_KEY = 'it''s safe'"},
	}
	for _, tt := range tests {
		if got := formatEnvAssignment(tt.shell, tt.key, tt.value); got != tt.want {
			t.Errorf("formatEnvAssignment(%q) = %q; want %q", tt.shell, got, tt.want)
		}
	}

	for _, args := range [][]string{{"--shell", "sh"}, {"--shell=pwsh"}} {
		if _, err := parseEnvShell(args); err != nil {
			t.Errorf("parseEnvShell(%q): %v", args, err)
		}
	}
	if _, err := parseEnvShell([]string{"--shell", "fish"}); err == nil {
		t.Fatal("parseEnvShell accepted unsupported shell")
	}
}

func TestParseEditorCommand(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"code --wait", []string{"code", "--wait"}},
		{`"C:\Program Files\Editor\editor.exe" --reuse-window`, []string{`C:\Program Files\Editor\editor.exe`, "--reuse-window"}},
		{`editor --name 'two words'`, []string{"editor", "--name", "two words"}},
	}
	for _, tt := range tests {
		got, err := parseEditorCommand(tt.input)
		if err != nil {
			t.Fatalf("parseEditorCommand(%q): %v", tt.input, err)
		}
		if strings.Join(got, "\x00") != strings.Join(tt.want, "\x00") {
			t.Errorf("parseEditorCommand(%q) = %q; want %q", tt.input, got, tt.want)
		}
	}
	if _, err := parseEditorCommand(`editor "unterminated`); err == nil {
		t.Fatal("parseEditorCommand accepted unclosed quote")
	}
}

func TestCommandArityErrorsBeforeSideEffects(t *testing.T) {
	tests := []struct {
		name string
		call func() error
	}{
		{"init", func() error { return cmdInit([]string{"one", "two"}) }},
		{"add", func() error { return cmdAdd(nil, false) }},
		{"get", func() error { return cmdGet([]string{"one", "two"}) }},
		{"list", func() error { return cmdList([]string{"extra"}) }},
		{"remove", func() error { return cmdRemove([]string{"one", "two"}) }},
		{"edit", func() error { return cmdEdit([]string{"extra"}) }},
		{"upgrade", func() error { return run([]string{"upgrade", "extra"}) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(); err == nil || !strings.Contains(err.Error(), "usage:") {
				t.Fatalf("error = %v; want usage error", err)
			}
		})
	}
}

func TestPromptPasswordConfirmRejectsShortPassword(t *testing.T) {
	t.Setenv("NILLSEC_PASSWORD", "too-short")
	if _, err := promptPasswordConfirm(); err == nil || !strings.Contains(err.Error(), "at least 12") {
		t.Fatalf("error = %v; want minimum-length error", err)
	}
}

// TestLookPathInEnvUsesChildPath verifies that lookPathInEnv finds an
// executable in a directory listed in the child env's PATH rather than in
// the current process PATH.
func TestLookPathInEnvUsesChildPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("executable permission bits not applicable on Windows")
	}

	dir := t.TempDir()
	exe := filepath.Join(dir, "myfakeexe")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatalf("write executable: %v", err)
	}

	childEnv := []string{"PATH=" + dir}
	got, err := lookPathInEnv("myfakeexe", childEnv)
	if err != nil {
		t.Fatalf("lookPathInEnv: %v", err)
	}
	if got != exe {
		t.Errorf("resolved path = %q; want %q", got, exe)
	}
}

func TestLookPathInEnvUsesPATHEXTOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only PATHEXT behavior")
	}
	dir := t.TempDir()
	exe := filepath.Join(dir, "myfakeexe.CMD")
	if err := os.WriteFile(exe, []byte("@exit /b 0\r\n"), 0o600); err != nil {
		t.Fatalf("write executable: %v", err)
	}
	got, err := lookPathInEnv("myfakeexe", []string{"PATH=" + dir, "PATHEXT=.CMD;.EXE"})
	if err != nil {
		t.Fatalf("lookPathInEnv: %v", err)
	}
	if !strings.EqualFold(got, exe) {
		t.Fatalf("resolved path = %q; want %q", got, exe)
	}
}

// TestLookPathInEnvExplicitPath verifies that a name containing a path
// separator is returned as-is without performing a directory search.
func TestLookPathInEnvExplicitPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("path separator semantics differ on Windows")
	}
	name := "/usr/bin/env"
	childEnv := []string{"PATH=/some/dir"}
	got, err := lookPathInEnv(name, childEnv)
	if err != nil {
		t.Fatalf("lookPathInEnv: %v", err)
	}
	if got != name {
		t.Errorf("got %q; want %q", got, name)
	}
}

// TestLookPathInEnvFallback verifies that when childEnv contains no PATH
// entry, lookPathInEnv falls back to the current process PATH via exec.LookPath.
func TestLookPathInEnvFallback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh not available on Windows")
	}
	// "sh" must be resolvable via the current process PATH on any Unix host.
	got, err := lookPathInEnv("sh", nil /* no PATH entry */)
	if err != nil {
		t.Fatalf("lookPathInEnv fallback: %v", err)
	}
	if got == "" {
		t.Error("expected a non-empty resolved path for 'sh'")
	}
}

// TestLookPathInEnvNotFound verifies that an error is returned when the
// executable is not found in the child env PATH.
func TestLookPathInEnvNotFound(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("executable permission bits not applicable on Windows")
	}
	childEnv := []string{"PATH=/nonexistent/directory"}
	_, err := lookPathInEnv("no-such-binary", childEnv)
	if err == nil {
		t.Fatal("expected error for missing executable, got nil")
	}
}

// TestCmdExecUsesVaultPath verifies that cmdExec resolves the command name
// using the vault-provided PATH rather than the current process PATH.
func TestCmdExecUsesVaultPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script subprocess not supported on Windows")
	}

	dir := t.TempDir()
	vaultFile := filepath.Join(dir, "test.vault")

	// Create a fake executable named "myapp" reachable only via binDir.
	binDir := filepath.Join(dir, "bin")
	if err := os.Mkdir(binDir, 0755); err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}
	outFile := filepath.Join(dir, "out.txt")
	fakeExe := filepath.Join(binDir, "myapp")
	scriptContent := "#!/bin/sh\necho ran > \"" + outFile + "\"\n"
	if err := os.WriteFile(fakeExe, []byte(scriptContent), 0755); err != nil {
		t.Fatalf("write fake exe: %v", err)
	}

	// Store binDir as the vault PATH so cmdExec can resolve "myapp" by name.
	makeTestVault(t, vaultFile, map[string]string{"path": binDir})

	t.Setenv("NILLSEC_VAULT", vaultFile)
	t.Setenv("NILLSEC_PASSWORD", editTestPassword)

	// "myapp" is not on the current process PATH; only the vault PATH has it.
	if err := cmdExec([]string{"myapp"}); err != nil {
		t.Fatalf("cmdExec: %v", err)
	}

	raw, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read out file: %v", err)
	}
	if got := strings.TrimRight(string(raw), "\n\r"); got != "ran" {
		t.Errorf("output = %q; want %q", got, "ran")
	}
}

func TestCmdExecUsesPATHEXTAndHidesMasterPasswordOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only command execution behavior")
	}
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.Mkdir(binDir, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	outFile := filepath.Join(dir, "out.txt")
	script := filepath.Join(binDir, "check-env.CMD")
	content := "@if defined NILLSEC_PASSWORD exit /b 9\r\n@echo %MY_SECRET%>\"" + outFile + "\"\r\n"
	if err := os.WriteFile(script, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	vaultFile := filepath.Join(dir, "test.vault")
	makeTestVault(t, vaultFile, map[string]string{
		"path":      binDir,
		"pathext":   ".CMD",
		"my_secret": "available",
	})
	t.Setenv("NILLSEC_VAULT", vaultFile)
	t.Setenv("NILLSEC_PASSWORD", editTestPassword)

	if err := cmdExec([]string{"check-env"}); err != nil {
		t.Fatalf("cmdExec: %v", err)
	}
	got, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.TrimSpace(string(got)) != "available" {
		t.Fatalf("output = %q; want injected secret", got)
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
