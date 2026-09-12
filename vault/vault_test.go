package vault_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/403-html/nillsec/vault"
)

const testPassword = "hunter2-test-password"

// testPW returns the test password as a byte slice, matching the []byte API.
func testPW() []byte { return []byte(testPassword) }

// ---------------------------------------------------------------------------
// Init / Load / Save round-trip
// ---------------------------------------------------------------------------

func TestInitCreatesVaultFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.vault")
	if err := vault.Init(path, testPW()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("vault file is empty")
	}
	if runtime.GOOS != "windows" {
		// File permissions should be 0600 on POSIX-like systems.
		if info.Mode().Perm() != 0600 {
			t.Errorf("file mode = %o, want 0600", info.Mode().Perm())
		}
	}
}

func TestInitFailsIfVaultAlreadyExists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.vault")
	if err := vault.Init(path, testPW()); err != nil {
		t.Fatalf("first Init: %v", err)
	}
	if err := vault.Init(path, testPW()); err == nil {
		t.Fatal("expected error on second Init, got nil")
	}
}

func TestInitRefusesDanglingSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.vault")
	target := filepath.Join(dir, "target-does-not-exist")
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if err := vault.Init(path, testPW()); err == nil {
		t.Fatal("Init followed a dangling symlink")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("symlink target was unexpectedly created: %v", err)
	}
}

func TestLoadEmptyVault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.vault")
	if err := vault.Init(path, testPW()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	v, err := vault.Load(path, testPW())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(v.Keys()) != 0 {
		t.Errorf("expected empty vault, got keys: %v", v.Keys())
	}
}

func TestLoadWrongPasswordFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.vault")
	if err := vault.Init(path, testPW()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if _, err := vault.Load(path, []byte("wrong-password")); err == nil {
		t.Fatal("expected decryption error with wrong password")
	}
}

// ---------------------------------------------------------------------------
// Set / Get / Delete / Keys
// ---------------------------------------------------------------------------

func TestSetAndGet(t *testing.T) {
	v := newVault(t)
	v.Set("db_pass", "secret123")
	val, ok := v.Get("db_pass")
	if !ok {
		t.Fatal("key not found after Set")
	}
	if val != "secret123" {
		t.Errorf("Get = %q, want %q", val, "secret123")
	}
}

func TestSetOverwrites(t *testing.T) {
	v := newVault(t)
	v.Set("key", "old")
	v.Set("key", "new")
	val, _ := v.Get("key")
	if val != "new" {
		t.Errorf("Get = %q, want %q", val, "new")
	}
}

func TestGetMissingKey(t *testing.T) {
	v := newVault(t)
	_, ok := v.Get("nonexistent")
	if ok {
		t.Fatal("expected ok=false for missing key")
	}
}

func TestDeleteExistingKey(t *testing.T) {
	v := newVault(t)
	v.Set("key", "value")
	if !v.Delete("key") {
		t.Fatal("Delete returned false for existing key")
	}
	if _, ok := v.Get("key"); ok {
		t.Fatal("key still present after Delete")
	}
}

func TestDeleteMissingKey(t *testing.T) {
	v := newVault(t)
	if v.Delete("nonexistent") {
		t.Fatal("Delete returned true for missing key")
	}
}

func TestKeysSorted(t *testing.T) {
	v := newVault(t)
	v.Set("zebra", "1")
	v.Set("alpha", "2")
	v.Set("mango", "3")
	keys := v.Keys()
	want := []string{"alpha", "mango", "zebra"}
	if len(keys) != len(want) {
		t.Fatalf("Keys len = %d, want %d", len(keys), len(want))
	}
	for i, k := range keys {
		if k != want[i] {
			t.Errorf("Keys[%d] = %q, want %q", i, k, want[i])
		}
	}
}

// ---------------------------------------------------------------------------
// Persistence round-trip
// ---------------------------------------------------------------------------

func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.vault")
	if err := vault.Init(path, testPW()); err != nil {
		t.Fatalf("Init: %v", err)
	}

	v, err := vault.Load(path, testPW())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	v.Set("api_token", "tok123")
	v.Set("db_pass", "dbsecret")
	if err := vault.Save(path, testPW(), v); err != nil {
		t.Fatalf("Save: %v", err)
	}

	v2, err := vault.Load(path, testPW())
	if err != nil {
		t.Fatalf("second Load: %v", err)
	}
	if val, ok := v2.Get("api_token"); !ok || val != "tok123" {
		t.Errorf("api_token = %q, %v; want %q, true", val, ok, "tok123")
	}
	if val, ok := v2.Get("db_pass"); !ok || val != "dbsecret" {
		t.Errorf("db_pass = %q, %v; want %q, true", val, ok, "dbsecret")
	}
}

func TestSaveRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.vault")
	if err := vault.Init(target, testPW()); err != nil {
		t.Fatalf("Init target: %v", err)
	}
	link := filepath.Join(dir, "link.vault")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	v, err := vault.Load(target, testPW())
	if err != nil {
		t.Fatalf("Load target: %v", err)
	}
	v.Set("key", "new value")
	if err := vault.Save(link, testPW(), v); err == nil {
		t.Fatal("Save accepted symlink destination")
	}

	unchanged, err := vault.Load(target, testPW())
	if err != nil {
		t.Fatalf("Load unchanged target: %v", err)
	}
	if _, exists := unchanged.Get("key"); exists {
		t.Fatal("Save through symlink modified the target vault")
	}
}

func TestSaveRepairsPrivatePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not applicable on Windows")
	}
	path := filepath.Join(t.TempDir(), "secrets.vault")
	if err := vault.Init(path, testPW()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	v, err := vault.Load(path, testPW())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := vault.Save(path, testPW(), v); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o; want 600", info.Mode().Perm())
	}
}

func TestSaveLeavesOnlyCompleteVaultFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.vault")
	if err := vault.Init(path, testPW()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	v, err := vault.Load(path, testPW())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	v.Set("key", "value")
	if err := vault.Save(path, testPW(), v); err != nil {
		t.Fatalf("Save: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "secrets.vault" {
		t.Fatalf("unexpected files left after atomic save: %v", entries)
	}
}

func TestEachSaveUsesNewNonce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.vault")
	if err := vault.Init(path, testPW()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	v, err := vault.Load(path, testPW())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile (first): %v", err)
	}
	if err := vault.Save(path, testPW(), v); err != nil {
		t.Fatalf("Save: %v", err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile (second): %v", err)
	}
	if string(first) == string(second) {
		t.Error("two consecutive saves produced identical ciphertext (nonce reuse?)")
	}
}

// ---------------------------------------------------------------------------
// MarshalText / UnmarshalText (used by edit command)
// ---------------------------------------------------------------------------

func TestMarshalUnmarshalText(t *testing.T) {
	v := newVault(t)
	v.Set("token", "abc")

	txt, err := v.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}

	v2 := newVault(t)
	if err := v2.UnmarshalText(txt); err != nil {
		t.Fatalf("UnmarshalText: %v", err)
	}

	val, ok := v2.Get("token")
	if !ok || val != "abc" {
		t.Errorf("Get after UnmarshalText = %q, %v; want %q, true", val, ok, "abc")
	}
}

func TestUnmarshalTextRejectsUnknownTrailingOrUnsupportedContent(t *testing.T) {
	v := newVault(t)
	tests := []string{
		`{"version":1,"secrets":{},"typo":true}`,
		`{"version":1,"secrets":{}} {"version":1,"secrets":{}}`,
		`{"version":2,"secrets":{}}`,
		`{"version":1,"secrets":null}`,
	}
	for _, input := range tests {
		if err := v.UnmarshalText([]byte(input)); err == nil {
			t.Errorf("UnmarshalText accepted invalid content: %s", input)
		}
	}
}

// ---------------------------------------------------------------------------
// Vault file robustness
// ---------------------------------------------------------------------------

func TestLoadHandlesCRLFLineEndings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.vault")
	if err := vault.Init(path, testPW()); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Replace LF with CRLF to simulate Windows / editor round-trips.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	crlf := make([]byte, 0, len(raw)+10)
	for _, b := range raw {
		if b == '\n' {
			crlf = append(crlf, '\r', '\n')
		} else {
			crlf = append(crlf, b)
		}
	}
	if err := os.WriteFile(path, crlf, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := vault.Load(path, testPW()); err != nil {
		t.Errorf("Load rejected vault with CRLF line endings: %v", err)
	}
}

func TestLoadRejectsTruncatedSalt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.vault")
	if err := vault.Init(path, testPW()); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Corrupt the salt field to contain only 4 bytes (too short).
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	invalidB64 := "c2hvcnQ=" // base64("short"); 5 bytes, not 16
	lines := strings.Split(string(raw), "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "salt: ") {
			lines[i] = "salt: " + invalidB64
			break
		}
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := vault.Load(path, testPW()); err == nil {
		t.Error("expected error when salt length is wrong, got nil")
	}
}

func TestLoadRejectsTruncatedNonce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.vault")
	if err := vault.Init(path, testPW()); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Corrupt the nonce field to contain only a few bytes.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	invalidB64 := "c2hvcnQ=" // base64("short"); 5 bytes, not 12
	lines := strings.Split(string(raw), "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "nonce: ") {
			lines[i] = "nonce: " + invalidB64
			break
		}
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := vault.Load(path, testPW()); err == nil {
		t.Error("expected error when nonce length is wrong, got nil")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newVault creates an empty vault that was persisted and loaded from a temp
// file, exercising the full init/load path.
func newVault(t *testing.T) *vault.Vault {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secrets.vault")
	if err := vault.Init(path, testPW()); err != nil {
		t.Fatalf("newVault Init: %v", err)
	}
	v, err := vault.Load(path, testPW())
	if err != nil {
		t.Fatalf("newVault Load: %v", err)
	}
	return v
}
