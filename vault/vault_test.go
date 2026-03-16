package vault_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/403-html/nillsec/vault"
)

const testPassword = "hunter2-test-password"

// ---------------------------------------------------------------------------
// Init / Load / Save round-trip
// ---------------------------------------------------------------------------

func TestInitCreatesVaultFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.vault")
	if err := vault.Init(path, testPassword); err != nil {
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
	if err := vault.Init(path, testPassword); err != nil {
		t.Fatalf("first Init: %v", err)
	}
	if err := vault.Init(path, testPassword); err == nil {
		t.Fatal("expected error on second Init, got nil")
	}
}

func TestLoadEmptyVault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.vault")
	if err := vault.Init(path, testPassword); err != nil {
		t.Fatalf("Init: %v", err)
	}
	v, err := vault.Load(path, testPassword)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(v.Keys()) != 0 {
		t.Errorf("expected empty vault, got keys: %v", v.Keys())
	}
}

func TestLoadWrongPasswordFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.vault")
	if err := vault.Init(path, testPassword); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if _, err := vault.Load(path, "wrong-password"); err == nil {
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
	if err := vault.Init(path, testPassword); err != nil {
		t.Fatalf("Init: %v", err)
	}

	v, err := vault.Load(path, testPassword)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	v.Set("api_token", "tok123")
	v.Set("db_pass", "dbsecret")
	if err := vault.Save(path, testPassword, v); err != nil {
		t.Fatalf("Save: %v", err)
	}

	v2, err := vault.Load(path, testPassword)
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

func TestEachSaveUsesNewNonce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.vault")
	if err := vault.Init(path, testPassword); err != nil {
		t.Fatalf("Init: %v", err)
	}
	v, _ := vault.Load(path, testPassword)
	first, _ := os.ReadFile(path)
	if err := vault.Save(path, testPassword, v); err != nil {
		t.Fatalf("Save: %v", err)
	}
	second, _ := os.ReadFile(path)
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newVault creates an empty vault that was persisted and loaded from a temp
// file, exercising the full init/load path.
func newVault(t *testing.T) *vault.Vault {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secrets.vault")
	if err := vault.Init(path, testPassword); err != nil {
		t.Fatalf("newVault Init: %v", err)
	}
	v, err := vault.Load(path, testPassword)
	if err != nil {
		t.Fatalf("newVault Load: %v", err)
	}
	return v
}
