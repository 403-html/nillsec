package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.vault")
	password := []byte("hunter2")

	// Create a new vault and save it.
	v := newVault()
	v.Secrets["db_password"] = "s3cr3t"
	v.Secrets["api_token"] = "tok-abc"

	if err := v.Save(path, password); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// The file must exist.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("vault file not created: %v", err)
	}

	// Re-open and compare.
	v2, err := openVault(path, password)
	if err != nil {
		t.Fatalf("openVault: %v", err)
	}

	if v2.Secrets["db_password"] != "s3cr3t" {
		t.Errorf("db_password: got %q, want %q", v2.Secrets["db_password"], "s3cr3t")
	}
	if v2.Secrets["api_token"] != "tok-abc" {
		t.Errorf("api_token: got %q, want %q", v2.Secrets["api_token"], "tok-abc")
	}
}

func TestWrongPassword(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.vault")
	password := []byte("correct-horse")

	v := newVault()
	v.Secrets["key"] = "value"
	if err := v.Save(path, password); err != nil {
		t.Fatalf("Save: %v", err)
	}

	_, err := openVault(path, []byte("wrong-password"))
	if err == nil {
		t.Fatal("expected error with wrong password, got nil")
	}
}

func TestNonceUniqueness(t *testing.T) {
	// Each Save should produce a different ciphertext (unique nonces).
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.vault")
	password := []byte("pass")

	v := newVault()
	v.Secrets["k"] = "v"

	if err := v.Save(path, password); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	data1, _ := os.ReadFile(path)

	if err := v.Save(path, password); err != nil {
		t.Fatalf("second Save: %v", err)
	}
	data2, _ := os.ReadFile(path)

	if string(data1) == string(data2) {
		t.Error("two saves produced identical ciphertexts (nonce reuse!)")
	}
}

func TestEmptyVault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.vault")
	password := []byte("pass")

	v := newVault()
	if err := v.Save(path, password); err != nil {
		t.Fatalf("Save: %v", err)
	}

	v2, err := openVault(path, password)
	if err != nil {
		t.Fatalf("openVault: %v", err)
	}
	if len(v2.Secrets) != 0 {
		t.Errorf("expected empty secrets, got %v", v2.Secrets)
	}
}

func TestNotAVaultFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.vault")
	if err := os.WriteFile(path, []byte("not a vault\n"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := openVault(path, []byte("pass"))
	if err == nil {
		t.Fatal("expected error for non-vault file, got nil")
	}
}

func TestSaveUpdatesSecrets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.vault")
	password := []byte("pass")

	v := newVault()
	v.Secrets["k"] = "original"
	if err := v.Save(path, password); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Mutate and re-save.
	v.Secrets["k"] = "updated"
	if err := v.Save(path, password); err != nil {
		t.Fatalf("re-Save: %v", err)
	}

	v2, err := openVault(path, password)
	if err != nil {
		t.Fatalf("openVault: %v", err)
	}
	if v2.Secrets["k"] != "updated" {
		t.Errorf("expected 'updated', got %q", v2.Secrets["k"])
	}
}
