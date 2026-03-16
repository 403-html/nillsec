// Package vault implements encrypted secret storage using Argon2id + AES-256-GCM.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	vaultHeader = "$VAULT;1"

	// Argon2id KDF parameters – tuned for interactive use.
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 4
	argonKeyLen  = 32 // 256-bit key

	saltSize  = 16 // 128-bit salt
	nonceSize = 12 // 96-bit GCM nonce (standard)
)

// payload is the plaintext structure stored inside the encrypted vault.
type payload struct {
	Version int               `json:"version"`
	Secrets map[string]string `json:"secrets"`
}

// Vault provides high-level access to the decrypted secrets.
type Vault struct {
	data payload
}

// Get returns the value for key, and whether it existed.
func (v *Vault) Get(key string) (string, bool) {
	val, ok := v.data.Secrets[key]
	return val, ok
}

// Set inserts or overwrites key with value.
func (v *Vault) Set(key, value string) {
	if v.data.Secrets == nil {
		v.data.Secrets = make(map[string]string)
	}
	v.data.Secrets[key] = value
}

// Delete removes key; returns true if the key existed.
func (v *Vault) Delete(key string) bool {
	if _, ok := v.data.Secrets[key]; !ok {
		return false
	}
	delete(v.data.Secrets, key)
	return true
}

// Keys returns a sorted list of secret keys.
func (v *Vault) Keys() []string {
	keys := make([]string, 0, len(v.data.Secrets))
	for k := range v.data.Secrets {
		keys = append(keys, k)
	}
	// Deterministic order.
	sortStrings(keys)
	return keys
}

// MarshalText serialises the decrypted payload as indented JSON, suitable
// for in-editor display.
func (v *Vault) MarshalText() ([]byte, error) {
	return json.MarshalIndent(v.data, "", "  ")
}

// UnmarshalText replaces the vault contents from indented JSON produced by
// MarshalText. Used by the edit command after the user saves the file.
func (v *Vault) UnmarshalText(data []byte) error {
	var p payload
	if err := json.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("invalid vault content: %w", err)
	}
	v.data = p
	return nil
}

// Init creates a new, empty, encrypted vault file at path.
// It returns an error if the file already exists.
func Init(path, password string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("vault already exists: %s", path)
	}
	v := &Vault{data: payload{Version: 1, Secrets: make(map[string]string)}}
	return Save(path, password, v)
}

// Load reads and decrypts the vault at path using password.
func Load(path, password string) (*Vault, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read vault: %w", err)
	}

	salt, nonce, ciphertext, err := parseVaultFile(raw)
	if err != nil {
		return nil, err
	}

	key := deriveKey([]byte(password), salt)
	defer wipe(key)

	plaintext, err := decrypt(ciphertext, nonce, key)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong password?): %w", err)
	}
	defer wipe(plaintext)

	var p payload
	if err := json.Unmarshal(plaintext, &p); err != nil {
		return nil, fmt.Errorf("corrupt vault payload: %w", err)
	}

	return &Vault{data: p}, nil
}

// Save encrypts the vault and writes it to path.
// A fresh random salt and nonce are generated on every call.
func Save(path, password string, v *Vault) error {
	plaintext, err := json.Marshal(v.data)
	if err != nil {
		return fmt.Errorf("marshal error: %w", err)
	}
	defer wipe(plaintext)

	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("cannot generate salt: %w", err)
	}

	key := deriveKey([]byte(password), salt)
	defer wipe(key)

	nonce, ciphertext, err := encrypt(plaintext, key)
	if err != nil {
		return fmt.Errorf("encryption error: %w", err)
	}

	raw := formatVaultFile(salt, nonce, ciphertext)
	return os.WriteFile(path, raw, 0600)
}

// ---------------------------------------------------------------------------
// Internal crypto helpers
// ---------------------------------------------------------------------------

// deriveKey derives a 256-bit key from password and salt using Argon2id.
func deriveKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, argonKeyLen)
}

// encrypt returns a fresh nonce and the AES-256-GCM ciphertext for plaintext.
func encrypt(plaintext, key []byte) (nonce, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertext, nil
}

// decrypt verifies and decrypts ciphertext using AES-256-GCM.
func decrypt(ciphertext, nonce, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// ---------------------------------------------------------------------------
// Vault file serialisation
// ---------------------------------------------------------------------------

// formatVaultFile serialises the encrypted fields into the on-disk format:
//
//	$VAULT;1
//	kdf: argon2id
//	salt: <base64>
//	nonce: <base64>
//	cipher: aes-256-gcm
//	data: <base64>
func formatVaultFile(salt, nonce, ciphertext []byte) []byte {
	enc := base64.StdEncoding
	var sb strings.Builder
	sb.WriteString(vaultHeader + "\n")
	sb.WriteString("kdf: argon2id\n")
	sb.WriteString("salt: " + enc.EncodeToString(salt) + "\n")
	sb.WriteString("nonce: " + enc.EncodeToString(nonce) + "\n")
	sb.WriteString("cipher: aes-256-gcm\n")
	sb.WriteString("data: " + enc.EncodeToString(ciphertext) + "\n")
	return []byte(sb.String())
}

// parseVaultFile decodes a vault file produced by formatVaultFile.
func parseVaultFile(raw []byte) (salt, nonce, ciphertext []byte, err error) {
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) < 6 {
		return nil, nil, nil, errors.New("invalid vault file format")
	}
	if lines[0] != vaultHeader {
		return nil, nil, nil, fmt.Errorf("unrecognised vault header: %q", lines[0])
	}

	fields := make(map[string]string)
	for _, line := range lines[1:] {
		parts := strings.SplitN(line, ": ", 2)
		if len(parts) == 2 {
			fields[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	enc := base64.StdEncoding
	decode := func(name string) ([]byte, error) {
		val, ok := fields[name]
		if !ok || val == "" {
			return nil, fmt.Errorf("missing field %q in vault file", name)
		}
		b, err := enc.DecodeString(val)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 for field %q: %w", name, err)
		}
		return b, nil
	}

	if salt, err = decode("salt"); err != nil {
		return
	}
	if nonce, err = decode("nonce"); err != nil {
		return
	}
	if ciphertext, err = decode("data"); err != nil {
		return
	}
	return
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

// wipe overwrites a byte slice with zeros to reduce plaintext exposure.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// sortStrings sorts a string slice in-place (avoids importing "sort" elsewhere).
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
