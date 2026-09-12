// Package vault implements encrypted secret storage using Argon2id + AES-256-GCM.
package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	vaultHeader = "$VAULT;1"

	// Argon2id KDF parameters, tuned for interactive use.
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 4
	argonKeyLen  = 32 // 256-bit key

	saltSize  = 16 // 128-bit salt
	nonceSize = 12 // 96-bit GCM nonce (standard)

	// Vaults are intended for environment-sized secrets, not arbitrary files.
	// Bounding input prevents a malicious or mistaken path from exhausting memory.
	maxVaultFileBytes = 16 << 20
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
	sort.Strings(keys)
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
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return fmt.Errorf("invalid vault content: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("invalid vault content: trailing data")
	}
	if err := validatePayload(p); err != nil {
		return fmt.Errorf("invalid vault content: %w", err)
	}
	v.data = p
	return nil
}

// Init creates a new, empty, encrypted vault file at path.
// It returns an error if the file already exists.
func Init(path string, password []byte) error {
	v := &Vault{data: payload{Version: 1, Secrets: make(map[string]string)}}
	raw, err := encryptVault(password, v)
	if err != nil {
		return err
	}
	return writeNewVault(path, raw)
}

// Load reads and decrypts the vault at path using password.
func Load(path string, password []byte) (*Vault, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot inspect vault: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("cannot read vault: %s is not a regular file", path)
	}
	if info.Size() > maxVaultFileBytes {
		return nil, fmt.Errorf("cannot read vault: file is larger than %d bytes", maxVaultFileBytes)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read vault: %w", err)
	}
	if len(raw) > maxVaultFileBytes {
		return nil, fmt.Errorf("cannot read vault: file is larger than %d bytes", maxVaultFileBytes)
	}

	salt, nonce, ciphertext, err := parseVaultFile(raw)
	if err != nil {
		return nil, err
	}

	key := deriveKey(password, salt)
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
	if err := validatePayload(p); err != nil {
		return nil, fmt.Errorf("corrupt vault payload: %w", err)
	}

	return &Vault{data: p}, nil
}

// Save encrypts the vault and writes it to path.
// A fresh random salt and nonce are generated on every call.
func Save(path string, password []byte, v *Vault) error {
	raw, err := encryptVault(password, v)
	if err != nil {
		return err
	}

	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return writeNewVault(path, raw)
	}
	if err != nil {
		return fmt.Errorf("cannot inspect vault: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("refusing to replace non-regular vault file: %s", path)
	}

	return replaceVault(path, raw)
}

// encryptVault serialises and encrypts a vault without touching the filesystem.
func encryptVault(password []byte, v *Vault) ([]byte, error) {
	if err := validatePayload(v.data); err != nil {
		return nil, fmt.Errorf("invalid vault payload: %w", err)
	}
	plaintext, err := json.Marshal(v.data)
	if err != nil {
		return nil, fmt.Errorf("marshal error: %w", err)
	}
	defer wipe(plaintext)

	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("cannot generate salt: %w", err)
	}

	key := deriveKey(password, salt)
	defer wipe(key)

	nonce, ciphertext, err := encrypt(plaintext, key)
	if err != nil {
		return nil, fmt.Errorf("encryption error: %w", err)
	}

	return formatVaultFile(salt, nonce, ciphertext), nil
}

func validatePayload(p payload) error {
	if p.Version != 1 {
		return fmt.Errorf("unsupported payload version %d", p.Version)
	}
	if p.Secrets == nil {
		return errors.New("missing secrets object")
	}
	return nil
}

// writeNewVault creates path exclusively. This prevents init from overwriting
// an existing file or following a dangling symlink between a check and write.
func writeNewVault(path string, raw []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("vault already exists: %s", path)
		}
		return fmt.Errorf("cannot create vault: %w", err)
	}

	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if err := writeAndSync(f, raw); err != nil {
		return fmt.Errorf("cannot write vault: %w", err)
	}
	ok = true
	return nil
}

// replaceVault writes the complete ciphertext to a private file in the same
// directory, then atomically renames it over the old vault.
func replaceVault(path string, raw []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".nillsec-vault-*")
	if err != nil {
		return fmt.Errorf("cannot create temporary vault: %w", err)
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()

	if err := writeAndSync(tmp, raw); err != nil {
		return fmt.Errorf("cannot write temporary vault: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("cannot replace vault: %w", err)
	}
	ok = true
	syncDirectory(dir)
	return nil
}

func writeAndSync(f *os.File, data []byte) error {
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("setting private permissions: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return f.Close()
}

// syncDirectory is best-effort: some platforms (notably Windows) cannot sync
// directory handles, while the file itself has already been flushed safely.
func syncDirectory(path string) {
	dir, err := os.Open(path)
	if err != nil {
		return
	}
	defer dir.Close()
	_ = dir.Sync()
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
	lines := strings.Split(strings.TrimRight(string(raw), "\r\n"), "\n")
	if len(lines) < 6 {
		return nil, nil, nil, errors.New("invalid vault file format")
	}
	if strings.TrimRight(lines[0], "\r") != vaultHeader {
		return nil, nil, nil, fmt.Errorf("unrecognised vault header: %q", lines[0])
	}

	fields := make(map[string]string)
	for _, line := range lines[1:] {
		parts := strings.SplitN(strings.TrimRight(line, "\r"), ": ", 2)
		if len(parts) == 2 {
			fields[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	if fields["kdf"] != "argon2id" {
		return nil, nil, nil, fmt.Errorf("unsupported kdf %q", fields["kdf"])
	}
	if fields["cipher"] != "aes-256-gcm" {
		return nil, nil, nil, fmt.Errorf("unsupported cipher %q", fields["cipher"])
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
	if len(salt) != saltSize {
		err = fmt.Errorf("invalid salt length %d, expected %d", len(salt), saltSize)
		return
	}
	if nonce, err = decode("nonce"); err != nil {
		return
	}
	if len(nonce) != nonceSize {
		err = fmt.Errorf("invalid nonce length %d, expected %d", len(nonce), nonceSize)
		return
	}
	if ciphertext, err = decode("data"); err != nil {
		return
	}
	if len(ciphertext) < 16 {
		err = errors.New("ciphertext is too short")
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
