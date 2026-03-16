// vault.go provides AES-256-GCM encrypted secret storage backed by an
// Argon2id-derived key.
//
// On-disk format (text envelope):
//
//	$VAULT;1
//	kdf: argon2id
//	salt: <base64>
//	nonce: <base64>
//	cipher: aes-256-gcm
//	data: <base64 encrypted YAML>
//
// The YAML plaintext inside the encrypted blob:
//
//	version: 1
//	secrets:
//	  key: value
package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
	"gopkg.in/yaml.v3"
)

const (
	fileHeader = "$VAULT;1"

	// Argon2id parameters – balanced for interactive use.
	argonMemory      = 64 * 1024 // 64 MiB
	argonIterations  = 3
	argonParallelism = 4
	argonKeyLen      = 32 // 256-bit key for AES-256

	saltLen  = 16 // bytes
	nonceLen = 12 // bytes (GCM standard)
)

// Vault holds the in-memory representation of a decrypted vault.
type Vault struct {
	Version int               `yaml:"version"`
	Secrets map[string]string `yaml:"secrets"`
}

// newVault returns an empty vault ready for use.
func newVault() *Vault {
	return &Vault{
		Version: 1,
		Secrets: make(map[string]string),
	}
}

// openVault reads and decrypts a vault file.
func openVault(path string, password []byte) (*Vault, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open vault: %w", err)
	}
	defer f.Close()

	salt, nonce, ciphertext, err := parseEnvelope(f)
	if err != nil {
		return nil, fmt.Errorf("parse vault: %w", err)
	}

	key := deriveKey(password, salt)
	defer zeroBytes(key)

	plaintext, err := decryptData(key, nonce, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt vault: %w", err)
	}
	defer zeroBytes(plaintext)

	var v Vault
	if err := yaml.Unmarshal(plaintext, &v); err != nil {
		return nil, fmt.Errorf("parse vault contents: %w", err)
	}
	if v.Secrets == nil {
		v.Secrets = make(map[string]string)
	}
	return &v, nil
}

// Save encrypts and writes the vault to path.
func (v *Vault) Save(path string, password []byte) error {
	plaintext, err := yaml.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal vault: %w", err)
	}
	defer zeroBytes(plaintext)

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}

	key := deriveKey(password, salt)
	defer zeroBytes(key)

	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext, err := encryptData(key, nonce, plaintext)
	if err != nil {
		return fmt.Errorf("encrypt vault: %w", err)
	}

	return writeEnvelope(path, salt, nonce, ciphertext)
}

// deriveKey derives a 256-bit key from password and salt using Argon2id.
func deriveKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, argonIterations, argonMemory, argonParallelism, argonKeyLen)
}

// encryptData encrypts plaintext with AES-256-GCM using the provided key and nonce.
func encryptData(key, nonce, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, nil), nil
}

// decryptData decrypts ciphertext with AES-256-GCM using the provided key and nonce.
func decryptData(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("wrong password or corrupted vault")
	}
	return plaintext, nil
}

// writeEnvelope serialises and atomically writes the vault envelope.
func writeEnvelope(path string, salt, nonce, ciphertext []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	_, writeErr := fmt.Fprintf(f, "%s\nkdf: argon2id\nsalt: %s\nnonce: %s\ncipher: aes-256-gcm\ndata: %s\n",
		fileHeader,
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(nonce),
		base64.StdEncoding.EncodeToString(ciphertext),
	)
	closeErr := f.Close()

	if writeErr != nil {
		os.Remove(tmp)
		return writeErr
	}
	if closeErr != nil {
		os.Remove(tmp)
		return closeErr
	}

	return os.Rename(tmp, path)
}

// parseEnvelope reads and validates the vault file header and returns its components.
func parseEnvelope(r io.Reader) (salt, nonce, ciphertext []byte, err error) {
	scanner := bufio.NewScanner(r)

	// First line must be the header.
	if !scanner.Scan() {
		return nil, nil, nil, errors.New("empty file")
	}
	if scanner.Text() != fileHeader {
		return nil, nil, nil, errors.New("not a vault file")
	}

	fields := map[string]string{}
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ": ", 2)
		if len(parts) == 2 {
			fields[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, nil, err
	}

	decode := func(field string) ([]byte, error) {
		v, ok := fields[field]
		if !ok {
			return nil, fmt.Errorf("missing field: %s", field)
		}
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 for %s: %w", field, err)
		}
		return b, nil
	}

	salt, err = decode("salt")
	if err != nil {
		return
	}
	nonce, err = decode("nonce")
	if err != nil {
		return
	}
	ciphertext, err = decode("data")
	return
}

// zeroBytes overwrites a byte slice with zeros to reduce the window in which
// sensitive material is present in memory.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
