//go:build linux

package main

import (
	"fmt"
	"os"
)

// newEditorFile creates the editor temp file in /dev/shm (RAM-only on Linux).
// Falls back to os.TempDir() if /dev/shm is unavailable or unwritable.
func newEditorFile(content []byte) (*editorFile, error) {
	dir := "/dev/shm"
	if _, err := os.Stat(dir); err != nil {
		dir = ""
	}

	tmp, err := os.CreateTemp(dir, "nillsec-edit-*.json")
	if err != nil && dir != "" {
		tmp, err = os.CreateTemp("", "nillsec-edit-*.json")
	}
	if err != nil {
		return nil, fmt.Errorf("cannot create editor file: %w", err)
	}

	path := tmp.Name()
	if _, err := tmp.Write(content); err != nil {
		wipeOpenFile(tmp)
		tmp.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("cannot write editor file: %w", err)
	}
	identity, err := tmp.Stat()
	if err != nil {
		wipeOpenFile(tmp)
		tmp.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("cannot inspect editor file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		wipeFileIfSame(path, identity)
		_ = os.Remove(path)
		return nil, fmt.Errorf("cannot close editor file: %w", err)
	}
	return &editorFile{fpath: path, original: identity}, nil
}
