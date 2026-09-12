//go:build !linux

package main

import (
	"fmt"
	"os"
)

// newEditorFile creates a private temp file (mode 0600) with the given content.
func newEditorFile(content []byte) (*editorFile, error) {
	tmp, err := os.CreateTemp("", "nillsec-edit-*.json")
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
