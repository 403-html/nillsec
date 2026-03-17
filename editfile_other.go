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
		tmp.Close()
		os.Remove(path)
		return nil, fmt.Errorf("cannot write editor file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(path)
		return nil, fmt.Errorf("cannot close editor file: %w", err)
	}
	return &editorFile{fpath: path}, nil
}
