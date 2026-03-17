//go:build !linux

package main

import (
	"fmt"
	"os"
)

// newEditorFile creates a private temp file with the given initial content.
//
// The file is created in the OS temp directory with mode 0600 (owner-readable
// only).  Its contents are zero-wiped and the file is deleted by
// readAndClose/discard.
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
