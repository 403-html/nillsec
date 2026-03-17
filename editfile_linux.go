//go:build linux

package main

import (
	"fmt"
	"os"
)

// newEditorFile creates a file for editing with the given initial content.
//
// On Linux it is placed in /dev/shm, which is a tmpfs mount backed entirely
// by RAM.  Writes to /dev/shm never reach a physical disk, satisfying the
// memory-only guarantee.  If /dev/shm is unavailable or unwritable the
// function silently falls back to the OS temp directory.
func newEditorFile(content []byte) (*editorFile, error) {
	// /dev/shm is a tmpfs mount on Linux: data lives only in RAM, never on disk.
	dir := "/dev/shm"
	if _, err := os.Stat(dir); err != nil {
		dir = "" // /dev/shm unavailable; fall back to the default temp dir
	}

	tmp, err := os.CreateTemp(dir, "nillsec-edit-*.json")
	if err != nil && dir != "" {
		// /dev/shm exists but is not writable (e.g. noexec mount, permissions);
		// fall back silently to the default temp directory.
		tmp, err = os.CreateTemp("", "nillsec-edit-*.json")
	}
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
