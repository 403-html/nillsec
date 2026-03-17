package main

import (
	"fmt"
	"os"
)

// editorFile manages the temporary file used to pass vault plaintext to an
// external editor. The platform-specific constructor (newEditorFile) is in
// editfile_linux.go / editfile_other.go.
type editorFile struct {
	fpath  string
	closed bool
}

// path returns the filesystem path to pass to the editor.
func (e *editorFile) path() string { return e.fpath }

// discard wipes and removes the editor file (best-effort, idempotent).
func (e *editorFile) discard() {
	if e.closed {
		return
	}
	e.closed = true
	wipeFile(e.fpath)
	_ = os.Remove(e.fpath)
}

// readAndClose reads the file contents, then wipes and removes the backing
// file. Returns an error if the file cannot be removed so that callers can
// abort rather than leave plaintext behind.
func (e *editorFile) readAndClose() ([]byte, error) {
	data, readErr := os.ReadFile(e.fpath)
	wipeFile(e.fpath)
	removeErr := os.Remove(e.fpath)
	e.closed = true
	if readErr != nil {
		return nil, fmt.Errorf("cannot read editor file: %w", readErr)
	}
	if removeErr != nil {
		return nil, fmt.Errorf("cannot remove editor file (plaintext may remain on disk): %w", removeErr)
	}
	return data, nil
}

// wipeFile overwrites the file with zeros (best-effort secure erasure).
func wipeFile(path string) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	size := info.Size()
	if size == 0 {
		return
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	const chunkSize = 4096
	zeros := make([]byte, chunkSize)
	var written int64
	for written < size {
		n := int64(chunkSize)
		if size-written < n {
			n = size - written
		}
		if _, err := f.Write(zeros[:n]); err != nil {
			break
		}
		written += n
	}
	_ = f.Sync()
}
