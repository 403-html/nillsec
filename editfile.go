package main

import (
	"fmt"
	"os"
)

// editorFile manages the backing storage used to pass vault plaintext to an
// external editor.
//
// On Linux the file is created in /dev/shm (a tmpfs mount), so the plaintext
// lives only in RAM and is never flushed to physical disk. On other platforms
// it falls back to the OS temp directory; the content is zero-wiped before the
// file is removed.
//
// The platform-specific newEditorFile constructor is provided in
// editfile_linux.go and editfile_other.go via build tags.
type editorFile struct {
	fpath  string
	closed bool
}

// path returns the filesystem path to pass to the editor.
func (e *editorFile) path() string { return e.fpath }

// discard wipes and removes the editor file.
// It is idempotent; subsequent calls are no-ops.
func (e *editorFile) discard() {
	if e.closed {
		return
	}
	e.closed = true
	wipeFile(e.fpath)
	_ = os.Remove(e.fpath)
}

// readAndClose reads the current file contents, then wipes and removes the
// backing file. It must be called at most once.
func (e *editorFile) readAndClose() ([]byte, error) {
	data, err := os.ReadFile(e.fpath)
	e.discard() // wipe + remove regardless of read outcome
	if err != nil {
		return nil, fmt.Errorf("cannot read editor file: %w", err)
	}
	return data, nil
}

// wipeFile overwrites a file with zero bytes for best-effort secure erasure.
// This is a best-effort measure; it does not guarantee against forensic
// recovery on systems with journaling file systems or SSDs with wear levelling.
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
