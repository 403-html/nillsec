package main

import (
	"fmt"
	"io"
	"os"
)

const maxEditorFileBytes = 16 << 20

// editorFile manages the temporary file used to pass vault plaintext to an
// external editor. The platform-specific constructor (newEditorFile) is in
// editfile_linux.go / editfile_other.go.
type editorFile struct {
	fpath    string
	original os.FileInfo
	closed   bool
}

// path returns the filesystem path to pass to the editor.
func (e *editorFile) path() string { return e.fpath }

// discard wipes and removes the editor file (best-effort, idempotent).
func (e *editorFile) discard() {
	_ = e.discardChecked()
}

func (e *editorFile) discardChecked() error {
	if e.closed {
		return nil
	}
	e.closed = true
	wipeFileIfSame(e.fpath, e.original)
	if err := os.Remove(e.fpath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cannot remove editor file (plaintext may remain on disk): %w", err)
	}
	return nil
}

// readAndClose reads the file contents, then wipes and removes the backing
// file. Returns an error if the file cannot be removed so that callers can
// abort rather than leave plaintext behind.
func (e *editorFile) readAndClose() ([]byte, error) {
	f, openErr := openRegularEditorFile(e.fpath)
	var data []byte
	var readErr error
	if openErr == nil {
		data, readErr = io.ReadAll(io.LimitReader(f, maxEditorFileBytes+1))
		if readErr == nil && len(data) > maxEditorFileBytes {
			readErr = fmt.Errorf("editor file is larger than %d bytes", maxEditorFileBytes)
		}
		current, statErr := f.Stat()
		if statErr == nil && e.original != nil && os.SameFile(e.original, current) {
			wipeOpenFile(f)
		}
		_ = f.Close()
	} else {
		readErr = openErr
	}
	removeErr := os.Remove(e.fpath)
	e.closed = true
	if readErr != nil {
		wipeBytes(data)
		return nil, fmt.Errorf("cannot read editor file: %w", readErr)
	}
	if removeErr != nil {
		wipeBytes(data)
		return nil, fmt.Errorf("cannot remove editor file (plaintext may remain on disk): %w", removeErr)
	}
	return data, nil
}

// openRegularEditorFile refuses symlinks and verifies that the file did not
// change between inspection and open. The identity check happens before any
// reads or writes through the descriptor.
func openRegularEditorFile(path string) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("editor path is not a regular file: %s", path)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !os.SameFile(before, after) {
		_ = f.Close()
		return nil, fmt.Errorf("editor file changed while it was being opened: %s", path)
	}
	return f, nil
}

// wipeFile overwrites a verified regular file with zeros (best-effort secure
// erasure). It never follows a symlink.
func wipeFile(path string) {
	wipeFileIfSame(path, nil)
}

// wipeFileIfSame wipes only the original editor inode when expected is set.
// Editors may atomically replace files; skipping the wipe for a replacement
// avoids corrupting an unrelated file introduced through a hard link.
func wipeFileIfSame(path string, expected os.FileInfo) {
	f, err := openRegularEditorFile(path)
	if err != nil {
		return
	}
	defer f.Close()
	if expected != nil {
		current, err := f.Stat()
		if err != nil || !os.SameFile(expected, current) {
			return
		}
	}
	wipeOpenFile(f)
}

func wipeOpenFile(f *os.File) {
	info, err := f.Stat()
	if err != nil {
		return
	}
	size := info.Size()
	if size == 0 {
		return
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return
	}
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
