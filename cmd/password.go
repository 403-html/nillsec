package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// stdinReader is used for non-TTY password reading to avoid buffering issues
// when readPassword is called multiple times.
var stdinReader = bufio.NewReader(os.Stdin)

// readPassword reads a password from the terminal without echoing it.
// When stdin is not a TTY (e.g. piped input in scripts), it falls back to
// reading a plain line from stdin so the tool remains scriptable.
func readPassword(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)

	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		pw, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		return pw, err
	}

	// Non-TTY: read a single line from the shared reader.
	line, err := stdinReader.ReadString('\n')
	fmt.Fprintln(os.Stderr)
	if err != nil && line == "" {
		return nil, fmt.Errorf("no password provided")
	}
	return []byte(strings.TrimRight(line, "\r\n")), nil
}
