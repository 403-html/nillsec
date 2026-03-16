// nillsec – encrypted project-secret vault.
//
// Usage:
//
//	nillsec init                          create a new vault
//	nillsec add  <key> <value>            add a secret (fails if key exists)
//	nillsec set  <key> <value>            add or overwrite a secret
//	nillsec get  <key>                    print a secret value
//	nillsec list                          list secret keys
//	nillsec remove <key>                  delete a secret
//	nillsec edit                          open vault in $EDITOR
//	nillsec env                           export secrets as shell variables
//
// The vault file is secrets.vault in the current directory unless
// NILLSEC_VAULT is set.
package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/403-html/nillsec/vault"
	"golang.org/x/term"
)

// version is set at build time via -ldflags "-X main.version=<tag>".
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}

	cmd, rest := args[0], args[1:]

	switch cmd {
	case "init":
		return cmdInit(rest)
	case "add":
		return cmdAdd(rest, false)
	case "set":
		return cmdAdd(rest, true)
	case "get":
		return cmdGet(rest)
	case "list":
		return cmdList(rest)
	case "remove", "rm":
		return cmdRemove(rest)
	case "edit":
		return cmdEdit(rest)
	case "env":
		return cmdEnv(rest)
	case "version", "--version", "-v":
		fmt.Println("nillsec", version)
		return nil
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		printUsage()
		return fmt.Errorf("unknown command: %q", cmd)
	}
}

// ---------------------------------------------------------------------------
// Command implementations
// ---------------------------------------------------------------------------

func cmdInit(args []string) error {
	path := vaultPath(args)
	pw, err := promptPasswordConfirm()
	if err != nil {
		return err
	}
	defer wipeString(&pw)

	if err := vault.Init(path, pw); err != nil {
		return err
	}
	fmt.Println("Vault created:", path)
	return nil
}

// cmdAdd handles both "add" (overwrite=false) and "set" (overwrite=true).
func cmdAdd(args []string, overwrite bool) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: nillsec %s <key> <value>", map[bool]string{true: "set", false: "add"}[overwrite])
	}
	key, value := args[0], args[1]

	path := vaultPath(nil)
	pw, err := promptPassword("Master password: ")
	if err != nil {
		return err
	}
	defer wipeString(&pw)

	v, err := vault.Load(path, pw)
	if err != nil {
		return err
	}

	if !overwrite {
		if _, exists := v.Get(key); exists {
			return fmt.Errorf("key %q already exists; use 'set' to overwrite", key)
		}
	}

	v.Set(key, value)
	return vault.Save(path, pw, v)
}

func cmdGet(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: nillsec get <key>")
	}
	key := args[0]

	path := vaultPath(nil)
	pw, err := promptPassword("Master password: ")
	if err != nil {
		return err
	}
	defer wipeString(&pw)

	v, err := vault.Load(path, pw)
	if err != nil {
		return err
	}

	val, ok := v.Get(key)
	if !ok {
		return fmt.Errorf("key not found: %q", key)
	}
	fmt.Println(val)
	return nil
}

func cmdList(_ []string) error {
	path := vaultPath(nil)
	pw, err := promptPassword("Master password: ")
	if err != nil {
		return err
	}
	defer wipeString(&pw)

	v, err := vault.Load(path, pw)
	if err != nil {
		return err
	}

	for _, k := range v.Keys() {
		fmt.Println(k)
	}
	return nil
}

func cmdRemove(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: nillsec remove <key>")
	}
	key := args[0]

	path := vaultPath(nil)
	pw, err := promptPassword("Master password: ")
	if err != nil {
		return err
	}
	defer wipeString(&pw)

	v, err := vault.Load(path, pw)
	if err != nil {
		return err
	}

	if !v.Delete(key) {
		return fmt.Errorf("key not found: %q", key)
	}
	return vault.Save(path, pw, v)
}

func cmdEdit(_ []string) error {
	path := vaultPath(nil)
	pw, err := promptPassword("Master password: ")
	if err != nil {
		return err
	}
	defer wipeString(&pw)

	v, err := vault.Load(path, pw)
	if err != nil {
		return err
	}

	text, err := v.MarshalText()
	if err != nil {
		return err
	}

	// Write decrypted content to a temp file.
	tmp, err := os.CreateTemp("", "nillsec-edit-*.json")
	if err != nil {
		return fmt.Errorf("cannot create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // always clean up

	if _, err := tmp.Write(text); err != nil {
		tmp.Close()
		return fmt.Errorf("cannot write temp file: %w", err)
	}
	tmp.Close()

	// Open in editor.
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}
	editorCmd := exec.Command(editor, tmpPath) //nolint:gosec // editor path from env
	editorCmd.Stdin = os.Stdin
	editorCmd.Stdout = os.Stdout
	editorCmd.Stderr = os.Stderr
	if err := editorCmd.Run(); err != nil {
		return fmt.Errorf("editor exited with error: %w", err)
	}

	// Read and re-encrypt.
	edited, err := os.ReadFile(tmpPath)
	if err != nil {
		return fmt.Errorf("cannot read edited file: %w", err)
	}
	defer wipeBytes(edited)

	if err := v.UnmarshalText(edited); err != nil {
		return err
	}

	// Remove temp file before writing vault (no plaintext on disk after this).
	os.Remove(tmpPath)

	return vault.Save(path, pw, v)
}

func cmdEnv(_ []string) error {
	path := vaultPath(nil)
	pw, err := promptPassword("Master password: ")
	if err != nil {
		return err
	}
	defer wipeString(&pw)

	v, err := vault.Load(path, pw)
	if err != nil {
		return err
	}

	for _, k := range v.Keys() {
		val, _ := v.Get(k)
		envKey := strings.ToUpper(k)
		// Single-quote the value and escape any embedded single quotes.
		safeVal := strings.ReplaceAll(val, "'", "'\\''")
		fmt.Printf("export %s='%s'\n", envKey, safeVal)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// vaultPath returns the vault file path from args, NILLSEC_VAULT env var,
// or the default "secrets.vault".
func vaultPath(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	if p := os.Getenv("NILLSEC_VAULT"); p != "" {
		return p
	}
	return "secrets.vault"
}

// stdinReader is a shared buffered reader for non-TTY password input.
// Using a package-level reader prevents data loss when promptPassword is
// called multiple times.
var stdinReader *bufio.Reader

func init() {
	stdinReader = bufio.NewReader(os.Stdin)
}

// promptPassword reads a password.
// Priority: NILLSEC_PASSWORD env var → TTY (no echo) → stdin line.
func promptPassword(prompt string) (string, error) {
	// Allow override via environment variable (useful in CI / scripts).
	if pw := os.Getenv("NILLSEC_PASSWORD"); pw != "" {
		return pw, nil
	}

	// If stdin is a real terminal, read without echo.
	if term.IsTerminal(int(syscall.Stdin)) {
		fmt.Fprint(os.Stderr, prompt)
		pw, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("cannot read password: %w", err)
		}
		if len(pw) == 0 {
			return "", fmt.Errorf("password must not be empty")
		}
		return string(pw), nil
	}

	// Non-TTY (piped) – read a line from the shared stdin reader.
	line, err := stdinReader.ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("cannot read password from stdin: %w", err)
	}
	pw := strings.TrimRight(line, "\r\n")
	if pw == "" {
		return "", fmt.Errorf("password must not be empty")
	}
	return pw, nil
}

// promptPasswordConfirm reads a password twice and ensures they match.
// When stdin is not a TTY the two passwords are expected on separate lines.
func promptPasswordConfirm() (string, error) {
	pw1, err := promptPassword("Master password: ")
	if err != nil {
		return "", err
	}
	pw2, err := promptPassword("Confirm password: ")
	if err != nil {
		wipeString(&pw1)
		return "", err
	}
	defer wipeString(&pw2)
	if pw1 != pw2 {
		wipeString(&pw1)
		return "", fmt.Errorf("passwords do not match")
	}
	return pw1, nil
}

// wipeString overwrites s in place.
func wipeString(s *string) {
	b := []byte(*s)
	for i := range b {
		b[i] = 0
	}
	*s = ""
}

// wipeBytes overwrites a byte slice.
func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, `nillsec – encrypted project-secret vault

Usage:
  nillsec init                  create a new vault (secrets.vault)
  nillsec add  <key> <value>    add a secret (error if key already exists)
  nillsec set  <key> <value>    add or overwrite a secret
  nillsec get  <key>            print a secret value
  nillsec list                  list secret keys (no values)
  nillsec remove <key>          delete a secret
  nillsec edit                  open vault contents in $EDITOR
  nillsec env                   print secrets as export statements
  nillsec version               print version

Environment:
  NILLSEC_VAULT    vault file path (default: secrets.vault)
  NILLSEC_PASSWORD master password (optional; if set, prompts may be skipped)
  EDITOR           editor used by 'edit' command (default: vi)
`)
}
