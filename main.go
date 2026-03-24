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
//	nillsec exec [--] <cmd> [args...]     run a command with secrets injected
//	nillsec file-add  <name> <path>       encrypt a file into the vault
//	nillsec file-set  <name> <path>       encrypt/overwrite a file in the vault
//	nillsec file-get  <name> [<path>]     decrypt a file from the vault to <path> (default: <name>)
//	nillsec file-list                     list stored file names
//	nillsec file-remove <name>            remove a stored file from the vault
//	nillsec upgrade                       upgrade nillsec to the latest release
//
// The vault file is secrets.vault in the current directory unless
// NILLSEC_VAULT is set.
package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"

	"github.com/403-html/nillsec/vault"
	"golang.org/x/term"
)

// version is set at build time via -ldflags "-X main.version=<tag>".
var version = "dev"

// osExitFn exits the process with the given code; overridable in tests.
var osExitFn = os.Exit

// validKeyRe matches valid POSIX shell identifier names (used as env var names).
var validKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

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
	case "exec":
		return cmdExec(rest)
	case "file-add":
		return cmdFileAdd(rest, false)
	case "file-set":
		return cmdFileAdd(rest, true)
	case "file-get":
		return cmdFileGet(rest)
	case "file-list":
		return cmdFileList(rest)
	case "file-remove", "file-rm":
		return cmdFileRemove(rest)
	case "upgrade":
		return cmdUpgrade()
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
	defer wipeBytes(pw)

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

	if !validKeyRe.MatchString(key) {
		return fmt.Errorf("invalid key %q: must be a valid POSIX identifier ([A-Za-z_][A-Za-z0-9_]*)", key)
	}

	path := vaultPath(nil)
	pw, err := promptPassword("Master password: ")
	if err != nil {
		return err
	}
	defer wipeBytes(pw)

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
	defer wipeBytes(pw)

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
	defer wipeBytes(pw)

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
	defer wipeBytes(pw)

	v, err := vault.Load(path, pw)
	if err != nil {
		return err
	}

	if !v.Delete(key) {
		return fmt.Errorf("key not found: %q", key)
	}
	return vault.Save(path, pw, v)
}

func cmdFileAdd(args []string, overwrite bool) error {
	cmdName := map[bool]string{true: "file-set", false: "file-add"}[overwrite]
	if len(args) < 2 {
		return fmt.Errorf("usage: nillsec %s <name> <path>", cmdName)
	}
	name, filePath := args[0], args[1]

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("cannot read file %q: %w", filePath, err)
	}
	defer wipeBytes(data)

	path := vaultPath(nil)
	pw, err := promptPassword("Master password: ")
	if err != nil {
		return err
	}
	defer wipeBytes(pw)

	v, err := vault.Load(path, pw)
	if err != nil {
		return err
	}

	if !overwrite {
		if _, exists := v.GetFile(name); exists {
			return fmt.Errorf("file %q already exists in vault; use 'file-set' to overwrite", name)
		}
	}

	v.SetFile(name, data)
	return vault.Save(path, pw, v)
}

func cmdFileGet(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: nillsec file-get <name> [<path>|-]")
	}
	name := args[0]
	// Default output path is the stored name itself (written to the current
	// directory).  Pass "-" explicitly to write to stdout instead.
	outPath := name
	if len(args) >= 2 {
		outPath = args[1]
	}

	path := vaultPath(nil)
	pw, err := promptPassword("Master password: ")
	if err != nil {
		return err
	}
	defer wipeBytes(pw)

	v, err := vault.Load(path, pw)
	if err != nil {
		return err
	}

	data, ok := v.GetFile(name)
	if !ok {
		return fmt.Errorf("file not found in vault: %q", name)
	}
	defer wipeBytes(data)

	if outPath == "-" {
		_, err = os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(outPath, data, 0600)
}

func cmdFileList(_ []string) error {
	path := vaultPath(nil)
	pw, err := promptPassword("Master password: ")
	if err != nil {
		return err
	}
	defer wipeBytes(pw)

	v, err := vault.Load(path, pw)
	if err != nil {
		return err
	}

	for _, n := range v.FileNames() {
		fmt.Println(n)
	}
	return nil
}

func cmdFileRemove(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: nillsec file-remove <name>")
	}
	name := args[0]

	path := vaultPath(nil)
	pw, err := promptPassword("Master password: ")
	if err != nil {
		return err
	}
	defer wipeBytes(pw)

	v, err := vault.Load(path, pw)
	if err != nil {
		return err
	}

	if !v.DeleteFile(name) {
		return fmt.Errorf("file not found in vault: %q", name)
	}
	return vault.Save(path, pw, v)
}

func cmdEdit(_ []string) error {
	path := vaultPath(nil)
	pw, err := promptPassword("Master password: ")
	if err != nil {
		return err
	}
	defer wipeBytes(pw)

	v, err := vault.Load(path, pw)
	if err != nil {
		return err
	}

	text, err := v.MarshalText()
	if err != nil {
		return err
	}
	defer wipeBytes(text)

	ef, err := newEditorFile(text)
	if err != nil {
		return err
	}
	defer ef.discard()

	// Open in editor.
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}
	editorCmd := exec.Command(editor, ef.path()) //nolint:gosec
	editorCmd.Stdin = os.Stdin
	editorCmd.Stdout = os.Stdout
	editorCmd.Stderr = os.Stderr
	if err := editorCmd.Run(); err != nil {
		return fmt.Errorf("editor exited with error: %w", err)
	}

	edited, err := ef.readAndClose()
	if err != nil {
		return err
	}
	defer wipeBytes(edited)

	if err := v.UnmarshalText(edited); err != nil {
		return err
	}

	return vault.Save(path, pw, v)
}

func cmdEnv(_ []string) error {
	path := vaultPath(nil)
	pw, err := promptPassword("Master password: ")
	if err != nil {
		return err
	}
	defer wipeBytes(pw)

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

func cmdExec(args []string) error {
	// Strip a leading "--" separator so that both
	//   nillsec exec -- npm run dev
	//   nillsec exec npm run dev
	// work correctly.  Only the very first argument is checked; any subsequent
	// "--" is left in place and passed through to the child command as-is.
	cmdArgs := args
	if len(args) > 0 && args[0] == "--" {
		cmdArgs = args[1:]
	}
	if len(cmdArgs) == 0 {
		return fmt.Errorf("usage: nillsec exec [--] <command> [args...]")
	}

	path := vaultPath(nil)
	pw, err := promptPassword("Master password: ")
	if err != nil {
		return err
	}
	defer wipeBytes(pw)

	v, err := vault.Load(path, pw)
	if err != nil {
		return err
	}

	// Build the child's environment: inherit the current environment, then
	// overlay vault secrets so they take precedence over any existing values.
	// On Windows, env-var keys are case-insensitive, so we normalize them to
	// upper-case to ensure vault values reliably override inherited ones.
	env := buildChildEnv(os.Environ(), v, runtime.GOOS == "windows")

	// Resolve the executable against the child's PATH so that a vault-provided
	// PATH override takes effect at lookup time rather than the current process PATH.
	resolvedCmd, err := lookPathInEnv(cmdArgs[0], env)
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}

	cmd := exec.Command(resolvedCmd, cmdArgs[1:]...) //nolint:gosec
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			osExitFn(exitErr.ExitCode())
			return nil
		}
		return fmt.Errorf("exec: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// buildChildEnv merges an inherited environment slice with vault secrets.
// Vault values are always upper-cased and take precedence over any inherited
// entry with the same name. When normalizeKeys is true (Windows), inherited
// keys are upper-cased before the merge so that mixed-case names such as
// "Path" do not survive alongside the upper-cased vault key "PATH".
func buildChildEnv(inherited []string, v *vault.Vault, normalizeKeys bool) []string {
	envMap := make(map[string]string, len(inherited))
	for _, e := range inherited {
		k, val, _ := strings.Cut(e, "=")
		if normalizeKeys {
			k = strings.ToUpper(k)
		}
		envMap[k] = val
	}
	for _, k := range v.Keys() {
		val, _ := v.Get(k)
		envMap[strings.ToUpper(k)] = val
	}
	env := make([]string, 0, len(envMap))
	for k, val := range envMap {
		env = append(env, k+"="+val)
	}
	return env
}

// lookPathInEnv resolves an executable name against the PATH entry found in
// childEnv, so that a vault-provided PATH override is honoured at lookup time
// rather than the current process PATH. If name contains a path separator it
// is returned unchanged. Falls back to exec.LookPath when childEnv has no PATH.
func lookPathInEnv(name string, childEnv []string) (string, error) {
	// Explicit or relative path – no directory search needed.
	if strings.ContainsRune(name, os.PathSeparator) || (runtime.GOOS == "windows" && strings.ContainsRune(name, '/')) {
		return name, nil
	}

	// Extract PATH from the child environment.
	for _, e := range childEnv {
		k, v, ok := strings.Cut(e, "=")
		if !ok {
			continue
		}
		keyMatches := k == "PATH"
		if runtime.GOOS == "windows" {
			keyMatches = strings.EqualFold(k, "PATH")
		}
		if !keyMatches {
			continue
		}
		// Search each directory in the child PATH for an executable.
		for _, dir := range filepath.SplitList(v) {
			if dir == "" {
				dir = "."
			}
			candidate := filepath.Join(dir, name)
			fi, err := os.Stat(candidate)
			if err != nil || fi.IsDir() {
				continue
			}
			if runtime.GOOS != "windows" && fi.Mode()&0111 == 0 {
				continue // not executable on Unix
			}
			return candidate, nil
		}
		return "", &exec.Error{Name: name, Err: exec.ErrNotFound}
	}
	// No PATH in child env; fall back to current process PATH.
	return exec.LookPath(name)
}

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
func promptPassword(prompt string) ([]byte, error) {
	// Allow override via environment variable (useful in CI / scripts).
	if pw := os.Getenv("NILLSEC_PASSWORD"); pw != "" {
		return []byte(pw), nil
	}

	// If stdin is a real terminal, read without echo.
	if term.IsTerminal(int(syscall.Stdin)) {
		fmt.Fprint(os.Stderr, prompt)
		pw, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, fmt.Errorf("cannot read password: %w", err)
		}
		if len(pw) == 0 {
			return nil, fmt.Errorf("password must not be empty")
		}
		return pw, nil
	}

	// Non-TTY (piped) – read a line from the shared stdin reader.
	line, err := stdinReader.ReadString('\n')
	if err != nil && line == "" {
		return nil, fmt.Errorf("cannot read password from stdin: %w", err)
	}
	pw := strings.TrimRight(line, "\r\n")
	if pw == "" {
		return nil, fmt.Errorf("password must not be empty")
	}
	return []byte(pw), nil
}

// promptPasswordConfirm reads a password twice and ensures they match.
// When stdin is not a TTY the two passwords are expected on separate lines.
func promptPasswordConfirm() ([]byte, error) {
	pw1, err := promptPassword("Master password: ")
	if err != nil {
		return nil, err
	}
	pw2, err := promptPassword("Confirm password: ")
	if err != nil {
		wipeBytes(pw1)
		return nil, err
	}
	defer wipeBytes(pw2)
	if !bytes.Equal(pw1, pw2) {
		wipeBytes(pw1)
		return nil, fmt.Errorf("passwords do not match")
	}
	return pw1, nil
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
  nillsec exec [--] <cmd> ...   run a command with secrets injected as env vars

  nillsec file-add  <name> <path>   encrypt a file into the vault (error if name exists)
  nillsec file-set  <name> <path>   encrypt a file into the vault (overwrite if exists)
  nillsec file-get  <name> [<path>] decrypt a file from the vault to <path> (default: <name>); use - for stdout
  nillsec file-list                 list stored file names
  nillsec file-remove <name>        remove a stored file from the vault

  nillsec upgrade               upgrade nillsec to the latest release
  nillsec version               print version

Environment:
  NILLSEC_VAULT    vault file path (default: secrets.vault)
  NILLSEC_PASSWORD master password (optional; if set, prompts may be skipped)
  EDITOR           editor used by 'edit' command (default: vi)
`)
}
