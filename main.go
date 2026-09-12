// nillsec: encrypted project-secret vault.
//
// Usage:
//
//	nillsec init                          create a new vault
//	nillsec add  <key> [value]            add a secret (fails if key exists)
//	nillsec set  <key> [value]            add or overwrite a secret
//	nillsec get  <key>                    print a secret value
//	nillsec list                          list secret keys
//	nillsec remove <key>                  delete a secret
//	nillsec edit                          open vault in $EDITOR
//	nillsec env                           export secrets as shell variables
//	nillsec exec [--] <cmd> [args...]     run a command with secrets injected
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
	"unicode/utf8"

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
	case "upgrade":
		if len(rest) != 0 {
			return fmt.Errorf("usage: nillsec upgrade")
		}
		return cmdUpgrade()
	case "version", "--version", "-v":
		if len(rest) != 0 {
			return fmt.Errorf("usage: nillsec version")
		}
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
	if len(args) > 1 {
		return fmt.Errorf("usage: nillsec init [path]")
	}
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
	command := map[bool]string{true: "set", false: "add"}[overwrite]
	if len(args) < 1 || len(args) > 2 {
		return fmt.Errorf("usage: nillsec %s <key> [value]", command)
	}
	key := args[0]
	value := ""
	if len(args) == 2 {
		value = args[1]
		fmt.Fprintln(os.Stderr, "warning: a secret passed as an argument may be visible in shell history and process listings; omit [value] to enter it securely")
	}

	if !validKeyRe.MatchString(key) {
		return fmt.Errorf("invalid key %q: must be a valid POSIX identifier ([A-Za-z_][A-Za-z0-9_]*)", key)
	}
	if strings.EqualFold(key, "NILLSEC_PASSWORD") {
		return fmt.Errorf("key %q is reserved for nillsec authentication", key)
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

	if len(args) == 1 {
		value, err = promptSecret("Secret value: ")
		if err != nil {
			return err
		}
	}

	v.Set(key, value)
	if err := validateEnvironment(v); err != nil {
		return err
	}
	return vault.Save(path, pw, v)
}

func cmdGet(args []string) error {
	if len(args) != 1 {
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

func cmdList(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: nillsec list")
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

	for _, k := range v.Keys() {
		fmt.Println(k)
	}
	return nil
}

func cmdRemove(args []string) error {
	if len(args) != 1 {
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

func cmdEdit(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: nillsec edit")
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
	editor := os.Getenv("VISUAL")
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		if runtime.GOOS == "windows" {
			editor = "notepad.exe"
		} else {
			editor = "vi"
		}
	}
	editorArgs, err := parseEditorCommand(editor)
	if err != nil {
		return err
	}
	editorCmd := exec.Command(editorArgs[0], append(editorArgs[1:], ef.path())...) //nolint:gosec
	editorCmd.Env = stripSensitiveEnv(os.Environ(), runtime.GOOS == "windows")
	editorCmd.Stdin = os.Stdin
	editorCmd.Stdout = os.Stdout
	editorCmd.Stderr = os.Stderr
	if err := editorCmd.Run(); err != nil {
		if cleanupErr := ef.discardChecked(); cleanupErr != nil {
			return fmt.Errorf("editor exited with error: %w; cleanup also failed: %v", err, cleanupErr)
		}
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
	if err := validateEnvironment(v); err != nil {
		return err
	}

	return vault.Save(path, pw, v)
}

func cmdEnv(args []string) error {
	shell, err := parseEnvShell(args)
	if err != nil {
		return err
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
	if err := validateEnvironment(v); err != nil {
		return err
	}

	for _, k := range v.Keys() {
		val, _ := v.Get(k)
		envKey := strings.ToUpper(k)
		fmt.Println(formatEnvAssignment(shell, envKey, val))
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
	if err := validateEnvironment(v); err != nil {
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
		if isSensitiveEnvKey(k, normalizeKeys) {
			continue
		}
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

// stripSensitiveEnv removes authentication-only variables before starting an
// external process. In particular, child commands never need the master key.
func stripSensitiveEnv(inherited []string, normalizeKeys bool) []string {
	env := make([]string, 0, len(inherited))
	for _, e := range inherited {
		k, _, _ := strings.Cut(e, "=")
		if !isSensitiveEnvKey(k, normalizeKeys) {
			env = append(env, e)
		}
	}
	return env
}

func isSensitiveEnvKey(key string, caseInsensitive bool) bool {
	if caseInsensitive {
		return strings.EqualFold(key, "NILLSEC_PASSWORD")
	}
	return key == "NILLSEC_PASSWORD"
}

// validateEnvironment ensures the vault can be represented unambiguously as
// process environment variables after nillsec's documented upper-casing.
func validateEnvironment(v *vault.Vault) error {
	seen := make(map[string]string, len(v.Keys()))
	for _, key := range v.Keys() {
		if !validKeyRe.MatchString(key) {
			return fmt.Errorf("invalid vault key %q: keys must match [A-Za-z_][A-Za-z0-9_]*", key)
		}
		envKey := strings.ToUpper(key)
		if envKey == "NILLSEC_PASSWORD" {
			return fmt.Errorf("vault key %q is reserved for nillsec authentication", key)
		}
		if previous, ok := seen[envKey]; ok {
			return fmt.Errorf("vault keys %q and %q both export as %q; rename one of them", previous, key, envKey)
		}
		seen[envKey] = key
		value, _ := v.Get(key)
		if strings.IndexByte(value, 0) >= 0 {
			return fmt.Errorf("value for %q contains a NUL byte and cannot be used as an environment variable", key)
		}
	}
	return nil
}

func parseEnvShell(args []string) (string, error) {
	shell := "sh"
	if runtime.GOOS == "windows" {
		shell = "powershell"
	}

	if len(args) == 0 {
		return shell, nil
	}
	var requested string
	switch {
	case len(args) == 2 && args[0] == "--shell":
		requested = args[1]
	case len(args) == 1 && strings.HasPrefix(args[0], "--shell="):
		requested = strings.TrimPrefix(args[0], "--shell=")
	default:
		return "", fmt.Errorf("usage: nillsec env [--shell sh|powershell]")
	}

	switch strings.ToLower(requested) {
	case "sh", "bash", "zsh":
		return "sh", nil
	case "powershell", "pwsh":
		return "powershell", nil
	default:
		return "", fmt.Errorf("unsupported shell %q (choose sh or powershell)", requested)
	}
}

func formatEnvAssignment(shell, key, value string) string {
	switch shell {
	case "powershell":
		return fmt.Sprintf("$env:%s = '%s'", key, strings.ReplaceAll(value, "'", "''"))
	default:
		return fmt.Sprintf("export %s='%s'", key, strings.ReplaceAll(value, "'", "'\\''"))
	}
}

// parseEditorCommand supports the common VISUAL/EDITOR forms "code --wait"
// and quoted executable paths without invoking a command shell.
func parseEditorCommand(command string) ([]string, error) {
	var args []string
	var current strings.Builder
	var quote byte
	tokenStarted := false
	flush := func() {
		if tokenStarted {
			args = append(args, current.String())
			current.Reset()
			tokenStarted = false
		}
	}

	for i := 0; i < len(command); i++ {
		c := command[i]
		if quote != 0 {
			if c == quote {
				quote = 0
				continue
			}
			if c == '\\' && i+1 < len(command) && (command[i+1] == quote || command[i+1] == '\\') {
				i++
				c = command[i]
			}
			current.WriteByte(c)
			tokenStarted = true
			continue
		}

		switch c {
		case '\'', '"':
			quote = c
			tokenStarted = true
		case ' ', '\t', '\r', '\n':
			flush()
		case '\\':
			if i+1 < len(command) && (command[i+1] == ' ' || command[i+1] == '\t' || command[i+1] == '\'' || command[i+1] == '"') {
				i++
				current.WriteByte(command[i])
			} else {
				current.WriteByte(c)
			}
			tokenStarted = true
		default:
			current.WriteByte(c)
			tokenStarted = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("invalid editor command %q: unclosed quote", command)
	}
	flush()
	if len(args) == 0 || args[0] == "" {
		return nil, errors.New("editor command must not be empty")
	}
	return args, nil
}

// lookPathInEnv resolves an executable name against the PATH entry found in
// childEnv, so that a vault-provided PATH override is honoured at lookup time
// rather than the current process PATH. If name contains a path separator it
// is returned unchanged. Falls back to exec.LookPath when childEnv has no PATH.
func lookPathInEnv(name string, childEnv []string) (string, error) {
	// Explicit or relative path: no directory search needed.
	if strings.ContainsRune(name, os.PathSeparator) || (runtime.GOOS == "windows" && strings.ContainsRune(name, '/')) {
		return name, nil
	}

	pathValue, hasPath := environmentValue(childEnv, "PATH", runtime.GOOS == "windows")
	if hasPath {
		names := []string{name}
		if runtime.GOOS == "windows" && filepath.Ext(name) == "" {
			pathExt, ok := environmentValue(childEnv, "PATHEXT", true)
			if !ok || pathExt == "" {
				pathExt = ".COM;.EXE;.BAT;.CMD"
			}
			for _, ext := range filepath.SplitList(pathExt) {
				ext = strings.TrimSpace(ext)
				if ext == "" {
					continue
				}
				if ext[0] != '.' {
					ext = "." + ext
				}
				names = append(names, name+ext)
			}
		}

		// Search each directory in the child PATH for an executable.
		for _, dir := range filepath.SplitList(pathValue) {
			if dir == "" {
				dir = "."
			}
			for _, candidateName := range names {
				candidate := filepath.Join(dir, candidateName)
				fi, err := os.Stat(candidate)
				if err != nil || fi.IsDir() {
					continue
				}
				if runtime.GOOS != "windows" && fi.Mode()&0o111 == 0 {
					continue // not executable on Unix
				}
				return candidate, nil
			}
		}
		return "", &exec.Error{Name: name, Err: exec.ErrNotFound}
	}
	// No PATH in child env; fall back to current process PATH.
	return exec.LookPath(name)
}

func environmentValue(env []string, name string, caseInsensitive bool) (string, bool) {
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if key == name || (caseInsensitive && strings.EqualFold(key, name)) {
			return value, true
		}
	}
	return "", false
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

	// Non-TTY (piped): read a line from the shared stdin reader.
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

// promptSecret reads a secret value without echo on a TTY. For piped input it
// consumes one line, allowing automation to avoid command-line arguments.
func promptSecret(prompt string) (string, error) {
	if term.IsTerminal(int(syscall.Stdin)) {
		fmt.Fprint(os.Stderr, prompt)
		value, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("cannot read secret: %w", err)
		}
		defer wipeBytes(value)
		return string(value), nil
	}

	line, err := stdinReader.ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("cannot read secret from stdin: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
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
	if utf8.RuneCount(pw1) < 12 {
		wipeBytes(pw1)
		return nil, fmt.Errorf("master password must be at least 12 characters")
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
	fmt.Fprint(os.Stderr, `nillsec: encrypted project-secret vault

Usage:
  nillsec init [path]           create a new vault (secrets.vault)
  nillsec add  <key> [value]    add a secret; omit value for a secure prompt
  nillsec set  <key> [value]    add or overwrite; omit value for a secure prompt
  nillsec get  <key>            print a secret value
  nillsec list                  list secret keys (no values)
  nillsec remove <key>          delete a secret
  nillsec edit                  open vault contents in $EDITOR
  nillsec env [--shell SHELL]   print sh or PowerShell environment assignments
  nillsec exec [--] <cmd> ...   run a command with secrets injected as env vars
  nillsec upgrade               upgrade nillsec to the latest release
  nillsec version               print version

Environment:
  NILLSEC_VAULT    vault file path (default: secrets.vault)
  NILLSEC_PASSWORD master password (optional; if set, prompts may be skipped)
  VISUAL, EDITOR   editor used by 'edit' (default: vi; notepad.exe on Windows)
`)
}
