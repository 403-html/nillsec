package main

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var envCmd = &cobra.Command{
	Use:   "env",
	Short: "Export secrets as environment variables",
	Long: `Prints shell export statements for every secret.

Integrate with your shell via:

    eval "$(nillsec env)"`,
	RunE: func(cmd *cobra.Command, args []string) error {
		password, err := readPassword("Master password: ")
		if err != nil {
			return err
		}
		defer zeroBytes(password)

		v, err := openVault(vaultPath, password)
		if err != nil {
			return err
		}

		keys := make([]string, 0, len(v.Secrets))
		for k := range v.Secrets {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		w := cmd.OutOrStdout()
		for _, k := range keys {
			envKey := strings.ToUpper(k)
			fmt.Fprintf(w, "export %s='%s'\n", envKey, shellEscape(v.Secrets[k]))
		}
		return nil
	},
}

var editCmd = &cobra.Command{
	Use:   "edit",
	Short: "Open decrypted vault in your editor",
	Long: `Decrypts the vault to a secure temporary file, opens it in $EDITOR,
and re-encrypts on save. The plaintext file is removed immediately after.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		password, err := readPassword("Master password: ")
		if err != nil {
			return err
		}
		defer zeroBytes(password)

		v, err := openVault(vaultPath, password)
		if err != nil {
			return err
		}

		// Write decrypted contents to a temp file with restricted permissions.
		tmp, err := os.CreateTemp("", "nillsec-edit-*.yaml")
		if err != nil {
			return fmt.Errorf("create temp file: %w", err)
		}
		tmpPath := tmp.Name()
		// Always remove the plaintext temp file.
		defer func() {
			os.Remove(tmpPath)
		}()

		content, err := vaultToYAML(v)
		if err != nil {
			tmp.Close()
			return err
		}
		if _, err := tmp.Write(content); err != nil {
			tmp.Close()
			return fmt.Errorf("write temp file: %w", err)
		}
		if err := tmp.Close(); err != nil {
			return err
		}

		editor := os.Getenv("EDITOR")
		if editor == "" {
			editor = "vi"
		}

		editorCmd := exec.Command(editor, tmpPath)
		editorCmd.Stdin = os.Stdin
		editorCmd.Stdout = os.Stdout
		editorCmd.Stderr = os.Stderr
		if err := editorCmd.Run(); err != nil {
			return fmt.Errorf("editor exited with error: %w", err)
		}

		// Parse edited content.
		edited, err := os.ReadFile(tmpPath)
		if err != nil {
			return fmt.Errorf("read edited file: %w", err)
		}
		defer zeroBytes(edited)

		updated, err := yamlToVault(edited)
		if err != nil {
			return fmt.Errorf("parse edited vault: %w", err)
		}

		return updated.Save(vaultPath, password)
	},
}

// shellEscape escapes single quotes in a value so it is safe to embed inside
// single-quoted shell strings.
func shellEscape(s string) string {
	return strings.ReplaceAll(s, "'", "'\\''")
}

// vaultToYAML serialises the vault secrets into a human-editable YAML blob.
func vaultToYAML(v *Vault) ([]byte, error) {
	sb := strings.Builder{}
	sb.WriteString("# Edit secrets below. Save and close the editor to re-encrypt.\n")
	sb.WriteString("# Do not change the 'version' field.\n")
	sb.WriteString(fmt.Sprintf("version: %d\n", v.Version))
	sb.WriteString("secrets:\n")

	keys := make([]string, 0, len(v.Secrets))
	for k := range v.Secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		// Use YAML block scalar indentation – simple quoted form is fine for
		// most values; the parser will handle it on read-back.
		sb.WriteString(fmt.Sprintf("  %s: %s\n", k, yamlQuote(v.Secrets[k])))
	}

	return []byte(sb.String()), nil
}

// yamlToVault parses the YAML blob produced by vaultToYAML back into a Vault.
func yamlToVault(data []byte) (*Vault, error) {
	v := newVault()
	if err := yaml.Unmarshal(data, v); err != nil {
		return nil, err
	}
	return v, nil
}

// yamlQuote wraps a string in double quotes when it contains characters that
// would confuse a naïve YAML parser.
func yamlQuote(s string) string {
	needsQuoting := strings.ContainsAny(s, ":{}[]|>&*!,#?-\t\n\r")
	if needsQuoting {
		return fmt.Sprintf("%q", s)
	}
	return s
}

func init() {
	rootCmd.AddCommand(envCmd)
	rootCmd.AddCommand(editCmd)
}
