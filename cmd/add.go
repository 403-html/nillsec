package cmd

import (
	"fmt"

	"nillsec/internal/vault"
	"github.com/spf13/cobra"
)

var addCmd = &cobra.Command{
	Use:   "add <key> <value>",
	Short: "Add a new secret",
	Long:  "Adds a new secret to the vault. Fails if the key already exists (use 'set' to update).",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		key, value := args[0], args[1]

		password, err := readPassword("Master password: ")
		if err != nil {
			return err
		}
		defer zeroSlice(password)

		v, err := vault.Open(vaultPath, password)
		if err != nil {
			return err
		}

		if _, exists := v.Secrets[key]; exists {
			return fmt.Errorf("key %q already exists (use 'set' to update)", key)
		}

		v.Secrets[key] = value
		return v.Save(vaultPath, password)
	},
}

func init() {
	rootCmd.AddCommand(addCmd)
}
