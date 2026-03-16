package cmd

import (
	"fmt"

	"nillsec/internal/vault"
	"github.com/spf13/cobra"
)

var removeCmd = &cobra.Command{
	Use:     "remove <key>",
	Aliases: []string{"rm", "delete"},
	Short:   "Remove a secret",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		key := args[0]

		password, err := readPassword("Master password: ")
		if err != nil {
			return err
		}
		defer zeroSlice(password)

		v, err := vault.Open(vaultPath, password)
		if err != nil {
			return err
		}

		if _, ok := v.Secrets[key]; !ok {
			return fmt.Errorf("key not found: %s", key)
		}

		delete(v.Secrets, key)
		return v.Save(vaultPath, password)
	},
}

func init() {
	rootCmd.AddCommand(removeCmd)
}
