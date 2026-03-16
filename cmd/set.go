package cmd

import (
	"github.com/403-html/nillsec/internal/vault"
	"github.com/spf13/cobra"
)

var setCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Set (create or update) a secret",
	Long:  "Creates or overwrites a secret in the vault.",
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

		v.Secrets[key] = value
		return v.Save(vaultPath, password)
	},
}

func init() {
	rootCmd.AddCommand(setCmd)
}
