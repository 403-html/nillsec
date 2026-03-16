package cmd

import (
	"fmt"

	"nillsec/internal/vault"
	"github.com/spf13/cobra"
)

var getCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Retrieve a secret value",
	Args:  cobra.ExactArgs(1),
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

		value, ok := v.Secrets[key]
		if !ok {
			return fmt.Errorf("key not found: %s", key)
		}

		fmt.Fprintln(cmd.OutOrStdout(), value)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(getCmd)
}
