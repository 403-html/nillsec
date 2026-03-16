package cmd

import (
	"fmt"
	"sort"

	"nillsec/internal/vault"
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List stored secret keys",
	Long:  "Prints all secret key names. Values are never displayed.",
	RunE: func(cmd *cobra.Command, args []string) error {
		password, err := readPassword("Master password: ")
		if err != nil {
			return err
		}
		defer zeroSlice(password)

		v, err := vault.Open(vaultPath, password)
		if err != nil {
			return err
		}

		keys := make([]string, 0, len(v.Secrets))
		for k := range v.Secrets {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			fmt.Fprintln(cmd.OutOrStdout(), k)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}
