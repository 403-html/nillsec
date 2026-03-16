package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"nillsec/internal/vault"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Create a new vault",
	Long:  "Creates a new empty encrypted vault file protected by a master password.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := os.Stat(vaultPath); err == nil {
			return fmt.Errorf("vault already exists: %s", vaultPath)
		}

		password, err := readPassword("Master password: ")
		if err != nil {
			return err
		}
		defer zeroSlice(password)

		confirm, err := readPassword("Confirm password: ")
		if err != nil {
			return err
		}
		defer zeroSlice(confirm)

		if !bytes.Equal(password, confirm) {
			return errors.New("passwords do not match")
		}

		v := vault.New()
		if err := v.Save(vaultPath, password); err != nil {
			return err
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Vault created: %s\n", vaultPath)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
}
