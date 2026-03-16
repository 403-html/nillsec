package cmd

import (
	"bytes"
	"errors"

	"github.com/403-html/nillsec/internal/vault"
	"github.com/spf13/cobra"
)

var rekeyCmd = &cobra.Command{
	Use:   "rekey",
	Short: "Change the master password",
	Long:  "Decrypts the vault with the current password and re-encrypts it with a new one.",
	RunE: func(cmd *cobra.Command, args []string) error {
		oldPassword, err := readPassword("Current master password: ")
		if err != nil {
			return err
		}
		defer zeroSlice(oldPassword)

		v, err := vault.Open(vaultPath, oldPassword)
		if err != nil {
			return err
		}

		newPassword, err := readPassword("New master password: ")
		if err != nil {
			return err
		}
		defer zeroSlice(newPassword)

		confirm, err := readPassword("Confirm new password: ")
		if err != nil {
			return err
		}
		defer zeroSlice(confirm)

		if !bytes.Equal(newPassword, confirm) {
			return errors.New("passwords do not match")
		}

		return v.Save(vaultPath, newPassword)
	},
}

func init() {
	rootCmd.AddCommand(rekeyCmd)
}
