package main

import (
	"bytes"
	"errors"

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
		defer zeroBytes(oldPassword)

		v, err := openVault(vaultPath, oldPassword)
		if err != nil {
			return err
		}

		newPassword, err := readPassword("New master password: ")
		if err != nil {
			return err
		}
		defer zeroBytes(newPassword)

		confirm, err := readPassword("Confirm new password: ")
		if err != nil {
			return err
		}
		defer zeroBytes(confirm)

		if !bytes.Equal(newPassword, confirm) {
			return errors.New("passwords do not match")
		}

		return v.Save(vaultPath, newPassword)
	},
}

func init() {
	rootCmd.AddCommand(rekeyCmd)
}
