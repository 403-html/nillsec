package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var vaultPath string

var rootCmd = &cobra.Command{
	Use:   "nillsec",
	Short: "Encrypted secrets vault",
	Long:  "nillsec manages encrypted project secrets stored in a single vault file.",
	// Don't print usage when a command returns a runtime error.
	SilenceUsage: true,
	// We handle error printing in Execute so it appears exactly once.
	SilenceErrors: true,
}

// Execute is the entry point for the CLI.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&vaultPath, "file", "f", "secrets.vault", "path to vault file")
}
