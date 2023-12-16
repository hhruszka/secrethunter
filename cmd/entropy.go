/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"secrethunter/app"

	"github.com/spf13/cobra"
)

// entropyCmd represents the entropy command
var entropyCmd = &cobra.Command{
	Use:   "entropy",
	Short: "Scan file system for secrets (API keys, credentials etc.) using entropy.",
	Long: `Scan file system for secrets (API keys, credentials etc.) using entropy. 
If no directories or files are provided for scanning then '/' root of a file 
system will be scanned.
`,
	Run: func(cmd *cobra.Command, args []string) {
		runapp := app.NewApp(app.EntropyScan, args, flags)
		app.Run(runapp)
	},
}

func init() {
	scanCmd.AddCommand(entropyCmd)
}
