/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"secrethunter/app"

	"github.com/spf13/cobra"
)

// base64Cmd represents the base64 command
var base64Cmd = &cobra.Command{
	Use:   "base64",
	Short: "Scan file system for base64 encoded secrets.",
	Long: `Scan file system for base64 encoded secrets (API keys, credentials etc.). 
If no directories or files are provided for scanning then '/' root of a file 
system will be scanned.`,
	Aliases: []string{"base", "bs", "64"},
	Run: func(cmd *cobra.Command, args []string) {
		runapp := app.NewApp(app.Base64Scan, args, flags)
		app.Run(runapp)
	},
}

func init() {
	scanCmd.AddCommand(base64Cmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// base64Cmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// base64Cmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
