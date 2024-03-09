/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"secrethunter/app"

	"github.com/spf13/cobra"
)

var (
	minWordLength int
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
		options := app.Options{
			ReportFile:       reportFile,
			ExcludedPaths:    excludedPaths,
			CpuWorkloadLimit: cpuWorkloadLimit,
			MaxCPU:           maxCPU,
			ForceFlg:         forceFlg,
			MinWordLength:    minWordLength,
		}
		runapp := app.NewApp(app.Base64Scan, args, options)
		app.Run(runapp)
	},
}

func init() {
	scanCmd.AddCommand(base64Cmd)
	base64Cmd.Flags().IntVarP(&minWordLength, "length", "l", 8, "minimum length of a word to consider it for base64 analysis")
}
