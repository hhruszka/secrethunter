/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"secrethunter/app"

	"github.com/spf13/cobra"
)

var (
	minimumEntropy float64
	minimumLength  int
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
		options := app.Options{
			ReportFile:       reportFile,
			ExcludedPaths:    excludedPaths,
			CpuWorkloadLimit: cpuWorkloadLimit,
			MaxCPU:           maxCPU,
			ForceFlg:         forceFlg,
			MinimumEntropy:   minimumEntropy,
			MinimumLength:    minimumLength,
		}

		runapp := app.NewApp(app.EntropyScan, args, options)
		app.Run(runapp)
	},
}

func init() {
	scanCmd.AddCommand(entropyCmd)
	entropyCmd.Flags().Float64VarP(&minimumEntropy, "minimum-entropy", "e", 60.0, "minimum entropy of password (password strength)")
	entropyCmd.Flags().IntVarP(&minimumLength, "minimum-length", "l", 8, "minimum length of password ")
}
