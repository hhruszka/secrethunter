/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	app2 "secrethunter/app"

	"github.com/spf13/cobra"
)

var patterns string

// patternCmd represents the pattern command
var patternCmd = &cobra.Command{
	Use:   "pattern [space separated list of directories or files to scan]",
	Short: "Scan file system for secrets (API keys, credentials etc.) using regular expressions (patterns).",
	Long: `Scan file system for secrets (API keys, credentials etc.) using regular 
expressions (patterns) provided by a file with the option '-p' or '--patterns'. 
If no directories or files are provided for scanning then '/' root of a file 
system will be scanned.
`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Number of passed directories: %d\n", len(args))
		app := app2.NewApp(args, patterns, scan.out, scan.exclusions, scan.throttling, scan.cpu, scan.force)
		app2.Run(app)
	},
}

func init() {
	scanCmd.AddCommand(patternCmd)

	patternCmd.Flags().StringVarP(&patterns, "patterns", "p", "", "file with regular expression patterns of secrets that the tool is\nsupposed to scan found files for. The file has to follow specific format.\nPatterns can be found on https://github.com/mazen160/secrets-patterns-db")
	patternCmd.MarkFlagRequired("patterns")
}
