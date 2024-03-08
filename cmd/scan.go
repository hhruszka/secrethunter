/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"github.com/spf13/cobra"
	"runtime"
)

var (
	reportFile       string
	excludedPaths    string
	cpuWorkloadLimit int
	maxCPU           int
	forceFlg         bool
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan METHOD",
	Short: "Scan file system for secrets.",
	Long: `Scan file system for secrets (API keys, credentials etc.) using one of
the scan methods. If no directories or files will be provided for
scanning then '/' root of a file system will be scanned.
`,
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.PersistentFlags().StringVarP(&reportFile, "out", "o", "Stdout", "output file for a generated report otherwise the report will be\nprinted to standard output")
	scanCmd.PersistentFlags().StringVarP(&excludedPaths, "exclusions", "x", "", "comma seperated list of regular expressions and/or files (with regular\nexpressions) to be used to exclude files or directories during the scan.\nTypically usage is to exclude directories containing documentation,\nmanual pages or examples.")
	scanCmd.PersistentFlags().IntVarP(&cpuWorkloadLimit, "throttling", "t", 65, "throttling value (from 10 to 80), which sets maximum CPU usage that\nthe system cannot exceed during execution of the tool")
	scanCmd.PersistentFlags().IntVarP(&maxCPU, "cpu", "c", runtime.NumCPU(), "maximum number of vCPUs to be used by the tool")
	scanCmd.PersistentFlags().BoolVarP(&forceFlg, "force", "f", false, "force execution inhibit throttling")
}
