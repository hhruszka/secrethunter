/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"github.com/spf13/cobra"
	"runtime"
)

type Scan struct {
	out        string
	exclusions string
	throttling int
	cpu        int
	force      bool
}

var scan Scan

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan [method] [flags] [space separated list of directories or files to scan]",
	Short: "Scan file system for secrets.",
	Long:  "Scan file system for secrets (API keys, credentials etc.) using one of the scan methods. If no directories or files will be provided for scanning then '/' root of a file system will be scanned.",
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.PersistentFlags().StringVarP(&scan.out, "out", "o", "Stdout", "output file for a generated report otherwise the report will be\nprinted to standard output")
	scanCmd.PersistentFlags().StringVarP(&scan.exclusions, "exlusions", "x", "", "list of regular expressions and/or files comma seperated list of regular\nexpressions and/or files (with regular expressions) to be used to\nexclude files or directories during the scan. Typically usage is to\nexclude directories containing documentation, manual pages or examples.")
	scanCmd.PersistentFlags().IntVarP(&scan.throttling, "throttling", "t", 65, "throttling value (from 10 to 80), which sets maximum CPU usage that\nthe system cannot exceed during execution of the tool")
	scanCmd.PersistentFlags().IntVarP(&scan.cpu, "cpu", "c", runtime.NumCPU(), "maximum number of vCPUs to be used by the tool")
	scanCmd.PersistentFlags().BoolVarP(&scan.force, "force", "f", false, "force execution inhibit throttling")
}
