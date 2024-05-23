package cmd

import (
	"ThreatCheck/utils"
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

type OPTS struct {
	engine   string
	file     string
	url      string
	filetype string
}

var opts OPTS

var rootCmd = &cobra.Command{
	Use:   "ThreatChecker",
	Short: " ",
	Long:  `ThreatChecker: Analyze malicious files and identify bad bytes`,

	Run: func(cmd *cobra.Command, args []string) {

		if len(os.Args) <= 1 {
			utils.Useages()
			cmd.Help()
			os.Exit(0)
		} else {
			targetfilepath := utils.CheckFileAbs(opts.file)
			filecontents := utils.CheckInFile(opts.url, targetfilepath)
			utils.CheckEngine(opts.engine, opts.filetype, filecontents)
		}

	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&opts.engine, "engine", "e", "AMSI", "Scanning engine. Options: Defender or AMSI")
	rootCmd.PersistentFlags().StringVarP(&opts.file, "file", "f", "", "Filepath, analyze a file on disk")
	rootCmd.PersistentFlags().StringVarP(&opts.url, "url", "u", "", "FileURL, analyze a file from a URL")
	rootCmd.PersistentFlags().StringVarP(&opts.filetype, "type", "t", "", "File type to scan. Options: Bin or Script")

}
