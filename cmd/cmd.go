package cmd

import (
	"fmt"
	"log"
	"path/filepath"
	"strings"

	analysis "github.com/aandersonl/strTwins/pkg/Analysis"
	"github.com/spf13/cobra"
)

type Arguments struct {
	Format       string
	YaraRuleName string
}

var arguments Arguments = Arguments{}

var cmd = &cobra.Command{
	Short: "Discover shared string references between binaries and output in a variety formats!",
	Use:   "strTwins file1, file2... [flags]",
	Run: func(cmd *cobra.Command, args []string) {

		// TODO: Improve code
		if len(args) == 0 {
			cmd.Help()
			return
		}
		analysis.FmtType = strings.ToLower(arguments.Format)
		analysis.YaraRuleName = arguments.YaraRuleName
		if len(args) == 1 {
			log.Println("Just one file has detected, extracting all the references..")
			target := args[0]

			binary, _ := analysis.NewBinary(target)
			binary.DeepReferenceAnalysis(true)

			if analysis.YaraRuleName == "" {
				analysis.YaraRuleName = "Gen_" + filepath.Base(target)
			}

			fmt.Println(binary)

			return
		} else {
			log.Printf("Starting analysis of %d files...", len(args))
			var globalStrTable analysis.GlobalStrTable = analysis.SharedDeepReferenceAnalysis(args)

			if analysis.YaraRuleName == "" {
				log.Println("No yara rule name provided!")
				analysis.YaraRuleName = "Gen_Shared_Str_Ref"
			}

			if len(globalStrTable) > 0 {
				fmt.Println(globalStrTable)
			} else {
				fmt.Println("No shared string was found!")
			}
		}

	},
}

func Execute() {
	cmd.Execute()
}

func init() {
	cmd.Flags().StringVarP(&arguments.Format, "format", "f", "yaml", "Format to output, available are: json, yaml and Yara!")
	cmd.Flags().StringVarP(&arguments.YaraRuleName, "rulename", "n", "", "Yara rule name, if was choosen as format output!")
}
