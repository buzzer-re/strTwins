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

			binary, err := analysis.NewBinary(target)
			if err != nil {
				log.Fatalf("Unable to open %s!\n", target)
			}

			err = binary.DeepReferenceAnalysis(true)

			if err != nil {
				log.Fatalf("Error on analysis: %v!\n", err)
			}

			if analysis.YaraRuleName == "" {
				analysis.YaraRuleName = "Gen_" + filepath.Base(target)
			}

			fmt.Println(binary)

			return
		} else {
			log.Printf("Starting analysis of %d files...", len(args))
			globalStrTable, err := analysis.SharedDeepReferenceAnalysis(args)

			if err != nil {
				log.Fatalf("Error: %v!\n", err)
				return
			}
			// if

			if analysis.YaraRuleName == "" && analysis.FmtType == "yara" {
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
