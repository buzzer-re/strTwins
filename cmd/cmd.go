package cmd

import (
	"fmt"
	"log"
	"strings"

	analysis "github.com/aandersonl/strTwins/pkg/Analysis"
	"github.com/spf13/cobra"
)

type Arguments struct {
	Format string
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

		if len(args) == 1 {
			log.Println("Just one file has detected, extracting all the references..")
			target := args[0]

			binary, _ := analysis.NewBinary(target)
			binary.DeepReferenceAnalysis(true)

			binary.OutputFormat = arguments.Format
			arguments.Format = strings.ToLower(arguments.Format)

			fmt.Println(binary)

			return
		} else {
			log.Printf("Starting analysis of %d files...", len(args))
			var globalStrTable analysis.GlobalStrTable = analysis.SharedDeepReferenceAnalysis(args)

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
	cmd.Flags().StringVarP(&arguments.Format, "format", "f", "text", "Format to output, available are: json, yaml, text and Yara")
}
