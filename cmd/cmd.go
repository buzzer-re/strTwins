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
		if len(args) == 1 {
			log.Println("Just one file has detected, extracting all the references..")
			target := args[0]

			binary, _ := analysis.NewBinary(target)
			binary.DeepReferenceAnalysis()

			binary.OutputFormat = "text"
			arguments.Format = strings.ToLower(arguments.Format)
			switch arguments.Format {
			case "json":
				binary.OutputFormat = arguments.Format
			case "yaml":
				binary.OutputFormat = arguments.Format
			case "yara":
				binary.OutputFormat = arguments.Format
			}

			fmt.Println(binary)

			return
		}

		cmd.Help()
	},
}

func Execute() {
	cmd.Execute()
}

func init() {
	cmd.Flags().StringVarP(&arguments.Format, "format", "f", "text", "Format to output, available are: json, yaml, text and Yara")
}
