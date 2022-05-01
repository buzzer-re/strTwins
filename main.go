package main

import (
	"fmt"
	"os"

	analysis "github.com/aandersonl/strTwins/pkg/Analysis"
)

func main() {

	target := os.Args[1]

	binary, _ := analysis.NewBinary(target)

	binary.DeepReferenceAnalysis()

	fmt.Println(binary)
}
