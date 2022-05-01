package analysis

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/radareorg/r2pipe-go"
)

// A struct that will hold the pipe between r2
// and processed information about the executable
type Binary struct {
	filename   string
	path       string
	pipe       *r2pipe.Pipe
	stringRefs []StringReference
}

// Create a new Binary struct
func NewBinary(filename string) (binary *Binary, err error) {
	binary = &Binary{
		filename: filename,
	}
	binary.pipe, err = r2pipe.NewPipe(filename)

	return
}

// Search all string references inside the code
// build a reference table and a string table
func (bin *Binary) DeepReferenceAnalysis() (err error) {
	bin.pipe.Cmd("aaa")

	// Get all string flags
	strFlags := []Flag{}
	err = bin.pipe.CmdjStruct("fs strings; fj", &strFlags)

	if err != nil {
		err = errors.New(fmt.Sprintf("%s does not have any reacheable string", bin.filename))
		return
	}

	// Get all references and string values
	for _, strFlag := range strFlags {
		strValue, _ := bin.pipe.Cmdf("ps @ %s", strFlag.Name)
		references := []Reference{}

		bin.pipe.CmdjfStruct("axtj @ %s", &references, strFlag.Name)

		if err != nil {
			fmt.Printf("%v\n", err)
			continue
		}

		if len(references) > 0 {

			codeReferences := []BasicInstruction{}

			for _, reference := range references {
				if reference.Type == "STRING" {
					codeReferences = append(codeReferences, BasicInstruction{
						Offset:      reference.From,
						Instruction: reference.Opcode,
						FuncOffset:  reference.FcnAddr,
					})
				}
			}

			if len(codeReferences) > 0 {
				strRef := StringReference{
					String:     strValue,
					References: codeReferences,
				}
				bin.stringRefs = append(bin.stringRefs, strRef)
			}
		}

	}
	return
}

func (bin *Binary) String() (out string) {
	yamlBytes, _ := json.Marshal(bin.stringRefs)
	out = string(yamlBytes)

	return
}