package analysis

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/radareorg/r2pipe-go"
	"gopkg.in/yaml.v2"
)

// A struct that will hold the pipe between r2
// and processed information about the executable
type Binary struct {
	filename     string
	path         string
	pipe         *r2pipe.Pipe
	stringRefs   []StringReference
	OutputFormat string
}

// Create a new Binary struct
func NewBinary(filename string) (binary *Binary, err error) {
	binary = &Binary{
		filename: filename,
	}

	// TODO: Fix NativePipe in concurrent execution
	binary.pipe, err = r2pipe.NewPipe(filename)

	return
}

// Search all string references inside the code and
// build a reference table and a string table
func (bin *Binary) DeepReferenceAnalysis(closePipe bool) (err error) {
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
				if reference.Type != "CODE" && reference.Opcode != "invalid" {
					codeReferences = append(codeReferences, BasicInstruction{
						Offset:        reference.From,
						ContextDisasm: reference.Opcode,
						FuncOffset:    reference.FcnAddr,
						Disasm:        bin.GetDisasmAt(reference.From),
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

	// Close pipe after analysis, useful when we are dealing with a lot of files
	// to leave open a bunch of r2 sessions opened
	if closePipe {
		bin.pipe.Close()
	}

	return
}

// Disassemble one instruction at a given address
func (bin *Binary) GetDisasmAt(address uint64) (disasm string) {
	inst := Instruction{}
	err := bin.pipe.CmdjfStruct("pdj 1 @ %d ~{0}", &inst, address)

	if err == nil {
		return inst.Opcode
	}

	return

}

func (bin *Binary) String() (out string) {
	out = fmt.Sprintf("Invalid output format specified %s\n", bin.OutputFormat)

	switch bin.OutputFormat {
	case "json":
		bytes, _ := json.Marshal(bin.stringRefs)
		out = string(bytes)
	case "yaml":
		bytes, _ := yaml.Marshal(bin.stringRefs)
		out = string(bytes)

		// TODO: yara and text

	}

	return
}
