package analysis

import (
	"errors"
	"fmt"
	"strings"

	"github.com/radareorg/r2pipe-go"
)

// A struct that will hold the pipe between r2
// and processed information about the executable
type Binary struct {
	filename     string
	path         string
	filehash     string
	pipe         *r2pipe.Pipe
	strTable     GlobalStrTable
	OutputFormat string
}

// Create a new Binary struct
func NewBinary(filename string) (binary *Binary, err error) {
	binary = &Binary{
		filename: filename,
	}

	// TODO: Fix NativePipe in concurrent execution
	binary.pipe, err = r2pipe.NewPipe(filename)
	binary.strTable = make(GlobalStrTable)

	return
}

// Search all string references inside the code and
// build a reference table and a string table
func (bin *Binary) DeepReferenceAnalysis(closePipe bool) (err error) {
	bin.pipe.Cmd("aaa")

	// Get all string flags
	strFlags := []Flag{}
	bin.pipe.CmdjStruct("fs strings; fj", &strFlags)

	if len(strFlags) == 0 {
		err = errors.New(fmt.Sprintf("%s does not have any reacheable string", bin.filename))
		return
	}

	// Get all references and string values
	for _, strFlag := range strFlags {
		wide := false
		strValue, _ := bin.pipe.Cmdf("ps @ %s", strFlag.Name)
		if len(strValue) == 1 {
			// Wide
			strValue, _ = bin.pipe.Cmdf("psw @ %s", strFlag.Name)
			wide = true
		}

		// Check if string is valid by checking if comes with \x<byte>
		if strings.Contains(strValue, "\\x") {
			continue
		}

		references := []Reference{}
		// rawJson, _ := bin.pipe.Cmdf("psj @ %s", strFlag.Name)

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
						Filename:      bin.filename,
						Offset:        reference.From,
						ContextDisasm: reference.Opcode,
						FuncOffset:    reference.FcnAddr,
						Disasm:        bin.GetDisasmAt(reference.From),
					})
				}
			}

			if len(codeReferences) > 0 {
				bin.strTable[strValue] = RefCounter{
					Instructions: codeReferences,
					WideString:   wide,
				}
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

func (bin *Binary) String() string {
	return bin.strTable.String()
}
