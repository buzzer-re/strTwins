package analysis

import (
	"fmt"
	"strings"
)

// YaraString is defined by a string as key and a list of modifiers
// example
// {
//  "COOLSTRING" : [nocase, wide]
// }

type YaraString map[string][]string

// TODO: Create a YARA_SMART_FMT that will have unique conditions for PE & ELF
const YARA_BASIC_FMT = `
rule %s {
	meta:
		description = "Generated rule by strTwins tool"
	strings:
%s
	condition:
		all of them
}
`

// Yara basic formater
func FormatToYara(rulename string, strs YaraString) string {
	if len(strs) == 0 {
		return "No strings to be formarted!"
	}

	var stringsValues string
	counter := 0
	for str, modifiers := range strs {
		stringsValues += fmt.Sprintf("\t\t$%d = \"%s\" %s\n", counter, str, strings.Join(modifiers, " "))
		counter++
	}

	return fmt.Sprintf(YARA_BASIC_FMT, rulename, stringsValues)
}
