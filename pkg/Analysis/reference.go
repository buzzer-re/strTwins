package analysis

import (
	"encoding/json"

	"gopkg.in/yaml.v2"
)

type RefCounter struct {
	hits         uint
	WideString   bool
	Instructions []BasicInstruction
}

// Quick access when checing
type GlobalStrTable map[string]RefCounter

type StringReference struct {
	String     string
	References []BasicInstruction
}

func (gtable GlobalStrTable) Format(fmtType string) (out string) {

	switch fmtType {
	case "json":
		bytes, _ := json.MarshalIndent(gtable, "", " ")
		out = string(bytes)
	case "yaml":
		bytes, _ := yaml.Marshal(gtable)
		out = string(bytes)
	case "yara":
		var yaraStrings YaraString = make(YaraString)
		for name, info := range gtable {
			modifiers := []string{}
			if info.WideString {
				modifiers = append(modifiers, "wide")
			}

			yaraStrings[name] = modifiers
		}
		out = FormatToYara("teste", yaraStrings)
	}

	return
}
