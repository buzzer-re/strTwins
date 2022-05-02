package analysis

import (
	"encoding/json"

	"gopkg.in/yaml.v2"
)

var FmtType string
var YaraRuleName string

func (gtable GlobalStrTable) String() (out string) {

	switch FmtType {
	case "json":
		bytes, _ := json.MarshalIndent(gtable, "", " ")
		out = string(bytes)
	case "yaml":
		bytes, _ := yaml.Marshal(gtable)
		out = string(bytes)
	case "yara":
		var yaraStrings YaraString = make(YaraString)
		var stringSize int
		for name, info := range gtable {
			modifiers := []string{}
			if info.WideString {
				modifiers = append(modifiers, "wide")
			}
			stringSize = len(name)
			if stringSize > MAX_STRING_SIZE {
				yaraStrings[name[:MAX_STRING_SIZE]] = modifiers
			} else {
				yaraStrings[name] = modifiers
			}

		}
		out = FormatToYara(YaraRuleName, yaraStrings)
	}

	return
}
