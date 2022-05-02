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
		for name, info := range gtable {
			modifiers := []string{}
			if info.WideString {
				modifiers = append(modifiers, "wide")
			}

			yaraStrings[name] = modifiers
		}
		out = FormatToYara(YaraRuleName, yaraStrings)
	}

	return
}
