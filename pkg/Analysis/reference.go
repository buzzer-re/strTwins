package analysis

import "encoding/json"

type RefCounter struct {
	hits         uint
	Instructions []BasicInstruction
}

// Quick access when checing
type GlobalStrTable map[string]RefCounter

type StringReference struct {
	String     string
	References []BasicInstruction
}

func (gtable GlobalStrTable) String() string {
	bytes, _ := json.Marshal(gtable)
	return string(bytes)
}
