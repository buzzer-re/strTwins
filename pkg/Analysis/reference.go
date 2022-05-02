package analysis

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
