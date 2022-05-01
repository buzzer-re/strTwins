package analysis

type BasicInstruction struct {
	Instruction string
	Offset      uint64
	FuncOffset  uint64
}

type StringReference struct {
	String     string
	References []BasicInstruction
}
