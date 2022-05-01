package analysis

type BasicInstruction struct {
	ContextDisasm string
	Disasm        string
	Offset        uint64
	FuncOffset    uint64
}

type StringReference struct {
	String     string
	References []BasicInstruction
}
