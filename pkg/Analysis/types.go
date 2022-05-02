package analysis

// r2 flag
type Flag struct {
	Name   string `json:"name"`
	Size   int    `json:"size"`
	Offset uint64 `json:"offset"`
}

// r2 Reference struct - axtj
type Reference struct {
	From    uint64 `json:"from"`
	Type    string `json:"type"`
	Opcode  string `json:"opcode"`
	FcnAddr uint64 `json:"fcn_addr"`
	FcnName string `json:"fcn_name"`
	Refname string `json:"refname"`
}

// r2 disasm, pdj
type Instruction struct {
	Offset   int    `json:"offset"`
	Ptr      int    `json:"ptr"`
	Val      int    `json:"val"`
	Esil     string `json:"esil"`
	Refptr   bool   `json:"refptr"`
	FcnAddr  int    `json:"fcn_addr"`
	FcnLast  int    `json:"fcn_last"`
	Size     int    `json:"size"`
	Opcode   string `json:"opcode"`
	Disasm   string `json:"disasm"`
	Bytes    string `json:"bytes"`
	Family   string `json:"family"`
	Type     string `json:"type"`
	Reloc    bool   `json:"reloc"`
	TypeNum  int    `json:"type_num"`
	Type2Num int    `json:"type2_num"`
	Refs     []struct {
		Addr int    `json:"addr"`
		Type string `json:"type"`
	} `json:"refs"`
	Xrefs []struct {
		Addr int    `json:"addr"`
		Type string `json:"type"`
	} `json:"xrefs"`
}

// Simplified struct to hold strTwins asm instructions
type BasicInstruction struct {
	Filename      string
	ContextDisasm string
	Disasm        string
	Offset        uint64
	FuncOffset    uint64
}
