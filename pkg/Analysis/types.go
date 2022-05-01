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
