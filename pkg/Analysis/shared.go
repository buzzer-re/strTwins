package analysis

// Struct that will hold the post processed data between N binaries
type SharedReference struct {
	BaseFile               string
	SharedStringReferences []StringReference
}

// Concurrently compute all the shared string references
func BuildSharedReferences(bins []*Binary) (sharedReference SharedReference) {

	return
}
