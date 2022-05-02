package analysis

// Concurrently call the DeepReference analysis in each binary
func ConcurrentDeepReferenceAnalysis(files []string) (bins []*Binary) {
	fileChan := make(chan string, 100)
	binaries := make(chan *Binary, len(files))

	for i := 0; i < 100; i++ {
		go binWorker(fileChan, binaries)
	}

	for _, file := range files {
		fileChan <- file
	}

	close(fileChan)

	for range files {
		var binFinished *Binary = <-binaries

		if binFinished != nil {
			bins = append(bins, binFinished)
		}

	}
	return
}

// Open and analyse the binary
func binWorker(files <-chan string, binary chan<- *Binary) {
	for f := range files {
		bin, _ := NewBinary(f)
		err := bin.DeepReferenceAnalysis(true)

		if err != nil {
			binary <- nil
		} else {
			binary <- bin
		}
	}
}
