package analysis

import (
	"sync"
)

// Concurrently call the DeepReference analysis in each binary
func SharedDeepReferenceAnalysis(files []string) (globalStrTable GlobalStrTable) {
	fileChan := make(chan string, 100)
	binChan := make(chan *Binary, len(files))
	binaries := []*Binary{}
	globalStrTable = make(GlobalStrTable)

	var mutex sync.Mutex = sync.Mutex{}
	for i := 0; i < 100; i++ {
		go binWorker(fileChan, binChan, globalStrTable, &mutex)
	}

	for _, file := range files {
		fileChan <- file
	}

	close(fileChan)

	for range files {
		binary := <-binChan
		if binary != nil {
			binaries = append(binaries, binary)
		}
	}

	totalBinaries := uint(len(binaries))

	// Filter
	var wait sync.WaitGroup = sync.WaitGroup{}

	for _, bin := range binaries {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for _, strRef := range bin.stringRefs {
				mutex.Lock()
				if refCounter, found := globalStrTable[strRef.String]; !found || refCounter.hits != totalBinaries {
					delete(globalStrTable, strRef.String)
				}
				mutex.Unlock()
			}
		}()
	}

	wait.Wait()
	return
}

// Open, analyse the binary and compute shared string references in code
func binWorker(files <-chan string, binary chan<- *Binary, globalStrTable GlobalStrTable, mutex *sync.Mutex) {
	for f := range files {
		bin, _ := NewBinary(f)
		err := bin.DeepReferenceAnalysis(true)
		if err != nil {
			binary <- nil
			continue
		}

		for _, strRef := range bin.stringRefs {
			mutex.Lock()
			refCounter, found := globalStrTable[strRef.String]
			if found {
				refCounter.hits++
				refCounter.Instructions = append(refCounter.Instructions, strRef.References...)
				globalStrTable[strRef.String] = refCounter
			} else {
				globalStrTable[strRef.String] = RefCounter{
					hits:         1,
					Instructions: strRef.References,
				}
			}
			mutex.Unlock()
		}

		binary <- bin
	}
}
