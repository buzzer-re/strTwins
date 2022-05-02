package analysis

import (
	"errors"
	"sync"
)

// Concurrently call the DeepReference analysis in each binary
func SharedDeepReferenceAnalysis(files []string) (globalStrTable GlobalStrTable, err error) {
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

	if totalBinaries == 0 {
		err = errors.New("no valid binary was found")
		return
	}
	//	Filter
	var wait sync.WaitGroup = sync.WaitGroup{}

	for _, bin := range binaries {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for name := range bin.strTable {
				mutex.Lock()
				if refCounter, found := globalStrTable[name]; !found || refCounter.hits != totalBinaries {
					delete(globalStrTable, name)
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

		// Build a global string table with all the reference strings collected
		// As we are doing this in paralellel, we can only filter after all the binaries have been analysed
		for name, references := range bin.strTable {
			mutex.Lock()
			refCounter, found := globalStrTable[name]
			if found {
				refCounter.hits++
				refCounter.Instructions = append(refCounter.Instructions, references.Instructions...)
				globalStrTable[name] = refCounter
			} else {
				globalStrTable[name] = RefCounter{
					hits:         1,
					Instructions: references.Instructions,
				}
			}
			mutex.Unlock()
		}

		binary <- bin
	}
}
