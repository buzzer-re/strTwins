package analysis

import (
	"errors"
	"runtime"
	"sync"

	"github.com/schollz/progressbar/v3"
)

// Concurrently call the DeepReference analysis in each binary
func SharedDeepReferenceAnalysis(files []string) (globalStrTable GlobalStrTable, err error) {
	numRoutines := runtime.NumCPU()
	numFiles := len(files)
	bar := progressbar.Default(int64(numFiles))
	fileChan := make(chan string, numRoutines)
	binChan := make(chan *Binary, numFiles)
	binaries := []*Binary{}
	globalStrTable = make(GlobalStrTable)

	var mutex sync.Mutex = sync.Mutex{}
	for i := 0; i < numRoutines; i++ {
		go binWorker(fileChan, binChan, globalStrTable, &mutex, bar)
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
		go func(binary *Binary) {
			defer wait.Done()
			for name := range binary.strTable {
				mutex.Lock()
				refCounter, found := globalStrTable[name]
				if !found || refCounter.hits != totalBinaries {
					delete(globalStrTable, name)
				}
				mutex.Unlock()
			}
		}(bin)
	}

	wait.Wait()
	return
}

// Open, analyse the binary and compute shared string references in code
func binWorker(files <-chan string, binary chan<- *Binary, globalStrTable GlobalStrTable, mutex *sync.Mutex, bar *progressbar.ProgressBar) {
	for f := range files {
		binary <- nil
		bin, err := NewBinary(f)
		if err != nil {
			binary <- nil
			continue
		}

		err = bin.DeepReferenceAnalysis(true)
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
				references.hits = 1
				globalStrTable[name] = references
			}
			mutex.Unlock()
		}

		// Not using defer here because we are inside a for loop
		bar.Add(1)
		binary <- bin
	}
}
