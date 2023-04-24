package main

import (
	"github.com/gabriel-vasile/mimetype"
	"github.com/schollz/progressbar/v3"
	"io/fs"
	"path/filepath"
	"runtime"
	"sync"
)

// workers will use mimetype to determine a file type and decide whether to collect it
func worker(id int, wg *sync.WaitGroup, jobs chan string, results chan string) {
	defer wg.Done()

	for fp := range jobs {
		fm, err := mimetype.DetectFile(fp)
		isBinary := true

		if fm.Is("application/octet-stream") {
			continue
		}

		if err == nil {
			for mtype := fm; mtype != nil; mtype = mtype.Parent() {
				if mtype.Is("text/plain") {
					isBinary = false
				}
			}

			if isBinary == false {
				results <- fp
			}
		}
	}
}

func isExcluded(path string, dirs []string) (excluded bool) {
	excluded = false
	for _, dir := range dirs {
		if path == dir {
			excluded = true
			break
		}
	}
	return
}

func getFileList(directory string, excludedDirs []string) (files []string) {
	var wg sync.WaitGroup
	var results chan string = make(chan string, 1000)
	var jobs chan string = make(chan string, runtime.NumCPU())

	files = []string{}
	bar := progressbar.Default(-1, "Finding plaintext files")
	//bar := progressbar.NewOptions(-1, progressbar.OptionSpinnerType(1), progressbar.OptionSetDescription("Finding plaintext files"), progressbar.OptionOnCompletion(func() {
	//	fmt.Printf("\n")
	//}))
	// start workers pool
	for cnt := 0; cnt < cap(jobs); cnt++ {
		wg.Add(1)
		go worker(cnt, &wg, jobs, results)
	}

	var rg sync.WaitGroup // results WaitGroup
	rg.Add(1)

	// start goroutine which collects files found by workers
	go func() {
		defer rg.Done()

		for ft := range results {
			files = append(files, ft)
		}
	}()

	// this goroutine walks through file systems and feeds workers with found files
	wg.Add(1)
	go func() {
		defer wg.Done()
		// since walking a file system has been completed signal workers that job has been finished
		defer close(jobs)

		_ = filepath.WalkDir(directory, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}

			if d.IsDir() && isExcluded(path, excludedDirs) {
				return filepath.SkipDir
			}

			if !d.IsDir() && d.Type().IsRegular() {
				jobs <- path
			}
			bar.Add(1)
			return nil
		})
	}()

	// waiting for workers and filepath.WalkDir() to finish
	wg.Wait()

	// let know goroutine collecting results from workers that we are done
	close(results)
	// wait for it to finish collecting found files
	rg.Wait()

	return files
}
