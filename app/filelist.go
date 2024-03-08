package app

import (
	"github.com/gabriel-vasile/mimetype"
	"github.com/schollz/progressbar/v3"
	"io/fs"
	"log"
	"path/filepath"
	"regexp"
	"runtime"
	"sync"
)

// workers will use mimetype to determine a file type and decide whether to collect it
func worker(id int, wg *sync.WaitGroup, jobs chan string, results chan string) {
	defer wg.Done()

	for fp := range jobs {
		fm, err := mimetype.DetectFile(fp)

		if fm.Is("application/octet-stream") {
			continue
		}

		if err == nil {
			for mtype := fm; mtype != nil; mtype = mtype.Parent() {
				if mtype.Is("text/plain") {
					results <- fp
				}
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

func isExcludedRegEx(path string, patterns []string) (excluded bool) {
	excluded = false
	for _, pattern := range patterns {
		if reg, err := regexp.Compile(pattern); err != nil {
			log.Printf("[!!] Encounter error when processing regular expression for excluding paths: %s\n", err.Error())
		} else if match := reg.FindStringSubmatch(path); len(match) > 0 {
			//log.Printf("[-] Excluded file: %s by pattern: %s\n", path, pattern)
			excluded = true
		}
	}
	return excluded
}

func getFileList(directory string, paths2exclude []string) (files []string, excludedPaths []string) {
	var wg sync.WaitGroup
	var results chan string = make(chan string, 1000)
	var excluded chan string = make(chan string, 100)
	var jobs chan string = make(chan string, runtime.NumCPU())

	files = []string{}
	excludedPaths = []string{}

	bar := progressbar.Default(-1, "Finding plaintext files")

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

	var ex sync.WaitGroup
	ex.Add(1)

	go func() {
		defer ex.Done()

		for ep := range excluded {
			excludedPaths = append(excludedPaths, ep)
		}
	}()

	// this goroutine walks through file systems and feeds workers with found files
	wg.Add(1)
	go func() {
		defer wg.Done()
		// since walking a file system has been completed signal workers that job has been finished
		defer close(jobs)
		defer close(excluded)

		_ = filepath.WalkDir(directory, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}

			if d.IsDir() && isExcludedRegEx(path, paths2exclude) {
				excluded <- path
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
	ex.Wait()

	// let know goroutine collecting results from workers that we are done
	close(results)
	// wait for it to finish collecting found files
	rg.Wait()

	return files, excludedPaths
}
