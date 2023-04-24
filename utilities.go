package main

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"runtime"
	"time"
)

func PrintMemUsage() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	// For info on each, see: https://golang.org/pkg/runtime/#MemStats
	fmt.Printf("Alloc = %v MiB", bToMb(m.Alloc))
	fmt.Printf("\tMallocs = %v MiB", bToMb(m.Mallocs))
	fmt.Printf("\tSys = %v MiB", bToMb(m.Sys))
	fmt.Printf("\tNumGC = %v\n", m.NumGC)
}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}

func timer(message string) func() {
	start := time.Now()
	return func() {
		fmt.Printf("%s %v\n", message, time.Since(start))
	}
}

// this function returns size of a variable
func getRealSizeOf(v interface{}) (int, error) {
	b := new(bytes.Buffer)
	if err := gob.NewEncoder(b).Encode(v); err != nil {
		return 0, err
	}
	return b.Len(), nil
}

// this function calculates size of a string slice
func sizeof(tbl []string) int {
	var size int
	for _, str := range tbl {
		strsize, err := getRealSizeOf(str)
		if err == nil {
			size += strsize
		}
	}

	// size in MiB
	return size / 1024 / 1024
}
