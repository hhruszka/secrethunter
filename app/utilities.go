package app

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
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
		fmt.Printf("%s %dms\n", message, time.Since(start).Milliseconds())
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

func CompressEntropy(entropy map[CharStats]Entropy) []byte {
	// Serialize the slice
	type entropy2json struct {
		Key CharStats
		Val Entropy
	}

	var jsonEntropy = make([]entropy2json, len(entropy))
	for key, val := range entropy {
		jsonEntropy = append(jsonEntropy, entropy2json{Key: key, Val: val})
	}

	serializedData, err := json.Marshal(jsonEntropy)
	if err != nil {
		panic(err)
	}

	// Compress the serialized data
	var compressedData bytes.Buffer
	gz := gzip.NewWriter(&compressedData)
	if _, err := gz.Write(serializedData); err != nil {
		panic(err)
	}
	if err := gz.Close(); err != nil {
		panic(err)
	}

	return compressedData.Bytes()
}

func uncompressEntropy(data []byte) map[CharStats]Entropy {
	// Serialize the slice
	type entropy2json struct {
		Key CharStats
		Val Entropy
	}

	fmt.Printf("[+] Got %d bytes to decompres\n", len(data))
	var uncompressedData bytes.Buffer
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	if n, err := io.Copy(&uncompressedData, gz); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	} else {
		fmt.Printf("[+] Uncompressed to %d bytes of data\n", n)
	}
	if err := gz.Close(); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	var jsonEntropy = make([]entropy2json, 0)

	err = json.Unmarshal(uncompressedData.Bytes(), &jsonEntropy)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	var entropy map[CharStats]Entropy = make(map[CharStats]Entropy)
	for _, entry := range jsonEntropy {
		entropy[entry.Key] = entry.Val
	}
	return entropy
}

func Save(filename string, data []byte) {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	defer func() { _ = file.Close() }()

	if err := binary.Write(file, binary.LittleEndian, int32(len(data))); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	if err := binary.Write(file, binary.LittleEndian, data); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}

func read(res fs.FS, fileName string) [][]byte {
	resFile, err := res.Open(fileName)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	defer func() { _ = resFile.Close() }()

	reader := bufio.NewReader(resFile)

	var data [][]byte
	var length int32

	lines := 0
	for {
		if err := binary.Read(reader, binary.LittleEndian, &length); err == io.EOF {
			break
		}

		data = append(data, make([]byte, length))
		if n, err := io.ReadFull(reader, data[lines]); err == nil {
			fmt.Printf("[+] Read %d bytes\n", n)
		}
		lines += 1

	}
	return data
}
