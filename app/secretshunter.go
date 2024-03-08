//go:build (linux && amd64) || darwin

// Copyright 2023 Henryk Hruszka
// SPDX-License-Identifier: AGPLv3
//
// This software is licensed under the GNU Affero General Public License v3.0 (AGPLv3). You
// are free to use, distribute, and modify this software under the terms of the AGPLv3. If you
// modify this software, any changes or improvements made must be made available to the
// community under the same license. This license also applies to any software that uses or is
// derived from this software. Please refer to the full text of the AGPLv3 for more details:
// https://www.gnu.org/licenses/agpl-3.0.html
//
// This code includes third-party packages that are subject to their respective licenses:
// - github.com/gabriel-vasile/mimetype is licensed under the MIT License. See https://github.com/gabriel-vasile/mimetype/blob/master/LICENSE for details.
// - gobyexample.com/rate-limiting is licensed under the CC BY 3.0.See https://github.com/mmcgrana/gobyexample#license.
// - github.com/dlclark/regexp2 is licensed under the Apache License, Version 2.0. See https://github.com/dlclark/regexp2/blob/master/LICENSE for details.
// Please review these licenses before using this code or these packages in your own projects.
package app

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/meryemchafry/go-cpulimit"
	"github.com/schollz/progressbar/v3"
	"log"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"unicode"

	//"secrethunter/cmd"
	"strings"
	"sync"
	"time"
)

const license string = `
Copyright 2023 Henryk Hruszka
SPDX-License-Identifier: AGPLv3

This software is licensed under the GNU Affero General Public License v3.0 (AGPLv3). You 
are free to use, distribute, and modify this software under the terms of the AGPLv3. If you 
modify this software, any changes or improvements made must be made available to the 
community under the same license. This license also applies to any software that uses or is 
derived from this software. Please refer to the full text of the AGPLv3 for more details: 
https://www.gnu.org/licenses/agpl-3.0.html

This code includes third-party packages that are subject to their respective licenses:
- github.com/gabriel-vasile/mimetype is licensed under the MIT License. See https://github.com/gabriel-vasile/mimetype/blob/master/LICENSE for details.
- gobyexample.com/rate-limiting is licensed under the CC BY 3.0.See https://github.com/mmcgrana/gobyexample#license.
- github.com/dlclark/regexp2 is licensed under the Apache License, Version 2.0. See https://github.com/dlclark/regexp2/blob/master/LICENSE for details.
Please review these licenses before using this code or these packages in your own projects.
`

type Options struct {
	FileWithPatterns string
	ReportFile       string
	ExcludedPaths    string
	CpuWorkloadLimit int
	MaxCPU           int
	ForceFlg         bool
	MinimumEntropy   float64
	MinimumLength    int
}

type Secret struct {
	SecretType  string
	SecretValue string
	LineNumber  int
}

type ScanResults struct {
	file    string
	secrets map[int]Secret
}

type ScanType int

const (
	PatternScan ScanType = iota
	Base64Scan
	EntropyScan
)

type App struct {
	scanType               ScanType
	fdout                  *os.File
	patternsFile           string
	maxNumberOfCpu         int
	maxCpuLoadLimit        int
	forceFlg               bool
	reportFile             string
	excludePathsFlag       string
	paths                  []string
	directories            []string // directories to scan
	excludedPaths          []string // directories and patterns to exclude
	files                  []string // files to scan
	limiter                *cpulimit.Limiter
	patterns               *Patterns
	ScanFileFunc           func(file string) *ScanResults
	passwordMinimumEntropy float64
	passwordMinimumLength  int
}

func NewApp(scanType ScanType, searchPaths []string, flags Options) *App {
	app := &App{fdout: os.Stdout}

	app.patternsFile = flags.FileWithPatterns
	app.maxNumberOfCpu = flags.MaxCPU
	app.maxCpuLoadLimit = flags.CpuWorkloadLimit
	app.excludePathsFlag = flags.ExcludedPaths
	app.forceFlg = flags.ForceFlg
	app.paths = searchPaths
	app.passwordMinimumLength = flags.MinimumLength
	app.passwordMinimumEntropy = flags.MinimumEntropy

	if flags.ReportFile != "" {
		app.reportFile = flags.ReportFile
	}

	app.scanType = scanType
	switch scanType {
	case PatternScan:
		app.ScanFileFunc = app.ScanFileWithRegex
	case Base64Scan:
		app.ScanFileFunc = app.ScanFileWithBase64
	case EntropyScan:
		app.ScanFileFunc = app.ScanFileWithEntropy
	default:
		app.ScanFileFunc = app.ScanFileWithRegex
	}

	app.directories = []string{}
	app.files = []string{}
	app.Init()

	return app
}

func (app *App) Init() {
	// future use
}

func (app *App) Start() {
	var err error

	log.SetFlags(0)

	if app.scanType == PatternScan {
		if len(app.patternsFile) == 0 {
			app.patterns, err = DefaultPatterns()
			if err != nil {
				log.Fatalf("[!!] Internal application error. Default secrets patterns cannot be initialized due to: %s\n", err.Error())
			}
			fmt.Printf("[*] No file with secret patterns provided, using default %d secret patterns\n", app.patterns.Num())
		} else {
			if _, err = os.Stat(app.patternsFile); os.IsNotExist(err) {
				log.Fatalf("[!!] Provided file with secret patterns cannot be accessed: %s\n", err.Error())
			}

			if app.patterns, err = NewPatterns(app.patternsFile); err != nil {
				log.Fatalf("[!!] Secret patterns cannot be loaded from the provided file %s due to %s\n", app.patternsFile, err.Error())
			}
			fmt.Printf("[*] Loaded %d secret patterns from %s file\n", app.patterns.Num(), app.patternsFile)
		}
	}

	if len(app.paths) == 0 {
		app.paths = append(app.paths, filepath.Join("/"))
		log.Printf("[+] No search paths provided, defaulting the search path to %s\n", strings.Join(app.paths, " "))
	}

	if app.maxCpuLoadLimit < 10 || app.maxCpuLoadLimit > 80 {
		log.Printf("[!!] Provided maximum CPU usage %d is not in the range from 10 to 80. Defaulting to 65.\n", app.maxCpuLoadLimit)
		app.maxCpuLoadLimit = 65
	}

	if app.maxNumberOfCpu < 1 || app.maxNumberOfCpu > runtime.NumCPU() {
		log.Printf("[!!] Provided number of %d vCPUs is not valid. Defaulting to the number of vCPUs on the system (%d vCPUs).\n", app.maxNumberOfCpu, runtime.NumCPU())
		app.maxNumberOfCpu = runtime.NumCPU()
	}

	app.verifyPaths()
	app.verifyExcludedPaths()

	if len(app.excludePathsFlag) == 0 {
		log.Printf("[+] No regular expressions provided for excluding file paths, using defaults ones:\n\t%s", strings.Join(app.excludedPaths, "\n\t"))
	}

	if app.reportFile != "Stdout" {
		app.fdout, err = os.Create(app.reportFile)
		if err != nil {
			fmt.Printf("[!!] Cannot create report file %s due to the error %s\n", app.reportFile, err.Error())
			fmt.Printf("[!!] Scan results will be printed to Stdout")
			app.fdout = os.Stdout
		} else {
			fmt.Printf("[*] Scan results will be saved to %s file\n", app.reportFile)
		}
	}

	// limit number of vCPUs used by the program
	runtime.GOMAXPROCS(app.maxNumberOfCpu)

	// configure limitter which limits CPU consumption by the program
	app.limiter = &cpulimit.Limiter{
		MaxCPUUsage:     float64(app.maxCpuLoadLimit),
		MeasureInterval: time.Millisecond * 333, // measure cpu usage in an interval of 333 ms
		Measurements:    3,                      // use the avg of the last 3 measurements
	}

	if !app.forceFlg {
		_ = app.limiter.Start()
	}
}

func (app *App) Stop() {
	_ = app.fdout.Close()
	if !app.forceFlg {
		app.limiter.Stop()
	}
}

func (app *App) verifyDirectories() {
	app.directories = append(app.directories, app.paths...)
	for idx, directory := range app.directories {
		if filepath.IsAbs(directory) {
			app.directories[idx] = filepath.Join(directory)
		} else {
			cwd, err := os.Getwd()
			if err != nil {
				log.Fatalln(err.Error())
			}
			app.directories[idx] = filepath.Join(cwd, directory)
		}

		info, err := os.Stat(app.directories[idx])
		if err != nil {
			log.Fatalf("[!!] Provided directory %s cannot be accessed due to error: %s\nAborting.\n", app.directories[idx], err.Error())
		}

		if !info.IsDir() {
			log.Fatalf("[!!] Provided path %s is not a directory. Aborting.\n", app.directories[idx])
		}
	}
}

func (app *App) verifyPaths() {
	for idx, path := range app.paths {
		if !filepath.IsAbs(path) {
			cwd, err := os.Getwd()
			if err != nil {
				log.Fatalln(err.Error())
			}
			app.paths[idx] = filepath.Join(cwd, path)
			path = app.paths[idx]
		}

		info, err := os.Stat(path)
		if err != nil {
			fmt.Printf("[!!] Provided path %s cannot be accessed due to error: %s\nSkipping.\n", path, err.Error())
			continue
		}

		if info.IsDir() {
			app.directories = append(app.directories, path)
		} else if info.Mode().IsRegular() {
			app.files = append(app.files, path)
		} else {
			fmt.Printf("[!!] Provided path %s is not a directory nor a file. Skipping.\n", app.directories[idx])
			continue
		}
	}
}

func (app *App) verifyExcludedPaths() {
	var patterns []string

	if len(app.excludePathsFlag) > 0 {
		patterns = strings.Split(app.excludePathsFlag, ",")
	} else {
		app.excludedPaths = defaultExcludePatterns
		return
	}

	for _, pattern := range patterns {
		filePath := pattern
		if _, err := os.Stat(filePath); !os.IsNotExist(err) {
			readFile, err := os.Open(filePath)

			if err != nil {
				//log.Fatalf("[!!] Cannot open file %s with path exclusion patterns due to error: %s. Aborting.\n", filePath, err)
				continue
			}

			fileScanner := bufio.NewScanner(readFile)
			fileScanner.Split(bufio.ScanLines)

			for fileScanner.Scan() {
				app.excludedPaths = append(app.excludedPaths, fileScanner.Text())
			}
			_ = readFile.Close()
		} else {
			app.excludedPaths = append(app.excludedPaths, pattern)
		}
	}
}

type RegexMatches struct {
	pattern *Pattern
	matches []string
}

func (app *App) scanWithRegex(text string) []RegexMatches {
	// TODO: it has to iterate through all patterns and return a slice with found patterns and matches
	//       since text line potentially can contain multiple patterns
	var foundMatches []RegexMatches

	for _, pattern := range app.patterns.Get() {
		if matches := pattern.CompiledRegex.FindAllString(text, -1); len(matches) > 0 {
			foundMatches = append(foundMatches, RegexMatches{pattern: &pattern, matches: matches})
		}

		if !app.forceFlg {
			app.limiter.Wait()
		}
	}
	return foundMatches
}

func (app *App) ScanFileWithRegex(file string) *ScanResults {
	f, err := os.Open(file)

	if err != nil && !os.IsNotExist(err) {
		log.Println(err.Error())
		return nil
	}
	defer func() { _ = f.Close() }()

	// Splits on newlines by default.
	scanner := bufio.NewScanner(f)

	line := 1
	foundSecrets := map[int]Secret{}

	for scanner.Scan() {
		foundMatches := app.scanWithRegex(scanner.Text())

		for _, found := range foundMatches {
			for _, match := range found.matches {
				foundSecrets[line] = Secret{SecretType: found.pattern.Name, SecretValue: match, LineNumber: line}
			}
		}
		line++
	}

	if len(foundSecrets) > 0 {
		return &ScanResults{file: file, secrets: foundSecrets}
	} else {
		return nil
	}
}

func calculateEntropy(s string) float64 {
	charCount := make(map[rune]float64)

	// Count the occurrences of each character
	for _, char := range s {
		charCount[char]++
	}

	// Calculate the entropy
	var entropy float64
	for _, count := range charCount {
		probability := count / float64(len(s))
		entropy += -probability * math.Log2(probability)
	}

	return entropy
}

func estimatePasswordEntropy(password string) float64 {
	charCount := make(map[rune]float64)
	var entropy float64
	charsetSize := 0
	hasLower := false
	hasUpper := false
	hasDigit := false
	hasSymbol := false

	for _, char := range password {
		switch {
		case unicode.IsLower(char) && !hasLower:
			hasLower = true
			charsetSize += 26
		case unicode.IsUpper(char) && !hasUpper:
			hasUpper = true
			charsetSize += 26
		case unicode.IsDigit(char) && !hasDigit:
			hasDigit = true
			charsetSize += 10
		case (unicode.IsPunct(char) || unicode.IsSymbol(char)) && !hasSymbol:
			hasSymbol = true
			charsetSize += 32 // Adjust based on the symbols you want to include
		}

		charCount[char]++
	}

	for _, count := range charCount {
		probability := count / float64(charsetSize)
		probability = probability * count / float64(len(password))
		entropy += -probability * math.Log2(probability)
	}

	//entropy := float64(len(password)) * math.Log2(float64(charsetSize))
	return entropy
}

func isPassword(password string, minEntropy float64, minLen int) bool {
	//const minimumEntropy = 60.0
	//const minimumLength = 12

	entropy := estimatePasswordEntropy(password)
	//entropy := calculateEntropy(password)

	// Check entropy, length, and character variety
	return entropy >= minEntropy && len(password) >= minLen
}

func (app *App) scanWithEntropy(text string) []string {
	var words []string = wordsRegex.Split(text, -1)
	var matches []string

	for _, word := range words {
		if isPassword(word, app.passwordMinimumEntropy, app.passwordMinimumLength) {
			matches = append(matches, word)
		}
	}
	return matches
}

func (app *App) ScanFileWithEntropy(file string) *ScanResults {
	f, err := os.Open(file)

	if err != nil && !os.IsNotExist(err) {
		log.Println(err.Error())
		return nil
	}
	defer func() { _ = f.Close() }()

	// Splits on newlines by default.
	scanner := bufio.NewScanner(f)

	line := 1
	foundSecrets := map[int]Secret{}

	for scanner.Scan() {
		matches := app.scanWithEntropy(scanner.Text())
		for _, match := range matches {
			foundSecrets[line] = Secret{SecretType: "entropy", SecretValue: match, LineNumber: line}
		}

		line++
	}

	if len(foundSecrets) > 0 {
		return &ScanResults{file: file, secrets: foundSecrets}
	} else {
		return nil
	}
}

func isBase64DecodedStringPrintable(s string) (string, error) {
	decodedBytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err // Not a valid base64 or other decode error
	}

	for _, b := range decodedBytes {
		if !unicode.IsPrint(rune(b)) || unicode.IsSymbol(rune(b)) || unicode.IsControl(rune(b)) {
			return "", errors.New("Decoded base64 string consists of non-printable charaters") // Contains non-printable characters
		}
	}

	return string(decodedBytes), nil // All characters are printable
}

func (app *App) scanWithBase64(text string) []string {
	var words []string = wordsRegex.Split(text, -1)
	var matches []string

	for _, word := range words {
		if len(word) >= 12 && base64Regex.MatchString(word) {
			decoded, err := isBase64DecodedStringPrintable(word)
			if err == nil {
				matches = append(matches, fmt.Sprintf("%s => %s", word, decoded))
			}
		}
	}
	return matches
}

func (app *App) ScanFileWithBase64(file string) *ScanResults {
	f, err := os.Open(file)

	if err != nil && !os.IsNotExist(err) {
		log.Println(err.Error())
		return nil
	}
	defer func() { _ = f.Close() }()

	// Splits on newlines by default.
	scanner := bufio.NewScanner(f)

	line := 1
	foundSecrets := map[int]Secret{}

	for scanner.Scan() {
		matches := app.scanWithBase64(scanner.Text())
		for _, match := range matches {
			foundSecrets[line] = Secret{SecretType: "base64", SecretValue: match, LineNumber: line}
		}

		line++
	}

	if len(foundSecrets) > 0 {
		return &ScanResults{file: file, secrets: foundSecrets}
	} else {
		return nil
	}
}

func (app *App) worker(wg *sync.WaitGroup, jobs chan string, scans chan *ScanResults, bar *progressbar.ProgressBar) {
	defer wg.Done()

	for file := range jobs {
		if scan := app.ScanFileFunc(file); scan != nil {
			scans <- scan
		}
		_ = bar.Add(1)
	}
}

func (app *App) ScanFiles(files []string) ([]*ScanResults, int) {
	var wg sync.WaitGroup
	var jobs = make(chan string, app.maxNumberOfCpu)
	var scans = make(chan *ScanResults, 50)
	var secretsCount int

	// calculate how long it took  to scan a file system
	defer timer("\n[+] Finished scanning files in")()

	fmt.Printf("[*] Started scanning %d files.\n", len(files))

	// start progress bar
	bar := progressbar.Default(int64(len(files)), "Scanning progress")

	for cnt := 0; cnt < cap(jobs); cnt++ {
		wg.Add(1)
		go app.worker(&wg, jobs, scans, bar)
	}

	var rg sync.WaitGroup // results WaitGroup
	rg.Add(1)

	// start goroutine which collects secrets found by workers
	var secrets []*ScanResults
	go func(secrets *[]*ScanResults, secretsFound *int) {
		defer rg.Done()

		for scan := range scans {
			*secretsFound += len(scan.secrets)
			*secrets = append(*secrets, scan)
		}
	}(&secrets, &secretsCount)

	wg.Add(1)

	// start goroutine which feeds workers with found files
	go func() {
		defer close(jobs)
		defer wg.Done()

		for _, file := range files {
			jobs <- file
		}
	}()

	wg.Wait()
	close(scans)
	rg.Wait()

	return secrets, secretsCount
}

func (app *App) GetFiles() (files []string, excludedPaths []string) {

	files = make([]string, len(app.files))

	copy(files, app.files)

	// start processing files
	for _, directory := range app.directories {
		fmt.Printf("[*] Processing directory %s\n", directory)

		// find plain text files a directory
		fndfiles, expaths := func() ([]string, []string) {
			message := fmt.Sprintf("\n[+] Finished scanning %s for files in", directory)
			defer timer(message)()
			return getFileList(directory, app.excludedPaths)
		}()

		if len(fndfiles) >= 0 {
			fmt.Printf("[+] Found %d files in %s\n", len(fndfiles), directory)
			files = append(files, fndfiles...)
		} else {
			fmt.Printf("[-] Nothing to scan in %s\n", directory)
		}

		if len(expaths) > 0 {
			fmt.Printf("[+] %d paths were excluded based on provided patterns\n", len(expaths))
			excludedPaths = expaths
		}
	}
	return files, excludedPaths
}

func (app *App) GenReport(scans []*ScanResults, secretsFound int, excludedPaths []string) {
	if len(scans) > 0 {
		if app.reportFile != "Stdout" {
			fmt.Printf("[+] Found %d secrets in %d files\n", secretsFound, len(scans))
		}

		_, _ = fmt.Fprintf(app.fdout, "[+] Found %d secrets in %d files\n", secretsFound, len(scans))
		// deliver scan results
		for _, scan := range scans {
			_, _ = fmt.Fprintf(app.fdout, "[+] Found %d secret(s) in %s file\n", len(scan.secrets), scan.file)
			for _, secret := range scan.secrets {
				_, _ = fmt.Fprintf(app.fdout, "\tLine: %d %s: %q\n", secret.LineNumber, secret.SecretType, secret.SecretValue)
			}
		}

		_, _ = fmt.Fprintf(app.fdout, "\n\n[*] Following files have to be reviewed to determine impact of found secrets\n")
		// list files with found secrets
		for _, scan := range scans {
			_, _ = fmt.Fprintf(app.fdout, "\t%s\n", printFileInfo(scan.file))
		}
	} else {
		if app.reportFile != "Stdout" {
			fmt.Printf("[-] No secrets found\n")
		}
		_, _ = fmt.Fprintf(app.fdout, "[-] No secrets found\n")
	}

	if len(excludedPaths) > 0 {
		_, _ = fmt.Fprintf(app.fdout, "\n\n[*] Following paths were excluded from a scan based on the provided patterns\n")
		for _, exPath := range excludedPaths {
			_, _ = fmt.Fprintf(app.fdout, "\t%s\n", exPath)
		}
	}
}

func Run(app *App) {
	var files []string
	var excludedPaths []string

	app.Start()
	defer app.Stop()

	// look for secrets in found files
	files, excludedPaths = app.GetFiles()
	scans, secretsFound := app.ScanFiles(files)
	app.GenReport(scans, secretsFound, excludedPaths)
}
