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
package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/meryemchafry/go-cpulimit"
	"github.com/schollz/progressbar/v3"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
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

type Secret struct {
	SecretType  string
	SecretValue string
	LineNumber  int
}

type ScanResults struct {
	file    string
	secrets map[int]Secret
}

type App struct {
	fdout           *os.File
	patternsFile    *string
	maxNumberOfCpu  *int
	maxCpuLoadLimit *float64
	outFile         *string
	excludeDirsFlag *string
	directories     []string
	excludedDirs    []string
	limiter         *cpulimit.Limiter
	patterns        *Patterns
	versionFlg      *bool
	helpFlg         *bool
}

func NewApp() *App {
	app := &App{fdout: os.Stdout}
	app.Init()

	return app
}

func (app *App) Init() {
	app.patternsFile = flag.String("p", "", "file with patterns - mandatory. Patterns can be found on https://github.com/mazen160/secrets-patterns-db")
	app.maxNumberOfCpu = flag.Int("c", runtime.NumCPU(), "maximum number of vCPUs to be used by a program - optional")
	app.maxCpuLoadLimit = flag.Float64("t", 80, "throttling:q range from 10 to 80 denoting maximum CPU usage (%) that the\nsystem cannot exceed during execution of the program - optional")
	app.outFile = flag.String("o", "Stdout", "output file - optional")
	app.excludeDirsFlag = flag.String("x", "", "comma seperated list of directories to exclude during the scan")
	app.versionFlg = flag.Bool("v", false, "prints version information")
	app.helpFlg = flag.Bool("h", false, "prints help")
	flag.Usage = app.usage
	flag.Parse()
	app.directories = flag.Args()

	if len(*app.excludeDirsFlag) > 0 {
		app.excludedDirs = strings.Split(*app.excludeDirsFlag, ",")
	}
}

func (app *App) usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] \"space seperated directories to scan\"\n", filepath.Base(os.Args[0]))
	flag.PrintDefaults()
	os.Exit(2)
}

func (app *App) version() {
	fmt.Println("Version 1.0 Released 04.2023")
	fmt.Printf(license)

	//	fmt.Printf(`Copyright 2023 Henryk Hruszka
	//SPDX-License-Identifier: AGPLv3
	//
	//This software is provided "as is" and the author disclaims all warranties
	//with regard to this software including all implied warranties of
	//merchantability and fitness. In no event shall the author be liable for any
	//special, direct, indirect, or consequential damages or any damages
	//whatsoever resulting from loss of use, data or profits, whether in an
	//action of contract, negligence or other tortious action, arising out of or
	//in connection with the use or performance of this software.
	//	`)
	//
	//	fmt.Printf(`
	//This code includes third-party packages that are subject to their respective licenses:
	//- github.com/gabriel-vasile/mimetype is licensed under the MIT License. See https://github.com/gabriel-vasile/mimetype/blob/master/LICENSE for details.
	//- gobyexample.com/rate-limiting is licensed under the CC BY 3.0.See https://github.com/mmcgrana/gobyexample#license.
	//- github.com/dlclark/regexp2 is licensed under the Apache License, Version 2.0. See https://github.com/dlclark/regexp2/blob/master/LICENSE for details.
	//Please review these licenses before using this code or these packages in your own projects.
	//	`)
}

func (app *App) Start() {
	var err error

	log.SetFlags(0)

	if *app.versionFlg {
		app.version()
		os.Exit(0)
	}
	// check if a minimum set of parameters was passed to the program
	if len(*app.patternsFile) == 0 || len(app.directories) == 0 {
		app.usage()
	}

	if _, err = os.Stat(*app.patternsFile); os.IsNotExist(err) {
		log.Fatalf("[!!] Provided file with patterns cannot be accessed: %s\n", err.Error())
	}

	if *app.maxCpuLoadLimit < 10 || *app.maxCpuLoadLimit > 80 {
		log.Fatalf("[!!] Provided maximum CPU usage %d is not in the range from 10 to 80: %s\n", *app.maxCpuLoadLimit)
	}

	if *app.maxNumberOfCpu < 1 || *app.maxNumberOfCpu > runtime.NumCPU() {
		log.Fatalf("[!!] Provided number of vCPUs %d is not in the range from 1 to %d.\n", *app.maxNumberOfCpu, runtime.NumCPU())
	}

	app.verifyDirectories()
	app.verifyExcludedDirectories()

	if app.patterns, err = NewPatterns(*app.patternsFile); err != nil {
		log.Fatalln(err.Error())
	}

	fmt.Printf("[*] Loaded %d patterns from %s file\n", app.patterns.Num(), *app.patternsFile)

	if *app.outFile != "Stdout" {
		app.fdout, err = os.Create(*app.outFile)
		if err != nil {
			log.Fatalln(err.Error())
		}
		fmt.Printf("[*] Scan results will be saved to %s file\n", *app.outFile)
	}

	// limit number of vCPUs used by the program
	runtime.GOMAXPROCS(*app.maxNumberOfCpu)

	// configure limitter which limits CPU consumption by the program
	app.limiter = &cpulimit.Limiter{
		MaxCPUUsage:     *app.maxCpuLoadLimit,   // throttle CPU usage to 50%
		MeasureInterval: time.Millisecond * 333, // measure cpu usage in an interval of 333 ms
		Measurements:    3,                      // use the avg of the last 3 measurements
	}

	app.limiter.Start()
}

func (app *App) Stop() {
	app.fdout.Close()
	app.limiter.Stop()
}

func (app *App) verifyDirectories() {
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

func (app *App) verifyExcludedDirectories() {
	for idx, dir := range app.excludedDirs {
		if filepath.IsAbs(dir) {
			app.excludedDirs[idx] = filepath.Join(dir)
		} else {
			cwd, err := os.Getwd()
			if err != nil {
				log.Fatalln(err.Error())
			}
			app.excludedDirs[idx] = filepath.Join(cwd, dir)
		}

		if info, err := os.Stat(app.excludedDirs[idx]); err != nil || !info.IsDir() {
			log.Fatalf("[!!] Provided directory %s does not exist. Aborting.\n", app.directories[idx])
		}
	}
}

func (app *App) scanWithRegex(text string) (*Pattern, *string) {
	for _, pattern := range app.patterns.Get() {
		if reg, err := regexp.Compile(pattern.Regex); err != nil {
			log.Println(err.Error())
		} else if match := reg.FindStringSubmatch(text); len(match) > 0 {
			return &pattern, &match[0]
		}
		app.limiter.Wait()
	}
	return nil, nil
}

func (app *App) scanFile(file string) *ScanResults {
	f, err := os.Open(file)

	if err != nil && !os.IsNotExist(err) {
		log.Println(err.Error())
		return nil
	}
	defer f.Close()

	// Splits on newlines by default.
	scanner := bufio.NewScanner(f)

	//buf := make([]byte, 0, 64*1024)
	//scanner.Buffer(buf, 1024*1024)

	line := 1
	foundSecrets := map[int]Secret{}

	for scanner.Scan() {
		if pattern, match := app.scanWithRegex(scanner.Text()); pattern != nil {
			foundSecrets[line] = Secret{SecretType: pattern.Name, SecretValue: *match, LineNumber: line}
		}
		line++
	}

	if len(foundSecrets) > 0 {
		return &ScanResults{file: file, secrets: foundSecrets}
	} else {
		return nil
	}
}

func (app *App) worker(id int, wg *sync.WaitGroup, jobs chan string, scans chan *ScanResults, bar *progressbar.ProgressBar) {
	defer wg.Done()

	for file := range jobs {
		if scan := app.scanFile(file); scan != nil {
			scans <- scan
		}
		bar.Add(1)
	}
}

func (app *App) ScanFiles(files []string) ([]*ScanResults, int) {
	var wg sync.WaitGroup
	var jobs chan string = make(chan string, *app.maxNumberOfCpu)
	var scans chan *ScanResults = make(chan *ScanResults, 50)
	var secretsCount int

	// calculate how long it took  to scan a file system
	defer timer("\n[+] Finished scanning files in")()

	fmt.Printf("[*] Started scanning %d files.\n", len(files))

	// start progress bar
	bar := progressbar.Default(int64(len(files)), "Scanning progress")
	//bar := progressbar.NewOptions(len(files), progressbar.OptionSetDescription("Scanning progress"), progressbar.OptionOnCompletion(func() {
	//	fmt.Printf("\n")
	//}))
	// start workers pool
	for cnt := 0; cnt < cap(jobs); cnt++ {
		wg.Add(1)
		go app.worker(cnt, &wg, jobs, scans, bar)
	}

	var rg sync.WaitGroup // results WaitGroup
	rg.Add(1)

	// start goroutine which collects secrets found by workers
	secrets := []*ScanResults{}
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

func main() {

	app := NewApp()
	app.Start()
	defer app.Stop()

	// start processing files
	for _, directory := range app.directories {
		fmt.Printf("[*] Processing directory %s\n", directory)

		// find plain text files a directory
		files := func() []string {
			message := fmt.Sprintf("\n[+] Finished scanning %s for files in", directory)
			defer timer(message)()
			return getFileList(directory, app.excludedDirs)
		}()

		fmt.Printf("[+] Found %d files in %s\n", len(files), directory)

		if len(files) == 0 {
			fmt.Printf("[-] Nothing to scan in %s\n", directory)
			continue
		}

		// look for secrets in found files
		scans, secretsFound := app.ScanFiles(files)

		if len(scans) > 0 {
			fmt.Printf("[+] Found %d secrets in %d files in %s directory\n", secretsFound, len(scans), directory)
		} else {
			fmt.Printf("[-] No secrets found in %s directory\n", directory)
			continue
		}

		// deliver scan results
		for _, scan := range scans {
			fmt.Fprintf(app.fdout, "[+] Found %d secret(s) in %s file\n", len(scan.secrets), scan.file)
			for _, secret := range scan.secrets {
				fmt.Fprintf(app.fdout, "\tLine: %d %s: %q\n", secret.LineNumber, secret.SecretType, secret.SecretValue)
			}
		}
	}
}
