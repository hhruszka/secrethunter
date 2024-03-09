package app

import (
	"bufio"
	"log"
	"os"
)

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
