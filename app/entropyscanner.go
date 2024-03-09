package app

import (
	"bufio"
	"log"
	"math"
	"os"
	"unicode"
)

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
