package app

import (
	"bufio"
	"log"
	"math"
	"os"
	"slices"
	"strings"
	"unicode"
)

type Entropy struct {
	Avg float64 `json:"Avg"`
	Min float64 `json:"Min"`
	Max float64 `json:"Max"`
}

// https://owasp.org/www-community/password-special-characters
var Symbols = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

type CharStats struct {
	lowers  int
	uppers  int
	digits  int
	symbols int
}

func charStats(word string) CharStats {
	var stats CharStats
	for _, char := range word {
		switch {
		case unicode.IsLower(char):
			stats.lowers++
		case unicode.IsUpper(char):
			stats.uppers++
		case unicode.IsDigit(char):
			stats.digits++
		case strings.ContainsRune(Symbols, char):
			stats.symbols++
		default:
			continue
		}
	}

	//stats.entropy = calculateEntropy(word)

	return stats
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

func isPassword(password string, entropyFunc func(string) float64, entropy float64) bool {
	return entropyFunc(password) > entropy
}

func (app *App) scanWithEntropy(text string, entropyset map[V]Entropy, entropyFunc func(string) float64) []string {
	var words []string = wordsRegex.Split(text, -1)
	var matches []string

	var keys []int
	for key := range entropyset {
		keys = append(keys, key)
	}

	maxLen := slices.Max(keys)
	if maxLen > 32 {
		maxLen = 32
	}

	minLen := slices.Min(keys)
	if minLen < 8 {
		minLen = 8
	}

	for _, word := range words {
		if len(word) >= minLen && len(word) <= maxLen && isPassword(word, entropyFunc, entropyset[len(word)].Avg) {
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
		matches := app.scanWithEntropy(scanner.Text(), entropySetOne, calculateEntropy)
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
