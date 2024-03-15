package app

import (
	"bufio"
	"embed"
	"log"
	"math"
	"os"
	"slices"
	"strings"
	"unicode"
)

// https://owasp.org/www-community/password-special-characters
var Symbols = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

//go:embed data/entropy.txt
var res embed.FS

type CharStats struct {
	Lowers  int `json:"Lowers"`
	Uppers  int `json:"Uppers"`
	Digits  int `json:"Digits"`
	Symbols int `json:"Symbols"`
}

func (s CharStats) len() int {
	return s.Digits + s.Uppers + s.Lowers + s.Symbols
}

type Entropy struct {
	Avg float64 `json:"Avg"`
	Min float64 `json:"Min"`
	Max float64 `json:"Max"`
}

func init() {
	data := read(res, "data/entropy.txt")

	entropySetWords = uncompressEntropy(data[0])
	entropySetBreaches = uncompressEntropy(data[1])
	entropySetGen = uncompressEntropy(data[2])

	//fmt.Printf("[+] entropySetWords set has %d entries\n", len(entropySetWords))
	//fmt.Printf("[+] entropySetBreaches set has %d entries\n", len(entropySetBreaches))
	//fmt.Printf("[+] entropySetGen set has %d entries\n", len(entropySetGen))
}

func charStats(word string) CharStats {
	var stats CharStats
	for _, char := range word {
		switch {
		case unicode.IsLower(char):
			stats.Lowers++
		case unicode.IsUpper(char):
			stats.Uppers++
		case unicode.IsDigit(char):
			stats.Digits++
		case strings.ContainsRune(Symbols, char):
			stats.Symbols++
		default:
			continue
		}
	}

	return stats
}

func calculateEntropyOne(s string) float64 {
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

func calculateEntropyTwo(word string) float64 {
	charCount := make(map[rune]float64)
	var entropy float64
	charsetSize := 0
	hasLower := false
	hasUpper := false
	hasDigit := false
	hasSymbol := false

	for _, char := range word {
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
		//probability = probability * count / float64(len(word))
		entropy += -probability * math.Log2(probability)
	}

	//entropy := float64(len(word)) * math.Log2(float64(charsetSize))
	return entropy
}

func isPassword(word string, entropyFunc func(string) float64, entropy float64) bool {
	return entropyFunc(word) > entropy
}

func (app *App) scanWithEntropyOne(text string, minLen int, maxLen int, entropyset map[int]Entropy, entropyFunc func(string) float64) []string {
	var words []string = wordsRegex.Split(text, -1)
	var matches []string

	for _, word := range words {
		// TODO:
		// - replace it with a set of checkers
		// - checkers should verify the semantics of a word:
		//   - is it a file path
		//   - if it is a path file, does it exist?
		//   - is a date
		//   - it does not contain symbols and special characters
		//   - entropy is within a range - how to compare entropy of a word and a password?
		//   - categorization could be done by ML

		if len(word) >= minLen && len(word) <= maxLen && isPassword(word, entropyFunc, entropyset[len(word)].Avg) {
			matches = append(matches, word)
		}
	}
	return matches
}

func (app *App) ScanFileWithEntropyOne(file string, entropySet map[int]Entropy, entropyFunc func(string) float64) *ScanResults {
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

	var keys []int
	for key := range entropySet {
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

	for scanner.Scan() {
		matches := app.scanWithEntropyOne(scanner.Text(), minLen, maxLen, entropySet, entropyFunc)
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

func (app *App) scanWithEntropyTwo(text string, minLen int, maxLen int, entropySet map[CharStats]Entropy, entropyFunc func(string) float64) []string {
	var words []string = wordsRegex.Split(text, -1)
	var matches []string

	for _, word := range words {
		if _, found := entropySet[charStats(word)]; !found {
			continue
		}

		if len(word) >= minLen && len(word) <= maxLen && isPassword(word, entropyFunc, entropySet[charStats(word)].Avg) {
			matches = append(matches, word)
		}
	}
	return matches
}

func (app *App) ScanFileWithEntropyTwo(file string, entropySet map[CharStats]Entropy, entropyFunc func(string) float64) *ScanResults {
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

	var keys []CharStats
	for key := range entropySet {
		keys = append(keys, key)
	}

	minLen := 32
	maxLen := 8

	for _, key := range keys {
		keyLen := key.len()
		if keyLen > maxLen && keyLen <= 32 {
			maxLen = keyLen
		}

		if keyLen < minLen && keyLen >= 8 {
			minLen = keyLen
		}
	}

	for scanner.Scan() {
		matches := app.scanWithEntropyTwo(scanner.Text(), minLen, maxLen, entropySet, entropyFunc)
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

func (app *App) ScanFileWithEntropy(file string) *ScanResults {
	//return app.ScanFileWithEntropyOne(file, entropySetOne, calculateEntropyOne)
	return app.ScanFileWithEntropyTwo(file, entropySetWords, calculateEntropyOne)
}
