package app

import (
	"bufio"
	"compress/gzip"
	"embed"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

// https://owasp.org/www-community/password-special-characters
var Symbols = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

//go:embed data/*
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

type EntropyStats struct {
	Avg float64 `json:"Avg"`
	Dev float64 `json:"Dev"`
	Min float64 `json:"Min"`
	Max float64 `json:"Max"`
}

type EntropySet struct {
	Min int
	Max int
	Set map[CharStats]EntropyStats
}

func (es *EntropySet) MinMax() (int, int) {
	var keys []CharStats
	for key := range es.Set {
		keys = append(keys, key)
	}

	es.Min = 32
	es.Max = 8

	for _, key := range keys {
		keyLen := key.len()
		if keyLen > es.Max && keyLen <= 32 {
			es.Max = keyLen
		}

		if keyLen < es.Min && keyLen >= 8 {
			es.Min = keyLen
		}
	}

	return es.Min, es.Max
}

func NewEntropySet(dataSet map[CharStats]EntropyStats) *EntropySet {
	es := EntropySet{Set: dataSet}
	es.MinMax()
	return &es
}

func init() {
	data := read(res, "data/entropy.txt")

	entropySetWords = NewEntropySet(uncompressEntropy(data[0]))
	entropySetBreaches = NewEntropySet(uncompressEntropy(data[1]))
	entropySetGen = NewEntropySet(uncompressEntropy(data[2]))

	file, err := res.Open("data/words.txt.gz")
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	gz, err := gzip.NewReader(file)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	defer func() { _ = gz.Close() }()

	var word string
	scanner := bufio.NewScanner(gz)
	for scanner.Scan() {
		word = scanner.Text()

		//dictionary = append(dictionary, line)
		dictionary[word] = 0
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("Failed to read: %v", err)
	}
	fmt.Printf("[+] Loaded %d words of English dictionary\n", len(dictionary))
	fmt.Printf("[+] entropySetWords set has %d entries\n", len(entropySetWords.Set))
	fmt.Printf("[+] entropySetBreaches set has %d entries\n", len(entropySetBreaches.Set))
	fmt.Printf("[+] entropySetGen set has %d entries\n", len(entropySetGen.Set))
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

func PasswordCheckerZero(word string) bool {
	if stats := charStats(word); stats.Digits == 0 && stats.Symbols == 0 {
		return false
	}
	return true
}

func PasswordCheckerOne(word string) bool {
	if stats := charStats(word); stats.Uppers == 0 && stats.Digits == 0 && stats.Symbols == 0 {
		return false
	}
	return true
}

func PasswordCheckerTwo(word string) bool {
	if filepath.IsAbs(word) {
		return false
	}
	return true
}

func PasswordCheckerThree(word string) bool {
	if filepath.IsAbs(word) {
		if _, err := os.Stat(word); err == nil {
			return true
		}
	}
	return false
}

func PasswordCheckFour(word string) bool {
	for _, reg := range timeRegexes {
		if reg.MatchString(word) {
			return false
		}
	}
	return true
}

func PasswordCheckerFive(word string) bool {
	if _, found := dictionary[word]; found {
		dictionary[word] += 1
		return false
	}
	return true
}

func PasswordCheckerSix(word string) bool {
	if _, found := dictionary[strings.ToTitle(word)]; found {
		dictionary[word] += 1
		return false
	}
	return true
}

func PasswordEntropyChecker(word string, entropySet *EntropySet, entropyFunc func(string) float64) bool {
	var entropy EntropyStats
	var found bool

	if entropy, found = entropySet.Set[charStats(word)]; !found {
		return false
	}

	return (entropyFunc(word) - entropy.Avg) > entropy.Dev
}

func isPassword(word string, entropyFunc func(string) float64) bool {
	// TODO:
	// - replace it with a set of checkers
	// - checkers should verify the semantics of a word:
	//   - is it a file path
	//   - if it is a path file, does it exist?
	//   - is a date
	//   - it does not contain symbols and special characters
	//   - entropy is within a range - how to compare entropy of a word and a password?
	//   - categorization could be done by ML
	return false
}

func (app *App) scanWithEntropyTwo(text string, entropyFunc func(string) float64) []string {
	var words []string = wordsRegex.Split(text, -1)
	var matches []string

	for _, word := range words {
		if _, found := entropySetBreaches.Set[charStats(word)]; !found {
			continue
		}

		if isPassword(word, entropyFunc) {
			matches = append(matches, word)
		}
	}
	return matches
}

func (app *App) ScanFileWithEntropyTwo(file string, entropyFunc func(string) float64) *ScanResults {
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
		matches := app.scanWithEntropyTwo(scanner.Text(), entropyFunc)
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
	//return app.ScanFileWithEntropyTwo(file, calculateEntropyOne)
	return nil
}

//func (app *App) scanWithEntropyOne(text string, minLen int, maxLen int, entropyset map[int]EntropyStats, entropyFunc func(string) float64) []string {
//	var words []string = wordsRegex.Split(text, -1)
//	var matches []string
//
//	for _, word := range words {
//		if len(word) >= minLen && len(word) <= maxLen && isPassword(word, entropyFunc, entropyset[len(word)].Avg) {
//			matches = append(matches, word)
//		}
//	}
//	return matches
//}
//
//func (app *App) ScanFileWithEntropyOne(file string, entropySet map[int]EntropyStats, entropyFunc func(string) float64) *ScanResults {
//	f, err := os.Open(file)
//
//	if err != nil && !os.IsNotExist(err) {
//		log.Println(err.Error())
//		return nil
//	}
//	defer func() { _ = f.Close() }()
//
//	// Splits on newlines by default.
//	scanner := bufio.NewScanner(f)
//
//	line := 1
//	foundSecrets := map[int]Secret{}
//
//	var keys []int
//	for key := range entropySet {
//		keys = append(keys, key)
//	}
//
//	maxLen := slices.Max(keys)
//	if maxLen > 32 {
//		maxLen = 32
//	}
//
//	minLen := slices.Min(keys)
//	if minLen < 8 {
//		minLen = 8
//	}
//
//	for scanner.Scan() {
//		matches := app.scanWithEntropyOne(scanner.Text(), minLen, maxLen, entropySet, entropyFunc)
//		for _, match := range matches {
//			foundSecrets[line] = Secret{SecretType: "entropy", SecretValue: match, LineNumber: line}
//		}
//
//		line++
//	}
//
//	if len(foundSecrets) > 0 {
//		return &ScanResults{file: file, secrets: foundSecrets}
//	} else {
//		return nil
//	}
//}
