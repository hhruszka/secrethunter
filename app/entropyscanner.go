package app

import (
	"bufio"
	"embed"
	"fmt"
	"golang.org/x/exp/utf8string"
	"log"
	"math"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

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

// https://owasp.org/www-community/password-special-characters
var Symbols = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

//go:embed data/*
var res embed.FS

var (
	entropySetWords    *EntropySet
	entropySetBreaches *EntropySet
	entropySetGen      *EntropySet
)

var (
	EnglishDictionary map[string]int = make(map[string]int)
	BreachedPasswords map[string]int = make(map[string]int)
	LinuxWords        map[string]int = make(map[string]int)
)

func init() {
	var (
		data  [][]byte
		lines []string
		err   error
	)

	data, err = ReadBinaryFile(res, "data/entropy.txt")
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	entropySetWords = NewEntropySet(uncompressEntropy(data[0]))
	entropySetBreaches = NewEntropySet(uncompressEntropy(data[1]))
	entropySetGen = NewEntropySet(uncompressEntropy(data[2]))

	lines, err = ReadAll("data/words.txt.gz")
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	for _, line := range lines {
		EnglishDictionary[line] = 0
	}

	lines, err = ReadAll("data/passwords.txt.gz")
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	for _, line := range lines {
		BreachedPasswords[line] = 0
	}

	lines, err = ReadAll("data/linuxwords.txt.gz")
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	for _, line := range lines {
		LinuxWords[line] = 0
	}

	fmt.Printf("[+] Loaded %d words of English dictionary\n", len(EnglishDictionary))
	fmt.Printf("[+] Loaded %d words of breached passwords\n", len(BreachedPasswords))
	fmt.Printf("[+] Loaded %d words of linux words\n", len(LinuxWords))
	fmt.Printf("[+] entropySetWords set has %d entries\n", len(entropySetWords.Set))
	fmt.Printf("[+] entropySetBreaches set has %d entries\n", len(entropySetBreaches.Set))
	fmt.Printf("[+] entropySetGen set has %d entries\n", len(entropySetGen.Set))
}

// charStats
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

// calculateEntropyOne calculates entropy of a word
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

// calculateEntropyTwo calculates entropy of a word
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

// PasswordCheckerZero checks if a word is just a bunch of lowercase letters and thus unlikely to be a password
func PasswordCheckerZero(word string) bool {
	if stats := charStats(word); stats.Uppers == 0 && stats.Digits == 0 && stats.Symbols == 0 {
		return true
	}
	return false
}

// PasswordCheckerOne checks if a word is a bunch of letters and thus unlikely to be a password
func PasswordCheckerOne(word string) bool {
	if stats := charStats(word); stats.Digits == 0 && stats.Symbols == 0 {
		return true
	}
	return false
}

// PasswordCheckerTwo checks if a word could be a file path
func PasswordCheckerTwo(word string) bool {
	if filepath.IsAbs(word) {
		return true
	}
	return false
}

// PasswordCheckerThree checks if a word is an existing directory or a file
func PasswordCheckerThree(word string) bool {
	if filepath.IsAbs(word) {
		if _, err := os.Stat(word); err == nil {
			return true
		}
	}
	return false
}

// PasswordCheckFour checks if a word is a time or a date typical for Linux (ML candidate)
func PasswordCheckFour(word string) bool {
	for _, reg := range timeRegexes {
		if reg.MatchString(word) {
			return true
		}
	}
	return false
}

// PasswordCheckerFive checks if a word is an english word
func PasswordCheckerFive(word string) bool {
	//var found bool
	if _, found := EnglishDictionary[word]; found {
		return true
	} else if _, found = EnglishDictionary[strings.ToLower(word)]; found {
		return true
	}
	return false
}

// PasswordCheckerSix checks if a word is an english word
func PasswordCheckerSix(word string) bool {
	if _, found := EnglishDictionary[strings.ToTitle(word)]; found {
		//dictionary[word] += 1
		return true
	}
	return false
}

// PasswordCheckSeven checks if a word could be an English word since its entropy is within an entropy range of
// the set of English words of a given length and characteristics
func PasswordCheckSeven(word string) bool {
	var entropy EntropyStats
	var found bool

	if len(word) < entropySetWords.Min && len(word) > entropySetWords.Max {
		return false
	}
	if entropy, found = entropySetWords.Set[charStats(word)]; !found {
		return false
	}

	return math.Abs(calculateEntropyTwo(word)-entropy.Avg) > entropy.Dev
}

// PasswordCheckEight checks if a word could be a password since its entropy is within an entropy range of
// the breached passwords with a given length and characteristics
func PasswordCheckEight(word string) bool {
	var entropy EntropyStats
	var found bool

	if len(word) < entropySetBreaches.Min && len(word) > entropySetBreaches.Max {
		return false
	}
	if entropy, found = entropySetBreaches.Set[charStats(word)]; !found {
		return false
	}

	return math.Abs(calculateEntropyTwo(word)-entropy.Avg) < entropy.Dev
}

// PasswordCheckNine checks if a word could be a password since its entropy is within an entropy range of
// the set of generated passwords of a given length
func PasswordCheckNine(word string) bool {
	var entropy EntropyStats
	var found bool

	if len(word) < entropySetGen.Min && len(word) > entropySetGen.Max {
		return false
	}
	if entropy, found = entropySetGen.Set[charStats(word)]; !found {
		return false
	}

	return math.Abs(calculateEntropyTwo(word)-entropy.Avg) < entropy.Dev
}

// PasswordCheckerTen checks if a word is an breached password
func PasswordCheckerTen(word string) bool {
	if _, found := BreachedPasswords[word]; found {
		return true
	}
	return false
}

// PasswordCheckerTen checks if a word is an breached password
func PasswordCheckerEleven(word string) bool {
	if stats := charStats(word); stats.Digits > 0 && stats.Symbols >= 0 && stats.Lowers == 0 && stats.Uppers == 0 {
		return true
	}
	return false
}

// PasswordCheckerTwelve checks if a word is one of the linux words
func PasswordCheckerTwelve(word string) bool {
	if _, found := LinuxWords[word]; found {
		return true
	}
	return false
}

// PasswordCheckerThirteen checks if a word consists only of ASCII characters
func PasswordCheckerThirteen(word string) bool {
	return utf8string.NewString(word).IsASCII()
}

func isPassword(word string) Probability {
	// TODO:
	// - replace it with a set of checkers
	// - checkers should verify the semantics of a word:
	//   - is it a file path
	//   - if it is a path file, does it exist?
	//   - is a date
	//   - it does not contain symbols and special characters
	//   - entropy is within a range - how to compare entropy of a word and a password?
	//   - categorization could be done by ML

	switch {
	case !PasswordCheckerThirteen(word):
		// word contains non-ascii characters therefore is unlikely to be a password
		return Unlikely
	case PasswordCheckerEleven(word):
		// is a bunch of digits and symbols
		return Unlikely
	case PasswordCheckerThree(word):
		// is an existing file or directory
		//fmt.Println("is an existing file or directory")
		return VeryUnlikely
	case PasswordCheckerTwo(word):
		// is likely a file path
		//fmt.Println("is likely a file path")
		return Unlikely
	case PasswordCheckFour(word):
		// is likely to be a date or time
		//fmt.Println("is likely to be a date or time")
		return VeryUnlikely
	case PasswordCheckerTwelve(word):
		// is a linux word
		return Unlikely
	case PasswordCheckerFive(word) || PasswordCheckerSix(word):
		// is an English word
		//fmt.Printf("case 1 - %s is an English word\n", word)
		return VeryUnlikely
	//case PasswordCheckerTen(word):
	//	// is a breached password
	//	//fmt.Fprintf(os.Stderr, "%s\n", word)
	//	return VeryLikely
	case PasswordCheckerZero(word):
		// is a bunch of lower case letters and is unlikely to be a password
		//fmt.Println("is a bunch of lower case letters and could be a low complexity password")
		return Unlikely
	case PasswordCheckerOne(word):
		// is a bunch of lower and upper case letters and could be a low complexity password
		//fmt.Println("is a bunch of lower and upper case letters and could be a medium complexity password")
		return Possible
	case PasswordCheckSeven(word):
		// is likely to be an English word
		//fmt.Println("is likely to be an English word")
		return Unlikely
	case PasswordCheckEight(word):
		// is likely a breached password
		//_, _ = fmt.Fprintf(os.Stderr, "%s is likely a breached password\n", word)
		return Likely
	case PasswordCheckNine(word):
		// is very likely a high complexity password
		//_, _ = fmt.Fprintf(os.Stderr, "%s is very likely a high complexity password\n", word)
		return VeryLikely
	}
	return VeryUnlikely
}

type Match struct {
	word        string
	probability Probability
}

// scanWithEntropyTwo breaks a text line into words based of a regular expression
// and checks whether any of the derived words could be a password.
func (app *App) scanWithEntropyTwo(text string) []Match {
	var words []string = wordsRegex.Split(text, -1)
	var matches []Match

	for _, word := range words {
		//fmt.Fprintf(os.Stderr, "%s\n", word)
		if len(word) >= 5 && len(word) <= 32 {
			switch probability := isPassword(word); probability {
			case VeryUnlikely:
				continue
			case Unlikely:
				continue
			case Possible:
				continue
			case Likely:
				continue
			case VeryLikely:
				matches = append(matches, Match{word: word, probability: probability})
			}
		}
	}
	return matches
}

func (app *App) ScanFileWithEntropyTwo(file string) *ScanResults {
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
		matches := app.scanWithEntropyTwo(scanner.Text())
		for _, match := range matches {
			foundSecrets[line] = Secret{SecretType: "entropy", SecretValue: match.word, Likelihood: match.probability, LineNumber: line}
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
	return app.ScanFileWithEntropyTwo(file)
	//return nil
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
