package app

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/exp/utf8string"
	"log"
	"os"
	"unicode"
)

func checkRuneType(c rune) {

	fmt.Printf("For %q (%d):\n", c, c)
	if unicode.Is(unicode.ASCII_Hex_Digit, c) {
		fmt.Println("\tis ascii rune")
	}
	if unicode.IsControl(c) {
		fmt.Println("\tis control rune")
	}
	if unicode.IsDigit(c) {
		fmt.Println("\tis digit rune")
	}
	if unicode.IsGraphic(c) {
		fmt.Println("\tis graphic rune")
	}
	if unicode.IsLetter(c) {
		fmt.Println("\tis letter rune")
	}
	if unicode.IsLower(c) {
		fmt.Println("\tis lower case rune")
	}
	if unicode.IsMark(c) {
		fmt.Println("\tis mark rune")
	}
	if unicode.IsNumber(c) {
		fmt.Println("\tis number rune")
	}
	if unicode.IsPrint(c) {
		fmt.Println("\tis printable rune")
	}
	if !unicode.IsPrint(c) {
		fmt.Println("\tis not printable rune")
	}
	if unicode.IsPunct(c) {
		fmt.Println("\tis punct rune")
	}
	if unicode.IsSpace(c) {
		fmt.Println("\tis space rune")
	}
	if unicode.IsSymbol(c) {
		fmt.Println("\tis symbol rune")
	}
	if unicode.IsTitle(c) {
		fmt.Println("\tis title case rune")
	}
	if unicode.IsUpper(c) {
		fmt.Println("\tis upper case rune")
	}

}

func isBase64DecodedString(s string) (string, error) {
	decodedBytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err // Not a valid base64 or other decode error
	}
	//fmt.Println(s, " => ", string(decodedBytes))
	decStr := string(decodedBytes)
	if utf8string.NewString(decStr).IsASCII() {
		for _, r := range decStr {
			//r := rune(decStr[idx])
			if !unicode.IsDigit(r) && !unicode.IsLetter(r) && !unicode.IsPunct(r) {
				// Contains non-printable characters
				return "", errors.New("Decoded base64 string consists of non-printable characters")
			}
		}
		return decStr, nil // All characters are printable
	}

	return "", errors.New("Decoded base64 string consists of non-printable characters")
}

func (app *App) scanWithBase64(text string) []string {
	var words []string = wordsRegex.Split(text, -1)
	var matches []string

	for _, word := range words {
		if len(word) >= app.minWordLength && base64Regex.MatchString(word) {
			decoded, err := isBase64DecodedString(word)
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
