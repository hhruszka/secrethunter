package main

import (
	"fmt"
	"regexp"
)

// example function of using regexp to split lines in word tokens
func splitWithRegex() {
	s := "This is a,string: containing. whitespaces"

	t := regexp.MustCompile(`[ ,:@]+`) // backticks are used here to contain the expression

	v := t.Split(s, -1) // second arg -1 means no limits for the number of substrings
	for _, str := range v {
		fmt.Printf("[%s]\n", str) // [x zx zx zx zx z]
	}
}
