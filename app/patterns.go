package app

import (
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"regexp"
)

type Pattern struct {
	Name          string         `yaml:"name"`
	Regex         string         `yaml:"regex"`
	Confidence    string         `yaml:"confidence"`
	CompiledRegex *regexp.Regexp `yaml:"-"`
}

type PatternsFile struct {
	Patterns []struct {
		Pattern Pattern `yaml:"pattern"`
	} `yaml:"patterns"`
}

type Patterns struct {
	file     string
	patterns []Pattern
}

func NewPatterns(fileWithPatterns string) (*Patterns, error) {
	p := Patterns{file: fileWithPatterns, patterns: nil}
	err := p.load()

	if err != nil {
		return nil, err
	}
	return &p, nil
}

func DefaultPatterns() (*Patterns, error) {
	p := Patterns{file: "", patterns: nil}
	err := p.read(defaultPatterns)

	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *Patterns) load() error {
	fd, err := os.Open(p.file)
	if err != nil {
		return err
	}
	defer fd.Close()

	data := PatternsFile{}
	err = yaml.NewDecoder(fd).Decode(&data)
	if err != nil {
		return err
	}

	p.patterns = []Pattern{}
	for _, dataElement := range data.Patterns {
		dataElement.Pattern.CompiledRegex, err = regexp.Compile(dataElement.Pattern.Regex)
		if err != nil {
			log.Fatalf("Compilation of regex %q failed with error: %s\nAborting!!!\n", dataElement.Pattern.Regex, err.Error())
		}
		p.patterns = append(p.patterns, dataElement.Pattern)
	}

	return nil
}

func (p *Patterns) read(yamlPatterns string) error {
	var data []Pattern
	var err error

	err = yaml.Unmarshal([]byte(defaultPatterns), &data)
	if err != nil {
		return err
	}

	p.patterns = data
	p.file = ""

	for idx, pattern := range p.patterns {
		p.patterns[idx].CompiledRegex, err = regexp.Compile(pattern.Regex)
		if err != nil {
			log.Fatalf("Compilation of regex %q failed with error: %s\nAborting!!!\n", pattern.Regex, err.Error())
		}
	}

	return nil
}

func (p *Patterns) Get() []Pattern {
	return p.patterns
}

func (p *Patterns) Num() int {
	return len(p.patterns)
}
