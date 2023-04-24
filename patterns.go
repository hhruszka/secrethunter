package main

import (
	"gopkg.in/yaml.v3"
	"os"
)

type Pattern struct {
	Name       string `yaml:"name"`
	Regex      string `yaml:"regex"`
	Confidence string `yaml:"confidence"`
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
		p.patterns = append(p.patterns, dataElement.Pattern)
	}

	return nil
}

func (p *Patterns) Get() []Pattern {
	return p.patterns
}

func (p *Patterns) Num() int {
	return len(p.patterns)
}
