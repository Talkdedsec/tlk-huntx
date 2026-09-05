// Package template runs nuclei-compatible detection templates. It reads the common
// HTTP subset of the nuclei schema (id, info, requests/http, matchers, extractors)
// from YAML or JSON, so existing community templates load without translation.
package template

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Template struct {
	ID       string    `yaml:"id" json:"id"`
	Info     Info      `yaml:"info" json:"info"`
	Requests []Request `yaml:"requests" json:"requests"`
	HTTP     []Request `yaml:"http" json:"http"`
}

type Info struct {
	Name        string `yaml:"name" json:"name"`
	Author      string `yaml:"author" json:"author"`
	Severity    string `yaml:"severity" json:"severity"`
	Description string `yaml:"description" json:"description"`
	Tags        string `yaml:"tags" json:"tags"`
}

type Request struct {
	Method            string            `yaml:"method" json:"method"`
	Path              []string          `yaml:"path" json:"path"`
	Headers           map[string]string `yaml:"headers" json:"headers"`
	Body              string            `yaml:"body" json:"body"`
	MatchersCondition string            `yaml:"matchers-condition" json:"matchers-condition"`
	Matchers          []Matcher         `yaml:"matchers" json:"matchers"`
	Extractors        []Extractor       `yaml:"extractors" json:"extractors"`
	StopAtFirstMatch  bool              `yaml:"stop-at-first-match" json:"stop-at-first-match"`
}

type Matcher struct {
	Type            string   `yaml:"type" json:"type"`
	Part            string   `yaml:"part" json:"part"`
	Words           []string `yaml:"words" json:"words"`
	Regex           []string `yaml:"regex" json:"regex"`
	Status          []int    `yaml:"status" json:"status"`
	Condition       string   `yaml:"condition" json:"condition"`
	Negative        bool     `yaml:"negative" json:"negative"`
	CaseInsensitive bool     `yaml:"case-insensitive" json:"case-insensitive"`
}

type Extractor struct {
	Name  string   `yaml:"name" json:"name"`
	Type  string   `yaml:"type" json:"type"`
	Part  string   `yaml:"part" json:"part"`
	Regex []string `yaml:"regex" json:"regex"`
	Group int      `yaml:"group" json:"group"`
}

// blocks returns the request blocks regardless of which key the template used.
func (t *Template) blocks() []Request {
	if len(t.HTTP) > 0 {
		return t.HTTP
	}
	return t.Requests
}

func (t *Template) tags() []string {
	var out []string
	for _, s := range strings.Split(t.Info.Tags, ",") {
		if s = strings.TrimSpace(strings.ToLower(s)); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func Parse(data []byte, asJSON bool) (*Template, error) {
	var t Template
	var err error
	if asJSON {
		err = json.Unmarshal(data, &t)
	} else {
		err = yaml.Unmarshal(data, &t)
	}
	if err != nil {
		return nil, err
	}
	if t.ID == "" {
		return nil, fmt.Errorf("template has no id")
	}
	return &t, nil
}

func LoadFile(path string) (*Template, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b, strings.EqualFold(filepath.Ext(path), ".json"))
}

// LoadDir walks a directory tree for .yaml/.yml/.json templates. A single broken
// template is reported but does not abort the load of the rest.
func LoadDir(dir string) ([]*Template, error) {
	var out []*Template
	var bad []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".yaml", ".yml", ".json":
			t, e := LoadFile(path)
			if e != nil {
				bad = append(bad, fmt.Sprintf("%s: %v", path, e))
				return nil
			}
			out = append(out, t)
		}
		return nil
	})
	if err != nil {
		return out, err
	}
	if len(bad) > 0 {
		return out, fmt.Errorf("%d template(s) skipped: %s", len(bad), strings.Join(bad, "; "))
	}
	return out, nil
}

// SelectByTech keeps templates that are generic (no tech tag) or whose tags match
// one of the discovered technologies, so a Rails host is not hit with WordPress checks.
func SelectByTech(templates []*Template, techs []string) []*Template {
	known := map[string]bool{
		"wordpress": true, "django": true, "next.js": true, "express": true,
		"apache": true, "nginx": true, "iis": true, "php": true, "cloudflare": true,
	}
	have := map[string]bool{}
	for _, t := range techs {
		have[strings.ToLower(strings.TrimSpace(t))] = true
	}
	var out []*Template
	for _, tpl := range templates {
		techTagged := false
		matched := false
		for _, tag := range tpl.tags() {
			if known[tag] {
				techTagged = true
				if have[tag] {
					matched = true
				}
			}
		}
		if !techTagged || matched {
			out = append(out, tpl)
		}
	}
	return out
}
