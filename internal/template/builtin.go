package template

import (
	"embed"
	"io/fs"
	"strings"
)

//go:embed builtin/*.yaml
var builtinFS embed.FS

// Builtin returns the templates shipped inside the binary.
func Builtin() ([]*Template, error) {
	var out []*Template
	err := fs.WalkDir(builtinFS, "builtin", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return err
		}
		b, err := builtinFS.ReadFile(path)
		if err != nil {
			return err
		}
		t, err := Parse(b, false)
		if err != nil {
			return err
		}
		out = append(out, t)
		return nil
	})
	return out, err
}
