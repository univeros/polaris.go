package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
)

// dotenv is a parsed .env file: its lines, kept for rewriting, and its values.
type dotenv struct {
	lines  []string
	values map[string]string
	spans  map[string][2]int // key -> first and last line of its assignment
}

// readDotenv reads a .env file; a missing file is empty. Supported: KEY=value, export KEY=value,
// # comments, 'single-quoted' (literal) and "double-quoted" values (\n, \", \\ escapes; may span
// lines, as a PEM does).
func readDotenv(path string) (dotenv, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return dotenv{values: map[string]string{}, spans: map[string][2]int{}}, nil
	}
	if err != nil {
		return dotenv{}, err
	}
	return parseDotenv(path, string(data))
}

func parseDotenv(path, data string) (dotenv, error) {
	d := dotenv{lines: strings.Split(strings.TrimSuffix(data, "\n"), "\n"), values: map[string]string{}, spans: map[string][2]int{}}
	if data == "" {
		d.lines = nil
	}
	for i := 0; i < len(d.lines); i++ {
		line := strings.TrimSpace(d.lines[i])
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, raw, ok := strings.Cut(strings.TrimPrefix(line, "export "), "=")
		key, raw = strings.TrimSpace(key), strings.TrimSpace(raw)
		if !ok || key == "" || strings.ContainsAny(key, " \t") {
			return dotenv{}, fmt.Errorf("%s:%d: expected KEY=value", path, i+1)
		}
		start := i
		var value string
		switch {
		case strings.HasPrefix(raw, `"`), strings.HasPrefix(raw, `'`):
			quote := raw[:1]
			body := raw[1:]
			for !closed(body, quote) {
				if i++; i == len(d.lines) {
					return dotenv{}, fmt.Errorf("%s:%d: %s has no closing %s", path, start+1, key, quote)
				}
				body += "\n" + d.lines[i]
			}
			body = strings.TrimRight(body, " \t")
			value = body[:len(body)-1]
			if quote == `"` {
				value = unescape(value)
			}
		default:
			value, _, _ = strings.Cut(raw, " #")
			value = strings.TrimSpace(value)
		}
		d.values[key] = value
		d.spans[key] = [2]int{start, i}
	}
	return d, nil
}

// closed reports whether body (after the opening quote) ends with an unescaped closing quote.
func closed(body, quote string) bool {
	body = strings.TrimRight(body, " \t")
	if !strings.HasSuffix(body, quote) {
		return false
	}
	if quote == `'` {
		return true
	}
	backslashes := 0
	for i := len(body) - 2; i >= 0 && body[i] == '\\'; i-- {
		backslashes++
	}
	return backslashes%2 == 0
}

func unescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'n':
				b.WriteByte('\n')
				i++
				continue
			case '"', '\\':
				b.WriteByte(s[i+1])
				i++
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// envLine is KEY="value", the value's newlines kept (a shell sourcing the file reads it as is).
func envLine(key, value string) string {
	return key + `="` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
}

// write rewrites the file with set applied: a key already present is replaced in place, a new one
// appended. The file is private to its owner.
func (d dotenv) write(path string, set map[string]string) error {
	lines := slices.Clone(d.lines)
	type span struct {
		key        string
		start, end int
	}
	var replace []span
	var appended []string
	for key := range set {
		if s, ok := d.spans[key]; ok {
			replace = append(replace, span{key, s[0], s[1]})
		} else {
			appended = append(appended, key)
		}
	}
	// Replace from the bottom up so earlier spans keep their indexes.
	slices.SortFunc(replace, func(a, b span) int { return b.start - a.start })
	for _, s := range replace {
		lines = slices.Replace(lines, s.start, s.end+1, envLine(s.key, set[s.key]))
	}
	slices.Sort(appended)
	for _, key := range appended {
		lines = append(lines, envLine(key, set[key]))
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}
