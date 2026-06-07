package lint

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Severity ranks the importance of a finding.
type Severity int

const (
	SeverityInfo  Severity = iota // informational, no action required
	SeverityWarn                  // should be addressed
	SeverityError                 // must be addressed
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO "
	case SeverityWarn:
		return "WARN "
	case SeverityError:
		return "ERROR"
	default:
		return "?????"
	}
}

// Finding is a single linting result.
type Finding struct {
	Service  string
	Severity Severity
	Rule     string
	Message  string
}

// Run parses raw docker-compose YAML and applies all rules.
func Run(data []byte) ([]Finding, error) {
	var cf ComposeFile
	if err := yaml.Unmarshal(data, &cf); err != nil {
		return nil, err
	}

	// Stable service order for deterministic output.
	names := make([]string, 0, len(cf.Services))
	for n := range cf.Services {
		names = append(names, n)
	}
	sort.Strings(names)

	var findings []Finding
	for _, name := range names {
		svc := cf.Services[name]
		for _, r := range allRules {
			findings = append(findings, r(name, svc)...)
		}
	}
	return findings, nil
}

// HasErrors returns true if any finding has Error severity.
func HasErrors(findings []Finding) bool {
	for _, f := range findings {
		if f.Severity == SeverityError {
			return true
		}
	}
	return false
}

const (
	ansiReset  = "\033[0m"
	ansiRed    = "\033[31m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
)

// Print writes a human-readable report to w.
func Print(findings []Finding, noColor bool, w io.Writer) {
	if len(findings) == 0 {
		fmt.Fprintln(w, "No issues found.")
		return
	}

	errors, warns, infos := 0, 0, 0
	for _, f := range findings {
		var color, reset string
		switch f.Severity {
		case SeverityError:
			color, reset = ansiRed, ansiReset
			errors++
		case SeverityWarn:
			color, reset = ansiYellow, ansiReset
			warns++
		case SeverityInfo:
			color, reset = ansiCyan, ansiReset
			infos++
		}
		if noColor {
			color, reset = "", ""
		}
		fmt.Fprintf(w, "%s[%s]%s  service %q: %s  (%s)\n",
			color, f.Severity, reset, f.Service, f.Message, f.Rule)
	}

	var parts []string
	if errors > 0 {
		parts = append(parts, fmt.Sprintf("%d error(s)", errors))
	}
	if warns > 0 {
		parts = append(parts, fmt.Sprintf("%d warning(s)", warns))
	}
	if infos > 0 {
		parts = append(parts, fmt.Sprintf("%d info(s)", infos))
	}
	fmt.Fprintf(w, "\nFound %d issue(s): %s\n", len(findings), strings.Join(parts, ", "))
}
