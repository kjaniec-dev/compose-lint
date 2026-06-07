package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/kjaniec-dev/compose-lint/lint"
)

func main() {
	noColor := flag.Bool("no-color", false, "disable colored output")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: compose-lint [options] [file...]\n\n")
		fmt.Fprintf(os.Stderr, "Lint docker-compose.yml files for common issues.\n\n")
		fmt.Fprintf(os.Stderr, "Checks performed:\n")
		fmt.Fprintf(os.Stderr, "  no-latest-tag   image uses :latest or has no tag\n")
		fmt.Fprintf(os.Stderr, "  healthcheck     missing or disabled healthcheck\n")
		fmt.Fprintf(os.Stderr, "  restart-policy  no restart policy defined\n")
		fmt.Fprintf(os.Stderr, "  port-binding    port exposed on all interfaces (0.0.0.0)\n")
		fmt.Fprintf(os.Stderr, "  memory-limit    no memory limit set\n")
		fmt.Fprintf(os.Stderr, "  cpu-limit       no CPU limit set\n")
		fmt.Fprintf(os.Stderr, "  privileged      container runs in privileged mode\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nIf no files are given, docker-compose.yml in the current directory is used.\n")
		fmt.Fprintf(os.Stderr, "\nExit codes:\n")
		fmt.Fprintf(os.Stderr, "  0  no issues (or only INFO findings)\n")
		fmt.Fprintf(os.Stderr, "  1  at least one ERROR finding\n")
		fmt.Fprintf(os.Stderr, "  2  file read or parse error\n")
	}
	flag.Parse()

	files := flag.Args()
	if len(files) == 0 {
		files = []string{"docker-compose.yml"}
	}

	exitCode := 0
	for i, file := range files {
		if i > 0 {
			fmt.Fprintln(os.Stdout)
		}
		if len(files) > 1 {
			fmt.Printf("==> %s\n", file)
		}

		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			exitCode = 2
			continue
		}

		findings, err := lint.Run(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "parse error in %s: %v\n", file, err)
			exitCode = 2
			continue
		}

		lint.Print(findings, *noColor, os.Stdout)

		if lint.HasErrors(findings) && exitCode < 1 {
			exitCode = 1
		}
	}

	os.Exit(exitCode)
}
