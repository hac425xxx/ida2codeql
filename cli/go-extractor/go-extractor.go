package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/github/codeql-go/extractor"
)

func usage() {
	fmt.Fprintf(os.Stderr, "%s is a program for create trap for hexray ast.\n\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Usage:\n\n  %s --ast astfile --type asttypefile\n\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "--help                Print this help.\n")
}

func parseFlags(args []string) (string, string) {
	astfile := ""
	asttypefile := ""
	i := 0
	for ; i < len(args) && strings.HasPrefix(args[i], "--"); i++ {
		switch args[i] {
		case "--help":
			usage()
			os.Exit(0)
		case "--ast":
			astfile = args[i+1]
			i++

		case "--type":
			asttypefile = args[i+1]
			i++
		}
	}

	if astfile == "" || asttypefile == "" {
		usage()
		os.Exit(2)
	}

	return astfile, asttypefile
}

func main() {
	astfile, asttypefile := parseFlags(os.Args[1:])
	extractor.ExtractWithFlags(astfile, asttypefile)
}
