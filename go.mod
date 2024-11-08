module github.com/github/codeql-go/extractor

go 1.20

// when updating this, run
//    bazel run @rules_go//go -- mod tidy
// when adding or removing dependencies, run
//    bazel mod tidy
require (
	golang.org/x/mod v0.19.0 // indirect
	golang.org/x/tools v0.23.0
)

require (
	github.com/tidwall/gjson v1.17.3
	github.com/tidwall/sjson v1.2.5
)

require (
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
)
