module github.com/AVecsi/pq-gabi

go 1.25.0

require (
	github.com/AVecsi/lazer v0.0.0-20260729101002-e8192d524694
	github.com/fxamacker/cbor v1.5.1
	github.com/go-errors/errors v1.5.1
	github.com/sirupsen/logrus v1.9.4
	github.com/stretchr/testify v1.10.0
	golang.org/x/crypto v0.54.0
)

// lazer (Falcon-512 / LNP) anonymous-credentials backend, used only by the
// -tags lazer build (internal/lazeranon). Resolved to the local cgo wrapper.
//require github.com/AVecsi/lazer@implement-anoncred-c-go

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.13.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/sys v0.47.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
