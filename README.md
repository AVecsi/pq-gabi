PQ-Gabi
&nbsp;
[![Go Reference](https://pkg.go.dev/badge/github.com/AVecsi/pq-gabi.svg)](https://pkg.go.dev/github.com/AVecsi/pq-gabi)
[![Go Report Card](https://goreportcard.com/badge/github.com/AVecsi/pq-gabi)](https://goreportcard.com/report/github.com/AVecsi/pq-gabi)
====

> **⚠️ WARNING:** This is an academic proof-of-concept prototype and has not received careful code review. This implementation is **NOT ready for production use**.

`pq-gabi` is a Go implementation of a post-quantum anonymous credential scheme based on [zkDilithium](https://eprint.iacr.org/2023/414) signatures and STARK proofs. It is a post-quantum extension of the [Yivi](https://yivi.app) (formerly known as IRMA) credential system, replacing the classical cryptographic primitives introduced by [Idemix](https://privacybydesign.foundation/irma-en) with post-quantum secure alternatives.

The cryptographic heavy lifting is done by [zkDilithium](https://github.com/AVecsi/zkDilithium), a Rust library exposing a C-compatible FFI. `pq-gabi` calls into it via CGo.

gabi serves as the cryptographic core of [`pq-irmago`](https://github.com/AVecsi/pq-irmago), which implements the IRMA server, IRMA app core, shared functionality between the two, and more.

## Dependencies

The Rust library [zkDilithium](https://github.com/AVecsi/zkDilithium) is a required dependency. It is fetched and built automatically by the Makefile — you do not need to clone or build it manually.

**Prerequisites:**
- Go
- Rust and Cargo
- Make
- CGo-compatible C compiler

## Install and Build

Clone the repository and build:

```bash
git clone https://github.com/AVecsi/pq-gabi
cd pq-gabi
make build
```

This will automatically clone `zkDilithium`, build it as a static library, generate the C header via `cbindgen`, and compile the Go library against it.

To update the Rust dependency to its latest version:

```bash
make fetch-rust-lib
```

## Test

```bash
make test-go
```

To run the Rust library tests:

```bash
make test-rust
```

## Clean

```bash
make clean      # removes build outputs
make clean-all  # also removes the cloned zkDilithium directory
```