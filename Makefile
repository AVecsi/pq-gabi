ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

# PHONY means that it doesn't correspond to a file; it always runs the build commands.

.PHONY: build-all
build-all: build-dynamic build-static

.PHONY: run-all
run-all: run-dynamic run-static

.PHONY: build-dynamic
build-dynamic:
	@cd zkDilithiumProof && cargo build --release
	@cp zkDilithiumProof/target/release/libzkDilithiumProof.dylib zkDilithiumProof
	go build -ldflags="-r $(ROOT_DIR)zkDilithiumProof"

.PHONY: build-static
build-static:
	@cd zkDilithiumProof && cargo build --release
	@cp zkDilithiumProof/target/release/libzkDilithiumProof.a zkDilithiumProof
	go build

.PHONY: run-dynamic
run-dynamic: build-dynamic
	@./main

.PHONY: run-static
run-static: build-static
	@./main

# This is just for running the Rust lib tests natively via cargo
.PHONY: test-rust-lib
test-rust-lib:
	@cd zkDilithiumProof && cargo test --release -- --nocapture

.PHONY: clean
clean:
	rm -rf main libzkDilithiumProof.dylib libzkDilithiumProof.a zkDilithiumProof/target
