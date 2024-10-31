ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

# PHONY means that it doesn't correspond to a file; it always runs the build commands.

.PHONY: build-all
build-all: build-dynamic build-static

.PHONY: run-all
run-all: run-dynamic run-static

.PHONY: build-dynamic
build-dynamic:
	@cd zkDilithium/lib/zkDilithiumProof && cargo build --release
	@cp zkDilithium/lib/zkDilithiumProof/target/release/libzkDilithium.dylib zkDilithium/lib/zkDilithiumProof
	go build -ldflags="-r $(ROOT_DIR)lib"

.PHONY: build-static
build-static:
	@cd zkDilithium/lib/zkDilithiumProof && cargo build --release
	@cp zkDilithium/lib/zkDilithiumProof/target/release/libzkDilithium.a zkDilithium/lib/
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
	@cd zkDilithium/lib/zkDilithiumProof && cargo test --release -- --nocapture

.PHONY: clean
clean:
	rm -rf main zkDilithium/lib/libzkDilithium.dylib zkDilithium/lib/libzkDilithium.a zkDilithium/lib/zkDilithiumProof/target
