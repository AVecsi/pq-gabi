ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

ZK_REPO   := https://github.com/AVecsi/zkDilithium
ZK_DIR    := zkDilithiumProof
ZK_LIB    := $(ZK_DIR)/target/release/libzk_dilithium.a
ZK_HEADER := $(ZK_DIR)/zkDilithiumProof.h

# PHONY means that it doesn't correspond to a file; it always runs the build commands.
.PHONY: build run test-go test-rust clean fetch-rust-lib

# ── top-level ───────────────────────────────────────────────────────────────

build: $(ZK_LIB) $(ZK_HEADER)
	go build

run: build
#	@./main
	go test

# ── rust lib ────────────────────────────────────────────────────────────────

# Clone zkDilithium if not present, then build
$(ZK_DIR):
	git clone $(ZK_REPO) $(ZK_DIR)

$(ZK_LIB) $(ZK_HEADER): | $(ZK_DIR)
	@cd $(ZK_DIR) && cargo build --release --features concurrent

# Force a fresh pull and rebuild of the Rust lib
fetch-rust-lib:
	@if [ -d $(ZK_DIR) ]; then \
		cd $(ZK_DIR) && git pull; \
	else \
		git clone $(ZK_REPO) $(ZK_DIR); \
	fi
	@cd $(ZK_DIR) && cargo build --release --features concurrent

# ── tests ───────────────────────────────────────────────────────────────────

test-go: build
	go test -v ./...

test-rust: $(ZK_DIR)
	@cd $(ZK_DIR) && cargo test --release -- --nocapture

# ── clean ───────────────────────────────────────────────────────────────────

clean:
	rm -f main
	rm -rf $(ZK_DIR)/target

clean-all: clean
	rm -rf $(ZK_DIR)