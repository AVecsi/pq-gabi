ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

ZK_REPO   := https://github.com/AVecsi/zkdilithium
ZK_DIR    := zkDilithiumProof
ZK_LIB    := $(ZK_DIR)/target/release/libzk_dilithium.a
ZK_HEADER := $(ZK_DIR)/zkDilithiumProof.h

# Branch of ZK_REPO to build. The f23 (FIPS 204 field) work lives on a branch,
# so cloning the default branch gives the old f23201 field and every proof fails
# to verify against this module -- the modulus is not carried across the FFI, so
# a mismatch is silent. Override with `make ZK_BRANCH=master ...`.
ZK_BRANCH ?= implement-migration-to-f23

# Installing the built artifacts. Kept in one place so the desktop and mobile
# targets cannot drift apart, and so the branch/commit and the field actually
# built are reported rather than assumed.
define install_zk_lib
	@mkdir -p lib
	@cp $(ZK_DIR)/target/release/libzk_dilithium.a lib/
	@cp $(ZK_DIR)/zkDilithiumProof.h lib/
	@echo "installed libzk_dilithium.a from $(ZK_BRANCH) @ $$(cd $(ZK_DIR) && git rev-parse --short HEAD)"
	@echo "header reports M = $$(awk '/^#define M /{print $$3}' lib/zkDilithiumProof.h), must equal dilcommon.Q = $$(awk '/^const Q = /{print $$4}' internal/dilcommon/constants.go)"
endef

.PHONY: build run test-go test-rust clean clean-all fetch-rust-lib build-ios build-android check-arch

# ── top-level ───────────────────────────────────────────────────────────────

build: check-arch $(ZK_LIB) $(ZK_HEADER)
	go build

# cargo builds libzk_dilithium.a for the host architecture only, so a Go toolchain
# with a different GOARCH cannot link it. That happens easily on an Apple Silicon
# Mac with both an arm64 (homebrew) and an amd64 (/usr/local/go) Go installed: the
# amd64 one discards every member of the archive and fails with "running clang
# failed", preceded by hundreds of "found architecture 'arm64', required
# architecture 'x86_64'" warnings. Catch it in one line instead.
# An amd64 Go here would also run the proofs under Rosetta, so any timings taken
# with it are meaningless even when it does link.
check-arch:
	@lib_arch=$$(lipo -info lib/libzk_dilithium.a 2>/dev/null | sed 's/.*architecture: *//'); \
	go_arch=$$(go env GOARCH); \
	case "$$go_arch" in amd64) want=x86_64 ;; *) want=$$go_arch ;; esac; \
	if [ -n "$$lib_arch" ] && [ "$$lib_arch" != "$$want" ]; then \
		echo "ERROR: lib/libzk_dilithium.a is $$lib_arch, but go targets $$go_arch ($$want)."; \
		echo "       go in PATH: $$(command -v go) -- $$(go version)"; \
		echo "       Use a $$lib_arch Go toolchain, e.g.:"; \
		echo "           PATH=/opt/homebrew/bin:\$$PATH make $(MAKECMDGOALS)"; \
		echo "       or rebuild the library for $$want:"; \
		echo "           cd $(ZK_DIR) && cargo build --release --features concurrent --target $$want-apple-darwin"; \
		exit 1; \
	fi

run: build
	go test

# ── rust lib ────────────────────────────────────────────────────────────────

$(ZK_DIR):
	@if [ ! -f $(ZK_DIR)/Cargo.toml ]; then \
		rm -rf $(ZK_DIR) && git clone --branch $(ZK_BRANCH) $(ZK_REPO) $(ZK_DIR); \
	fi

$(ZK_LIB) $(ZK_HEADER): | $(ZK_DIR)
	@cd $(ZK_DIR) && cargo build --release --features concurrent
	$(call install_zk_lib)

# Force a fresh fetch and rebuild of the Rust lib.
# Checks out ZK_BRANCH explicitly: an existing clone is on whatever branch it was
# created with, which for any checkout made before the f23 migration is master.
fetch-rust-lib: | $(ZK_DIR)
	@cd $(ZK_DIR) && git fetch origin && git checkout $(ZK_BRANCH) && git pull --ff-only origin $(ZK_BRANCH)
	# winterfell is a git *branch* dependency and Cargo.lock is gitignored, so the
	# lock is untracked: git checkout/pull never touch it and cargo keeps the commit
	# it first resolved, even after the branch moves. Re-resolve explicitly. Skipping
	# this pins winterfell to a pre-patch revision whose zk randomizer does not
	# reject out-of-range draws, which panics with "failed to generate randomness"
	# over f23 (~0.098% of draws are rejects, and there are millions per proof).
	@cd $(ZK_DIR) && cargo update -p winterfell
	@cd $(ZK_DIR) && cargo build --release --features concurrent
	$(call install_zk_lib)

# ── mobile targets ──────────────────────────────────────────────────────────

build-ios: | $(ZK_DIR)
	@cd $(ZK_DIR) && cargo build --release \
		--target aarch64-apple-ios \
		--target x86_64-apple-ios
	@mkdir -p lib/ios
	@cp $(ZK_DIR)/target/aarch64-apple-ios/release/libzk_dilithium.a lib/ios/
	@cp $(ZK_DIR)/zkDilithiumProof.h lib/

# Detect OS and set NDK toolchain path accordingly
ifeq ($(shell uname), Darwin)
    NDK_HOST := darwin-x86_64
    ANDROID_SDK_ROOT ?= $(HOME)/Library/Android/sdk
else ifeq ($(shell uname), Linux)
    NDK_HOST := linux-x86_64
    ANDROID_SDK_ROOT ?= $(HOME)/Android/sdk
endif

NDK_VERSION := $(shell ls $(ANDROID_SDK_ROOT)/ndk | sort -V | tail -1)
NDK_BIN := $(ANDROID_SDK_ROOT)/ndk/$(NDK_VERSION)/toolchains/llvm/prebuilt/$(NDK_HOST)/bin

build-android: | $(ZK_DIR)
	@export PATH=$(NDK_BIN):$$PATH && \
	cd $(ZK_DIR) && cargo build --release --features concurrent \
		--target aarch64-linux-android \
		--target armv7-linux-androideabi \
		--target i686-linux-android \
		--target x86_64-linux-android
	@mkdir -p lib/arm64-v8a lib/armeabi-v7a lib/x86 lib/x86_64
	@cp $(ZK_DIR)/target/aarch64-linux-android/release/libzk_dilithium.a lib/arm64-v8a/
	@cp $(ZK_DIR)/target/armv7-linux-androideabi/release/libzk_dilithium.a lib/armeabi-v7a/
	@cp $(ZK_DIR)/target/i686-linux-android/release/libzk_dilithium.a lib/x86/
	@cp $(ZK_DIR)/target/x86_64-linux-android/release/libzk_dilithium.a lib/x86_64/
	@cp $(ZK_DIR)/zkDilithiumProof.h lib/

# ── tests ───────────────────────────────────────────────────────────────────

test-go: build
	go test -v ./...

# --test test is required: the suite is a separate target ([[test]] name = "test",
# path = "src/test/test.rs" in Cargo.toml). Without it cargo tests the lib target
# instead and reports "running 0 tests" while exiting 0.
test-rust: | $(ZK_DIR)
	@cd $(ZK_DIR) && cargo test --release --features concurrent --test test -- --nocapture

# ── clean ───────────────────────────────────────────────────────────────────

clean:
	rm -f main
	rm -rf lib/
	rm -rf $(ZK_DIR)/target

clean-all: clean
	rm -rf $(ZK_DIR)