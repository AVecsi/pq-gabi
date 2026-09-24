ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

ZK_REPO   := https://github.com/AVecsi/zkDilithium
ZK_DIR    := zkDilithiumProof

# The zkDilithium revision this wrapper's FFI speaks to. The cgo declarations in
# internal/zkdil are part of that contract, so a build against any other
# revision is not a supported combination -- bump this together with them.
ZK_REV    := a8e591fbeb370be1748bdc0ccf240cb2ee1973c2

# What cgo actually links against, and the stamp recording which revision it was
# built from.
# Every platform gets its own directory, because the cgo LDFLAGS for each one
# point at lib/$(GOOS)_$(GOARCH) and they used to collide in a single lib/.
GOOS      := $(shell go env GOOS)
GOARCH    := $(shell go env GOARCH)
HOST_DIR  := lib/$(GOOS)_$(GOARCH)

ZK_LIB    := $(HOST_DIR)/libzk_dilithium.a
ZK_HEADER := lib/zkDilithiumProof.h
ZK_STAMP  := $(HOST_DIR)/.zk-rev

# Cross-built with cargo-zigbuild so it links against an old glibc and runs on
# any CI image. Needs: brew install zig && cargo install cargo-zigbuild &&
# rustup target add x86_64-unknown-linux-gnu
LINUX_AMD64_TARGET := x86_64-unknown-linux-gnu.2.17

# Rebuild the lib when the Rust changes, not only when it is missing. Evaluated
# at parse time, so it is empty before the first clone -- harmless, because then
# the target does not exist either.
ZK_SRC := $(wildcard $(ZK_DIR)/Cargo.toml $(ZK_DIR)/Cargo.lock $(ZK_DIR)/build.rs $(ZK_DIR)/cbindgen.toml) \
          $(shell find $(ZK_DIR)/src -name '*.rs' 2>/dev/null)

.PHONY: build run test-go test-rust test-lazer build-lazer build-linux-amd64 clean clean-all zk-sync zk-check fetch-rust-lib build-ios build-android

# ── top-level ───────────────────────────────────────────────────────────────

build: $(ZK_LIB)
	go build

run: build
	go test

# ── rust lib ────────────────────────────────────────────────────────────────

# A fresh clone lands on ZK_REV; there is no local work to lose.
$(ZK_DIR):
	@if [ ! -f $(ZK_DIR)/Cargo.toml ]; then \
		rm -rf $(ZK_DIR) && git clone $(ZK_REPO) $(ZK_DIR) && \
		cd $(ZK_DIR) && git checkout --quiet --detach $(ZK_REV); \
	fi

# Refuses to build against the wrong circuit rather than moving somebody's
# checkout out from under them: if you are working in $(ZK_DIR), you decide
# whether to go back to the pin or to bump it.
zk-check: | $(ZK_DIR)
	@have=$$(cd $(ZK_DIR) && git rev-parse HEAD); \
	if [ "$$have" != "$(ZK_REV)" ]; then \
		echo "$(ZK_DIR) is at $$have"; \
		echo "Makefile pins ZK_REV   $(ZK_REV)"; \
		echo "Run 'make zk-sync' to move the checkout, or bump ZK_REV."; \
		exit 1; \
	fi

zk-sync: | $(ZK_DIR)
	@cd $(ZK_DIR) && git fetch --quiet origin && git checkout --quiet --detach $(ZK_REV)
	@rm -f $(ZK_STAMP)

$(ZK_STAMP): Makefile | $(ZK_DIR)
	@$(MAKE) --no-print-directory zk-check
	@mkdir -p $(HOST_DIR)
	@echo $(ZK_REV) > $@

$(ZK_LIB) $(ZK_HEADER): $(ZK_STAMP) $(ZK_SRC)
	@cd $(ZK_DIR) && cargo build --release --features concurrent
	@mkdir -p $(HOST_DIR)
	@cp $(ZK_DIR)/target/release/libzk_dilithium.a $(HOST_DIR)/
	@cp $(ZK_DIR)/zkDilithiumProof.h lib/

build-linux-amd64: zk-check
	@cd $(ZK_DIR) && cargo zigbuild --release --features concurrent --target $(LINUX_AMD64_TARGET)
	@mkdir -p lib/linux_amd64
	@cp $(ZK_DIR)/target/x86_64-unknown-linux-gnu/release/libzk_dilithium.a lib/linux_amd64/
	@cp $(ZK_DIR)/zkDilithiumProof.h lib/

fetch-rust-lib: zk-sync $(ZK_LIB)

# ── mobile targets ──────────────────────────────────────────────────────────

# --features concurrent, like every other target: without it the prover runs
# single-threaded and an iPhone is several times slower than the equivalent
# Android for no visible reason.
#
# The device lib goes to lib/ios/, which is where the "#cgo ios,arm64" LDFLAGS
# look. Copying it to lib/ instead put it where the host build expects its own
# library, so building for iOS overwrote the macOS one.
build-ios: zk-check | $(ZK_DIR)
	@cd $(ZK_DIR) && cargo build --release --features concurrent \
		--target aarch64-apple-ios \
		--target x86_64-apple-ios
	@mkdir -p lib/ios lib/ios-sim
	@cp $(ZK_DIR)/target/aarch64-apple-ios/release/libzk_dilithium.a lib/ios/
	@cp $(ZK_DIR)/target/x86_64-apple-ios/release/libzk_dilithium.a lib/ios-sim/
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

build-android: zk-check | $(ZK_DIR)
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

# ── lazer backend ───────────────────────────────────────────────────────────

# lazer's headers pass unsigned long long* where GMP declares unsigned long*.
# Clang under Go >= 1.27 rejects that instead of warning, so the -tags pq_lazer
# build needs it demoted. Upstream issue in lazer, not in this repo.
LAZER_CFLAGS := -Wno-incompatible-pointer-types

build-lazer: $(ZK_LIB)
	CGO_CFLAGS="$(LAZER_CFLAGS)" go build -tags pq_lazer ./...

test-lazer: $(ZK_LIB)
	CGO_CFLAGS="$(LAZER_CFLAGS)" go test -tags pq_lazer -v ./...

# ── tests ───────────────────────────────────────────────────────────────────

test-go: build
	go test -v ./...

test-rust: zk-check | $(ZK_DIR)
	@cd $(ZK_DIR) && cargo test --release --features concurrent -- --nocapture

# ── clean ───────────────────────────────────────────────────────────────────

# Only the build tree; the committed lib/ archives are deliberately kept.
clean:
	rm -f main
	rm -rf $(ZK_DIR)/target

clean-all: clean
	rm -rf $(ZK_DIR)