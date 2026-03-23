ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

ZK_REPO   := https://github.com/AVecsi/zkDilithium
ZK_DIR    := zkDilithiumProof
ZK_LIB    := $(ZK_DIR)/target/release/libzk_dilithium.a
ZK_HEADER := $(ZK_DIR)/zkDilithiumProof.h

.PHONY: build run test-go test-rust clean clean-all fetch-rust-lib build-ios build-android

# ── top-level ───────────────────────────────────────────────────────────────

build: $(ZK_LIB) $(ZK_HEADER)
	go build

run: build
	go test

# ── rust lib ────────────────────────────────────────────────────────────────

$(ZK_DIR):
	@if [ ! -f $(ZK_DIR)/Cargo.toml ]; then \
		rm -rf $(ZK_DIR) && git clone $(ZK_REPO) $(ZK_DIR); \
	fi

$(ZK_LIB) $(ZK_HEADER): | $(ZK_DIR)
	@cd $(ZK_DIR) && cargo build --release --features concurrent
	@mkdir -p lib
	@cp $(ZK_DIR)/target/release/libzk_dilithium.a lib/
	@cp $(ZK_DIR)/zkDilithiumProof.h lib/

# Force a fresh pull and rebuild of the Rust lib
fetch-rust-lib: | $(ZK_DIR)
	@cd $(ZK_DIR) && git pull
	@cd $(ZK_DIR) && cargo build --release --features concurrent
	@mkdir -p lib
	@cp $(ZK_DIR)/target/release/libzk_dilithium.a lib/
	@cp $(ZK_DIR)/zkDilithiumProof.h lib/

# ── mobile targets ──────────────────────────────────────────────────────────

build-ios: | $(ZK_DIR)
	@cd $(ZK_DIR) && cargo build --release \
		--target aarch64-apple-ios \
		--target x86_64-apple-ios
	@mkdir -p lib/ios
	@cp $(ZK_DIR)/target/aarch64-apple-ios/release/libzk_dilithium.a lib/
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
	@echo "Using NDK: $(NDK_BIN)"
	@export PATH=$(NDK_BIN):$$PATH && \
	cd $(ZK_DIR) && cargo build --release \
		--target aarch64-linux-android \
		--target armv7-linux-androideabi
	@mkdir -p lib/arm64-v8a lib/armeabi-v7a
	@cp $(ZK_DIR)/target/aarch64-linux-android/release/libzk_dilithium.a lib/arm64-v8a/
	@cp $(ZK_DIR)/target/armv7-linux-androideabi/release/libzk_dilithium.a lib/armeabi-v7a/
	@cp $(ZK_DIR)/zkDilithiumProof.h lib/

# ── tests ───────────────────────────────────────────────────────────────────

test-go: build
	go test -v ./...

test-rust: | $(ZK_DIR)
	@cd $(ZK_DIR) && cargo test --release --features concurrent -- --nocapture

# ── clean ───────────────────────────────────────────────────────────────────

clean:
	rm -f main
	rm -rf lib/
	rm -rf $(ZK_DIR)/target

clean-all: clean
	rm -rf $(ZK_DIR)