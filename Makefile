# Convenience targets for building the Wazuh Desktop Agent.
#
# Usage:
#   make build            — Debug build for the host platform
#   make release          — Optimised release build for the host
#   make test             — Run all tests
#   make lint             — Format check + clippy
#   make all-targets      — Cross-compile for every supported target
#   make clean            — Remove build artefacts

CARGO  := cargo
CROSS  := cross

# All cross-compilation targets
TARGETS := \
	x86_64-unknown-linux-gnu \
	x86_64-unknown-linux-musl \
	aarch64-unknown-linux-gnu \
	x86_64-apple-darwin \
	aarch64-apple-darwin \
	x86_64-pc-windows-msvc

.PHONY: build release test lint fmt clippy all-targets clean

build:
	$(CARGO) build

release:
	$(CARGO) build --release

test:
	$(CARGO) test --all

lint: fmt clippy

fmt:
	$(CARGO) fmt --all -- --check

clippy:
	$(CARGO) clippy --all-targets --all-features -- -D warnings

all-targets: $(addprefix build-,$(TARGETS))

build-%:
	$(CROSS) build --release --target $*

clean:
	$(CARGO) clean
