#!/usr/bin/env bash
# build-ios.sh — builds Hysteria2.xcframework for iOS (arm64) and iOS Simulator (arm64 + x86_64).
#
# Prerequisites:
#   • Go 1.21+  (with CGO_ENABLED=1)
#   • Xcode Command Line Tools (xcode-select --install)
#   • Go module dependencies fetched:  go mod download
#
# Output:
#   ../../3rd-prebuilt/3rd-prebuilt/hysteria2/Hysteria2.xcframework
#
# Usage:
#   cd client/3rd/hysteria2-apple
#   go mod download
#   ./build-ios.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$SCRIPT_DIR/../../3rd-prebuilt/3rd-prebuilt/hysteria2"
INCLUDE_DIR="$SCRIPT_DIR/include"
MIN_IOS_VERSION="14.0"

mkdir -p "$OUT_DIR" "$INCLUDE_DIR"

# build_slice GOARCH SDK_NAME CLANG_ARCH TARGET_TRIPLE OUTPUT_A
# Example:
#   build_slice arm64 iphoneos arm64 arm64-apple-ios14.0 libhysteria2_ios_arm64.a
#   build_slice arm64 iphonesimulator arm64 arm64-apple-ios14.0-simulator libhysteria2_sim_arm64.a
#   build_slice amd64 iphonesimulator x86_64 x86_64-apple-ios14.0-simulator libhysteria2_sim_x86_64.a
build_slice() {
    local goarch="$1"
    local sdk="$2"
    local clang_arch="$3"
    local target="$4"
    local out="$5"

    local sdk_path
    sdk_path="$(xcrun --sdk "$sdk" --show-sdk-path)"

    CGO_ENABLED=1 \
    GOOS=ios \
    GOARCH="$goarch" \
    CGO_CFLAGS="-isysroot $sdk_path -arch $clang_arch -target $target -mios-version-min=$MIN_IOS_VERSION" \
    CGO_LDFLAGS="-isysroot $sdk_path -arch $clang_arch -target $target" \
    go build -mod=mod -buildmode=c-archive -o "$SCRIPT_DIR/$out" .

    echo "Built $out"
}

cd "$SCRIPT_DIR"

# ── iOS device (arm64) ──────────────────────────────────────────────────────
build_slice arm64 iphoneos arm64 \
    "arm64-apple-ios${MIN_IOS_VERSION}" \
    libhysteria2_ios_arm64.a

# Copy the auto-generated header (identical across architectures)
cp "$SCRIPT_DIR/libhysteria2_ios_arm64.h" "$INCLUDE_DIR/hysteria2.h"

# ── iOS Simulator arm64 (Apple Silicon Mac) ─────────────────────────────────
build_slice arm64 iphonesimulator arm64 \
    "arm64-apple-ios${MIN_IOS_VERSION}-simulator" \
    libhysteria2_sim_arm64.a

# ── iOS Simulator x86_64 (Intel Mac) ────────────────────────────────────────
build_slice amd64 iphonesimulator x86_64 \
    "x86_64-apple-ios${MIN_IOS_VERSION}-simulator" \
    libhysteria2_sim_x86_64.a

# ── Fat simulator library ────────────────────────────────────────────────────
lipo -create \
    "$SCRIPT_DIR/libhysteria2_sim_arm64.a" \
    "$SCRIPT_DIR/libhysteria2_sim_x86_64.a" \
    -output "$SCRIPT_DIR/libhysteria2_sim_fat.a"

# ── Assemble xcframework ─────────────────────────────────────────────────────
rm -rf "$OUT_DIR/Hysteria2.xcframework"
xcodebuild -create-xcframework \
    -library "$SCRIPT_DIR/libhysteria2_ios_arm64.a" \
    -headers "$INCLUDE_DIR" \
    -library "$SCRIPT_DIR/libhysteria2_sim_fat.a" \
    -headers "$INCLUDE_DIR" \
    -output "$OUT_DIR/Hysteria2.xcframework"

echo "Done: $OUT_DIR/Hysteria2.xcframework"

# ── Clean up intermediate files ──────────────────────────────────────────────
rm -f "$SCRIPT_DIR"/libhysteria2_*.a "$SCRIPT_DIR"/libhysteria2_*.h
