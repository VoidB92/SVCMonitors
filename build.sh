#!/bin/bash
# =============================================================================
# build.sh — One-click build script for SVCModule KPM
# =============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KPM_DIR="$SCRIPT_DIR/kpm"
BUILD_DIR="$KPM_DIR/build"
OUTPUT="$BUILD_DIR/svc_monitor.kpm"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN} SVCModule KPM Build Script${NC}"
echo -e "${GREEN} Target: ARM64 / kernel 5.10.43${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""

# ---- Check toolchain ----
CROSS_COMPILE="${CROSS_COMPILE:-aarch64-linux-gnu-}"
CC="${CC:-${CROSS_COMPILE}gcc}"
LD="${LD:-${CROSS_COMPILE}ld}"

# Try to find compiler
if ! command -v "$CC" &>/dev/null; then
    # Try Android NDK
    if [ -n "$NDK_HOME" ]; then
        CLANG="$NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/clang"
        if [ -x "$CLANG" ]; then
            CC="$CLANG --target=aarch64-linux-android31"
            LD="$NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/ld.lld"
            echo -e "${GREEN}[OK]${NC} Using NDK clang: $CLANG"
        else
            echo -e "${RED}[ERROR]${NC} NDK clang not found at: $CLANG"
            exit 1
        fi
    else
        echo -e "${RED}[ERROR]${NC} Cross-compiler not found: $CC"
        echo ""
        echo "Please install one of:"
        echo "  1. sudo apt install gcc-aarch64-linux-gnu"
        echo "  2. Set NDK_HOME to Android NDK path"
        echo "  3. Set CROSS_COMPILE to your toolchain prefix"
        exit 1
    fi
else
    echo -e "${GREEN}[OK]${NC} Compiler: $CC"
fi

# ---- Build ----
mkdir -p "$BUILD_DIR"

SRC="$KPM_DIR/src/svc_monitor_v10.c"
OBJ="$BUILD_DIR/svc_monitor.o"
KPM="$BUILD_DIR/svc_monitor.kpm"

CFLAGS="-Wall -Wextra -Werror=implicit-function-declaration \
        -std=gnu11 -O2 \
        -fno-common -fno-builtin -fno-stack-protector \
        -fno-exceptions -fno-asynchronous-unwind-tables \
        -fno-unwind-tables -nostdlib -nostdinc \
        -ffreestanding -fPIC \
        -I$SCRIPT_DIR/kp_headers"

echo ""
echo -e "${YELLOW}[1/2]${NC} Compiling svc_monitor_v10.c ..."
$CC $CFLAGS -c "$SRC" -o "$OBJ"
echo -e "       ${GREEN}OK${NC} → $OBJ"

echo -e "${YELLOW}[2/2]${NC} Linking svc_monitor.kpm ..."
$LD -shared -nostdlib -o "$KPM" "$OBJ"
echo -e "       ${GREEN}OK${NC} → $KPM"

# ---- Summary ----
echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN} Build Successful!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo "  Output:  $KPM"
echo "  Size:    $(du -h "$KPM" | cut -f1)"
echo ""
echo "To deploy on device:"
echo "  1. adb push $KPM /data/local/tmp/svc_monitor.kpm"
echo "  2. adb shell su -c 'kpatch <superkey> kpm load /data/local/tmp/svc_monitor.kpm'"
echo ""
echo "To unload:"
echo "  adb shell su -c 'kpatch <superkey> kpm unload svc_monitor'"
echo ""
