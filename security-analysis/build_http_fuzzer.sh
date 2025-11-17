#!/bin/bash
#
# Build Suricata HTTP fuzzer with AFL++ and ASAN
#
# This script builds a fuzzing harness targeting the HTTP parser,
# which has the highest CVE count and most complex attack surface.
#

set -e

echo "[+] Building Suricata HTTP Fuzzer"
echo "[+] Target: app-layer-htp.c and related HTTP parsing code"
echo ""

# Check for AFL++
if ! command -v afl-clang-fast &> /dev/null; then
    echo "[-] AFL++ not found. Install with:"
    echo "    git clone https://github.com/AFLplusplus/AFLplusplus"
    echo "    cd AFLplusplus && make && sudo make install"
    exit 1
fi

# Setup environment for AFL++ with ASAN
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_USE_ASAN=1
export CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1"
export CXXFLAGS="$CFLAGS"
export LDFLAGS="-fsanitize=address"

echo "[+] Configuring Suricata with fuzzing optimizations..."

# Clean previous builds
make distclean 2>/dev/null || true

# Generate configure script if needed
if [ ! -f configure ]; then
    ./autogen.sh
fi

# Configure with minimal dependencies
./configure \
    --enable-debug \
    --enable-debug-validation \
    --disable-shared \
    --enable-fuzztargets \
    --disable-geoip \
    --disable-lua \
    --disable-rust \
    --prefix=/tmp/suricata-fuzz \
    CC="$CC" \
    CFLAGS="$CFLAGS"

echo "[+] Building Suricata library..."
make -j$(nproc)

echo "[+] Building fuzzer harness..."
$CC $CFLAGS \
    -I./src \
    -I./libhtp \
    -I./rust/gen/c-headers \
    security-analysis/http_fuzzer.c \
    -o http_fuzzer \
    src/.libs/libsuricata.a \
    libhtp/.libs/libhtp.a \
    -lpthread -lpcre -lyaml -lz -lm

echo ""
echo "[+] Fuzzer built successfully: ./http_fuzzer"
echo "[+] Testing fuzzer with sample input..."

# Test run
echo "GET / HTTP/1.1\r\nHost: test\r\n\r\n" | ./http_fuzzer

echo ""
echo "[+] Build complete!"
echo ""
echo "Next steps:"
echo "  1. Generate corpus: python3 security-analysis/generate_http_corpus.py"
echo "  2. Start fuzzing: afl-fuzz -i corpus_http -o findings_http -m none -- ./http_fuzzer"
echo "  3. Monitor with: afl-whatsup findings_http"
echo ""
