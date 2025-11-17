#!/usr/bin/env python3
"""
Generate intelligent HTTP corpus for Suricata fuzzing

Based on CVE analysis, focuses on:
1. HTTP Range requests (CVE-2024-38536 - integer overflow patterns)
2. Content-Length manipulation (historical overflow issues)
3. Multipart boundaries (complex state machine)
4. Header accumulation (buffer overflow patterns)
5. Chunked encoding (parser complexity)
6. X-Forwarded-For parsing (string handling bugs)
"""

import os
import struct
import sys

def generate_valid_http():
    """Generate valid baseline HTTP requests for coverage"""
    requests = [
        # Simple GET
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",

        # POST with body
        b"POST /api HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Content-Length: 13\r\n"
        b"\r\n"
        b"Hello, World!",

        # Multiple headers
        b"GET /path HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: Mozilla/5.0\r\n"
        b"Accept: */*\r\n"
        b"Accept-Encoding: gzip, deflate\r\n"
        b"\r\n",

        # Chunked encoding
        b"POST / HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"5\r\n"
        b"Hello\r\n"
        b"6\r\n"
        b"World!\r\n"
        b"0\r\n"
        b"\r\n",

        # HTTP response
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html\r\n"
        b"Content-Length: 13\r\n"
        b"\r\n"
        b"Hello, World!",
    ]
    return requests

def generate_range_attacks():
    """Generate HTTP Range requests targeting CVE-2024-38536 patterns"""
    attacks = []

    # Integer overflow patterns from app-layer-htp-range.c:264
    # const uint64_t buflen = end - start + 1;

    # Pattern 1: end < start (underflow)
    attacks.append(
        b"GET /file.bin HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Range: bytes=100-50\r\n"  # end < start
        b"\r\n"
    )

    # Pattern 2: Massive range
    attacks.append(
        b"GET /file.bin HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Range: bytes=0-18446744073709551615\r\n"  # UINT64_MAX
        b"\r\n"
    )

    # Pattern 3: Many overlapping ranges
    ranges = ",".join([f"0-{i}" for i in range(1, 100)])
    attacks.append(
        b"GET /file.bin HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Range: bytes=" + ranges.encode() + b"\r\n"
        b"\r\n"
    )

    # Pattern 4: Response with Content-Range
    attacks.append(
        b"HTTP/1.1 206 Partial Content\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Range: bytes 0-99/18446744073709551615\r\n"
        b"Content-Length: 100\r\n"
        b"\r\n" + b"A" * 100
    )

    # Pattern 5: Invalid range syntax
    attacks.append(
        b"GET /file HTTP/1.1\r\n"
        b"Range: bytes=0-0-0\r\n"
        b"\r\n"
    )

    return attacks

def generate_integer_overflow():
    """Target integer overflow vulnerabilities identified in analysis"""
    attacks = []

    # Content-Length integer overflow
    for value in [0xFFFFFFFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE]:
        attacks.append(
            b"POST / HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Content-Length: " + str(value).encode() + b"\r\n"
            b"\r\n"
        )

    # Negative Content-Length (unsigned interpretation)
    attacks.append(
        b"POST / HTTP/1.1\r\n"
        b"Content-Length: -1\r\n"
        b"\r\n"
    )

    # Huge chunk size in chunked encoding
    attacks.append(
        b"POST / HTTP/1.1\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"FFFFFFFF\r\n"  # Max uint32
        b"data\r\n"
        b"0\r\n\r\n"
    )

    # Conflicting Content-Length and Transfer-Encoding (request smuggling)
    attacks.append(
        b"POST / HTTP/1.1\r\n"
        b"Content-Length: 6\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"0\r\n\r\n"
    )

    return attacks

def generate_multipart_attacks():
    """Target multipart parsing state machine (app-layer-htp.c:1095-1197)"""
    attacks = []

    # Simple multipart POST
    boundary = b"----WebKitFormBoundary"
    attacks.append(
        b"POST /upload HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Content-Type: multipart/form-data; boundary=" + boundary + b"\r\n"
        b"Content-Length: 150\r\n"
        b"\r\n"
        b"--" + boundary + b"\r\n"
        b"Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n"
        b"\r\n"
        b"File content here\r\n"
        b"--" + boundary + b"--\r\n"
    )

    # Missing closing boundary
    attacks.append(
        b"POST /upload HTTP/1.1\r\n"
        b"Content-Type: multipart/form-data; boundary=" + boundary + b"\r\n"
        b"Content-Length: 100\r\n"
        b"\r\n"
        b"--" + boundary + b"\r\n"
        b"Content-Disposition: form-data; name=\"file\"\r\n"
        b"\r\n"
        b"data" + b"A" * 50
        # No closing boundary
    )

    # Extremely long filename (target app-layer-htp-file.c:189-195)
    long_filename = b"A" * 8192
    attacks.append(
        b"POST /upload HTTP/1.1\r\n"
        b"Content-Type: multipart/form-data; boundary=" + boundary + b"\r\n"
        b"\r\n"
        b"--" + boundary + b"\r\n"
        b"Content-Disposition: form-data; filename=\"" + long_filename + b"\"\r\n"
        b"\r\n"
        b"data\r\n"
        b"--" + boundary + b"--\r\n"
    )

    # Nested boundaries
    attacks.append(
        b"POST /upload HTTP/1.1\r\n"
        b"Content-Type: multipart/form-data; boundary=outer\r\n"
        b"\r\n"
        b"--outer\r\n"
        b"Content-Type: multipart/mixed; boundary=inner\r\n"
        b"\r\n"
        b"--inner\r\n"
        b"data\r\n"
        b"--inner--\r\n"
        b"--outer--\r\n"
    )

    return attacks

def generate_header_attacks():
    """Target header accumulation overflow (app-layer-htp.c:1869-1871)"""
    attacks = []

    # Many headers (targeting accumulation)
    many_headers = b"GET / HTTP/1.1\r\n"
    for i in range(500):
        many_headers += f"X-Header-{i}: value{i}\r\n".encode()
    many_headers += b"\r\n"
    attacks.append(many_headers)

    # Extremely long single header value
    attacks.append(
        b"GET / HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"X-Long-Header: " + b"A" * 16384 + b"\r\n"
        b"\r\n"
    )

    # Header continuation (folded headers - CVE-2024-23837 related)
    attacks.append(
        b"GET / HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"X-Folded: line1\r\n"
        b" line2\r\n"
        b" line3\r\n" * 100 +
        b"\r\n"
    )

    # NULL bytes in header (targeting XFF parser app-layer-htp-xff.c:59-95)
    attacks.append(
        b"GET / HTTP/1.1\r\n"
        b"Host: evil\x00.com\r\n"
        b"X-Forwarded-For: 127.0.0.1\x00, 192.168.1.1\r\n"
        b"\r\n"
    )

    # CR/LF injection
    attacks.append(
        b"GET / HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"X-Evil: value\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: evil.com\r\n"
        b"\r\n"
    )

    return attacks

def generate_malformed():
    """Generate malformed requests for parser stress testing"""
    malformed = []

    # Missing HTTP version
    malformed.append(b"GET / \r\n\r\n")

    # Invalid HTTP version
    malformed.append(b"GET / HTTP/999.999\r\n\r\n")

    # Missing CRLF (only LF)
    malformed.append(b"GET / HTTP/1.1\nHost: example.com\n\n")

    # Truncated request
    malformed.append(b"GET / HTTP/1.1\r\nHost: exa")

    # Only headers, no request line
    malformed.append(b"Host: example.com\r\n\r\n")

    # Binary garbage
    malformed.append(b"\x00\x01\x02\x03\x04\x05" * 20)
    malformed.append(struct.pack("!I", 0xDEADBEEF) * 10)

    # Mixed valid/invalid
    malformed.append(
        b"GET / HTTP/1.1\r\n"
        b"\x00\x00\x00\x00\r\n"
        b"Host: test\r\n\r\n"
    )

    return malformed

def main():
    corpus_dir = "corpus_http"
    os.makedirs(corpus_dir, exist_ok=True)

    print("[+] Generating HTTP fuzzing corpus...")
    print(f"[+] Target directory: {corpus_dir}/")
    print()

    all_samples = []

    categories = [
        ("valid", generate_valid_http()),
        ("range", generate_range_attacks()),
        ("overflow", generate_integer_overflow()),
        ("multipart", generate_multipart_attacks()),
        ("headers", generate_header_attacks()),
        ("malformed", generate_malformed()),
    ]

    for category, samples in categories:
        print(f"  [{category:12s}] {len(samples):3d} samples")
        for i, sample in enumerate(samples):
            filename = f"{corpus_dir}/{category}_{i:04d}"
            with open(filename, "wb") as f:
                f.write(sample)
            all_samples.append(sample)

    print()
    print(f"[+] Generated {len(all_samples)} corpus files")
    print(f"[+] Total size: {sum(len(s) for s in all_samples):,} bytes")
    print()
    print("[+] Corpus ready for fuzzing!")
    print(f"[+] Start with: afl-fuzz -i {corpus_dir} -o findings_http -m none -- ./http_fuzzer")
    print()

if __name__ == "__main__":
    main()
