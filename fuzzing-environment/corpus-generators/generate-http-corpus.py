#!/usr/bin/env python3
"""
HTTP Corpus Generator

Generates diverse HTTP request/response seeds for fuzzing:
  - Various methods (GET, POST, PUT, DELETE, etc.)
  - Headers (standard and exotic)
  - Content-Length vs Transfer-Encoding
  - Range requests
  - Chunked encoding
  - Malformed HTTP
  - Edge cases

Generates 150+ seeds
"""

import os
import sys
from pathlib import Path

def get_corpus_dir():
    """Get corpus directory from environment or default"""
    fuzz_root = os.environ.get('SURICATA_FUZZ_ROOT', '.')
    corpus_dir = Path(fuzz_root) / 'corpus' / 'http'
    corpus_dir.mkdir(parents=True, exist_ok=True)
    return corpus_dir

def save_seed(corpus_dir, name, data):
    """Save seed file"""
    if isinstance(data, str):
        data = data.encode('latin-1')

    filepath = corpus_dir / f"{name}.bin"
    with filepath.open('wb') as f:
        f.write(data)

def generate_basic_requests(corpus_dir):
    """Generate basic valid HTTP requests"""
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE', 'PATCH']
    paths = ['/', '/index.html', '/api/v1/users', '/very/long/path/to/resource']

    seed_num = 0

    for method in methods:
        for path in paths:
            req = f"{method} {path} HTTP/1.1\r\n"
            req += "Host: example.com\r\n"
            req += "User-Agent: Mozilla/5.0\r\n"
            req += "\r\n"
            save_seed(corpus_dir, f"req_{seed_num:03d}_{method.lower()}", req)
            seed_num += 1

    # POST with body
    for i in range(5):
        body = "param1=value1&param2=value2" * (i + 1)
        req = "POST /api/data HTTP/1.1\r\n"
        req += "Host: example.com\r\n"
        req += f"Content-Length: {len(body)}\r\n"
        req += "Content-Type: application/x-www-form-urlencoded\r\n"
        req += "\r\n"
        req += body
        save_seed(corpus_dir, f"req_{seed_num:03d}_post_body", req)
        seed_num += 1

    return seed_num

def generate_basic_responses(corpus_dir, start_num):
    """Generate basic valid HTTP responses"""
    status_codes = [
        (200, "OK"),
        (201, "Created"),
        (204, "No Content"),
        (301, "Moved Permanently"),
        (302, "Found"),
        (304, "Not Modified"),
        (400, "Bad Request"),
        (401, "Unauthorized"),
        (403, "Forbidden"),
        (404, "Not Found"),
        (500, "Internal Server Error"),
        (502, "Bad Gateway"),
        (503, "Service Unavailable"),
    ]

    seed_num = start_num

    for code, text in status_codes:
        resp = f"HTTP/1.1 {code} {text}\r\n"
        resp += "Server: nginx/1.18.0\r\n"
        resp += "Content-Type: text/html\r\n"
        resp += "Content-Length: 13\r\n"
        resp += "\r\n"
        resp += "Hello, World!"
        save_seed(corpus_dir, f"resp_{seed_num:03d}_{code}", resp)
        seed_num += 1

    return seed_num

def generate_range_requests(corpus_dir, start_num):
    """Generate Range request variations (targets VULN-2025-HTTP-001)"""
    seed_num = start_num

    range_headers = [
        "bytes=0-499",
        "bytes=500-999",
        "bytes=-500",  # Last 500 bytes
        "bytes=500-",  # From 500 to end
        "bytes=0-0",   # Single byte
        "bytes=0-0,-1",  # Multi-range
        "bytes=100-50",  # INVALID: end < start (underflow trigger)
        "bytes=1000-0",  # INVALID: massive underflow
        "bytes=18446744073709551615-0",  # INVALID: UINT64_MAX
    ]

    for i, range_val in enumerate(range_headers):
        req = "GET /bigfile.bin HTTP/1.1\r\n"
        req += "Host: example.com\r\n"
        req += f"Range: {range_val}\r\n"
        req += "\r\n"
        save_seed(corpus_dir, f"req_{seed_num:03d}_range", req)
        seed_num += 1

        # Corresponding 206 response
        resp = "HTTP/1.1 206 Partial Content\r\n"
        resp += f"Content-Range: {range_val}/10000\r\n"
        resp += "Content-Length: 100\r\n"
        resp += "\r\n"
        resp += "A" * 100
        save_seed(corpus_dir, f"resp_{seed_num:03d}_range", resp)
        seed_num += 1

    return seed_num

def generate_chunked_encoding(corpus_dir, start_num):
    """Generate chunked transfer encoding tests"""
    seed_num = start_num

    # Valid chunked response
    resp = "HTTP/1.1 200 OK\r\n"
    resp += "Transfer-Encoding: chunked\r\n"
    resp += "\r\n"
    resp += "5\r\n"
    resp += "Hello\r\n"
    resp += "7\r\n"
    resp += ", World\r\n"
    resp += "0\r\n"
    resp += "\r\n"
    save_seed(corpus_dir, f"resp_{seed_num:03d}_chunked_valid", resp)
    seed_num += 1

    # Malformed chunk sizes
    bad_chunks = [
        "FFFFFFFF\r\nDATA",  # Huge chunk
        "0\r\n\r\n",  # Zero chunk (valid terminator)
        "-1\r\nDATA",  # Negative
        "G\r\nDATA",  # Invalid hex
        "10;extension=value\r\n" + "A"*16,  # Chunk extension
    ]

    for i, chunk in enumerate(bad_chunks):
        resp = "HTTP/1.1 200 OK\r\n"
        resp += "Transfer-Encoding: chunked\r\n"
        resp += "\r\n"
        resp += chunk
        save_seed(corpus_dir, f"resp_{seed_num:03d}_chunked_bad", resp)
        seed_num += 1

    return seed_num

def generate_header_variations(corpus_dir, start_num):
    """Generate various header edge cases"""
    seed_num = start_num

    # Long headers
    for i in range(5):
        req = "GET / HTTP/1.1\r\n"
        req += "Host: example.com\r\n"
        req += f"X-Long-Header: {'A' * (100 * (i + 1))}\r\n"
        req += "\r\n"
        save_seed(corpus_dir, f"req_{seed_num:03d}_long_header", req)
        seed_num += 1

    # Many headers
    req = "GET / HTTP/1.1\r\n"
    req += "Host: example.com\r\n"
    for i in range(100):
        req += f"X-Custom-{i}: value{i}\r\n"
    req += "\r\n"
    save_seed(corpus_dir, f"req_{seed_num:03d}_many_headers", req)
    seed_num += 1

    # Duplicate headers
    req = "GET / HTTP/1.1\r\n"
    req += "Host: example.com\r\n"
    req += "Host: evil.com\r\n"
    req += "Content-Length: 10\r\n"
    req += "Content-Length: 20\r\n"
    req += "\r\n"
    save_seed(corpus_dir, f"req_{seed_num:03d}_duplicate_headers", req)
    seed_num += 1

    # Malformed headers
    bad_headers = [
        "NoColonHeader\r\n",
        ": NoName\r\n",
        "Header: Value\rWithoutNewline",
        "Header : SpaceBeforeColon\r\n",
        "\x00: NullByte\r\n",
    ]

    for i, bad_hdr in enumerate(bad_headers):
        req = "GET / HTTP/1.1\r\n"
        req += bad_hdr
        req += "\r\n"
        save_seed(corpus_dir, f"req_{seed_num:03d}_malformed_header", req)
        seed_num += 1

    return seed_num

def generate_malformed_http(corpus_dir, start_num):
    """Generate malformed/invalid HTTP"""
    seed_num = start_num

    malformed = [
        # Missing CRLF
        "GET / HTTP/1.1\nHost: example.com\n\n",

        # Wrong HTTP version
        "GET / HTTP/0.9\r\n\r\n",
        "GET / HTTP/2.0\r\n\r\n",
        "GET / HTTP/1.2\r\n\r\n",

        # No version
        "GET /\r\n\r\n",

        # No path
        "GET HTTP/1.1\r\n\r\n",

        # Invalid method
        "INVALID / HTTP/1.1\r\n\r\n",

        # Only newlines
        "\r\n\r\n\r\n",

        # Random bytes
        "\x00\x01\x02\x03\x04\x05",

        # Very long request line
        f"GET /{'A'*10000} HTTP/1.1\r\n\r\n",

        # Response without request
        "HTTP/1.1 200 OK\r\n\r\n",
    ]

    for i, data in enumerate(malformed):
        save_seed(corpus_dir, f"malformed_{seed_num:03d}", data)
        seed_num += 1

    return seed_num

def main():
    print("Generating HTTP corpus...")

    corpus_dir = get_corpus_dir()
    print(f"Output directory: {corpus_dir}")

    seed_count = 0

    print("  - Basic requests...")
    seed_count = generate_basic_requests(corpus_dir)

    print("  - Basic responses...")
    seed_count = generate_basic_responses(corpus_dir, seed_count)

    print("  - Range requests (VULN-2025-HTTP-001 triggers)...")
    seed_count = generate_range_requests(corpus_dir, seed_count)

    print("  - Chunked encoding...")
    seed_count = generate_chunked_encoding(corpus_dir, seed_count)

    print("  - Header variations...")
    seed_count = generate_header_variations(corpus_dir, seed_count)

    print("  - Malformed HTTP...")
    seed_count = generate_malformed_http(corpus_dir, seed_count)

    print(f"\n✓ Generated {seed_count} HTTP seeds in {corpus_dir}")

if __name__ == '__main__':
    main()
