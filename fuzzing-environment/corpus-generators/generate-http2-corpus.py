#!/usr/bin/env python3
"""
HTTP/2 Corpus Generator

Generates diverse HTTP/2 frame seeds:
  - Frame headers (9 bytes)
  - DATA frames
  - HEADERS frames
  - SETTINGS frames
  - PRIORITY, PING, GOAWAY
  - Stream multiplexing
  - HPACK header compression

Generates 110+ seeds
"""

import os
import struct
from pathlib import Path

def get_corpus_dir():
    fuzz_root = os.environ.get('SURICATA_FUZZ_ROOT', '.')
    corpus_dir = Path(fuzz_root) / 'corpus' / 'http2'
    corpus_dir.mkdir(parents=True, exist_ok=True)
    return corpus_dir

def save_seed(corpus_dir, name, data):
    filepath = corpus_dir / f"{name}.bin"
    with filepath.open('wb') as f:
        f.write(data)

# Frame types
DATA = 0x0
HEADERS = 0x1
PRIORITY = 0x2
RST_STREAM = 0x3
SETTINGS = 0x4
PUSH_PROMISE = 0x5
PING = 0x6
GOAWAY = 0x7
WINDOW_UPDATE = 0x8
CONTINUATION = 0x9

# Flags
END_STREAM = 0x1
END_HEADERS = 0x4
PADDED = 0x8
PRIORITY_FLAG = 0x20

def make_frame(frame_type, flags, stream_id, payload):
    """Create HTTP/2 frame"""
    length = len(payload)
    header = struct.pack('!I', length)[1:]  # 3-byte length
    header += struct.pack('!BB', frame_type, flags)
    header += struct.pack('!I', stream_id & 0x7FFFFFFF)  # 31-bit stream ID
    return header + payload

def generate_connection_preface(corpus_dir):
    """Generate connection preface and initial frames"""
    seed_num = 0

    # Connection preface
    preface = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
    save_seed(corpus_dir, f"http2_{seed_num:03d}_preface", preface)
    seed_num += 1

    # SETTINGS frame (empty)
    frame = make_frame(SETTINGS, 0, 0, b'')
    save_seed(corpus_dir, f"http2_{seed_num:03d}_settings_empty", frame)
    seed_num += 1

    # SETTINGS with values
    settings = struct.pack('!HI', 3, 100)  # MAX_CONCURRENT_STREAMS = 100
    settings += struct.pack('!HI', 4, 65535)  # INITIAL_WINDOW_SIZE = 65535
    frame = make_frame(SETTINGS, 0, 0, settings)
    save_seed(corpus_dir, f"http2_{seed_num:03d}_settings", frame)
    seed_num += 1

    # SETTINGS ACK
    frame = make_frame(SETTINGS, 0x1, 0, b'')  # ACK flag
    save_seed(corpus_dir, f"http2_{seed_num:03d}_settings_ack", frame)
    seed_num += 1

    return seed_num

def generate_data_frames(corpus_dir, start_num):
    """Generate DATA frames"""
    seed_num = start_num

    # Simple DATA frames
    for stream_id in [1, 3, 5]:
        for size in [0, 10, 100, 1000, 8192]:
            payload = b'A' * size
            frame = make_frame(DATA, 0, stream_id, payload)
            save_seed(corpus_dir, f"http2_{seed_num:03d}_data", frame)
            seed_num += 1

    # DATA with END_STREAM
    frame = make_frame(DATA, END_STREAM, 1, b'Final data')
    save_seed(corpus_dir, f"http2_{seed_num:03d}_data_end", frame)
    seed_num += 1

    # DATA with padding
    pad_len = 10
    payload = struct.pack('!B', pad_len) + b'Data' + (b'\x00' * pad_len)
    frame = make_frame(DATA, PADDED, 1, payload)
    save_seed(corpus_dir, f"http2_{seed_num:03d}_data_padded", frame)
    seed_num += 1

    return seed_num

def generate_headers_frames(corpus_dir, start_num):
    """Generate HEADERS frames"""
    seed_num = start_num

    # Simple HEADERS (literal without indexing)
    # :method: GET
    headers = b'\x00'  # Literal header field without indexing
    headers += b'\x07:method'  # Name length + name
    headers += b'\x03GET'      # Value length + value

    frame = make_frame(HEADERS, END_HEADERS, 1, headers)
    save_seed(corpus_dir, f"http2_{seed_num:03d}_headers_get", frame)
    seed_num += 1

    # HEADERS with END_STREAM
    frame = make_frame(HEADERS, END_HEADERS | END_STREAM, 3, headers)
    save_seed(corpus_dir, f"http2_{seed_num:03d}_headers_end", frame)
    seed_num += 1

    # HEADERS with priority
    priority = struct.pack('!I', 0)  # Stream dependency
    priority += struct.pack('!B', 16)  # Weight
    frame = make_frame(HEADERS, PRIORITY_FLAG | END_HEADERS, 5, priority + headers)
    save_seed(corpus_dir, f"http2_{seed_num:03d}_headers_priority", frame)
    seed_num += 1

    # Multiple header fields
    headers = b''
    for i in range(10):
        headers += b'\x00'
        name = f'x-custom-{i}'.encode()
        value = f'value{i}'.encode()
        headers += bytes([len(name)]) + name
        headers += bytes([len(value)]) + value

    frame = make_frame(HEADERS, END_HEADERS, 7, headers)
    save_seed(corpus_dir, f"http2_{seed_num:03d}_headers_many", frame)
    seed_num += 1

    return seed_num

def generate_priority_frames(corpus_dir, start_num):
    """Generate PRIORITY frames"""
    seed_num = start_num

    for stream_id in [1, 3, 5]:
        for dependency in [0, 1, stream_id - 1 if stream_id > 1 else 0]:
            payload = struct.pack('!I', dependency)
            payload += struct.pack('!B', 16)  # Weight
            frame = make_frame(PRIORITY, 0, stream_id, payload)
            save_seed(corpus_dir, f"http2_{seed_num:03d}_priority", frame)
            seed_num += 1

    return seed_num

def generate_rst_stream_frames(corpus_dir, start_num):
    """Generate RST_STREAM frames"""
    seed_num = start_num

    error_codes = [0, 1, 2, 3, 7, 11]  # Various error codes

    for stream_id in [1, 3, 5]:
        for error_code in error_codes:
            payload = struct.pack('!I', error_code)
            frame = make_frame(RST_STREAM, 0, stream_id, payload)
            save_seed(corpus_dir, f"http2_{seed_num:03d}_rst", frame)
            seed_num += 1

    return seed_num

def generate_ping_frames(corpus_dir, start_num):
    """Generate PING frames"""
    seed_num = start_num

    # PING
    payload = b'\x01\x02\x03\x04\x05\x06\x07\x08'
    frame = make_frame(PING, 0, 0, payload)
    save_seed(corpus_dir, f"http2_{seed_num:03d}_ping", frame)
    seed_num += 1

    # PING ACK
    frame = make_frame(PING, 0x1, 0, payload)
    save_seed(corpus_dir, f"http2_{seed_num:03d}_ping_ack", frame)
    seed_num += 1

    return seed_num

def generate_goaway_frames(corpus_dir, start_num):
    """Generate GOAWAY frames"""
    seed_num = start_num

    error_codes = [0, 1, 2, 11]

    for last_stream in [0, 1, 10, 100]:
        for error_code in error_codes:
            payload = struct.pack('!I', last_stream)
            payload += struct.pack('!I', error_code)
            payload += b'Debug data'
            frame = make_frame(GOAWAY, 0, 0, payload)
            save_seed(corpus_dir, f"http2_{seed_num:03d}_goaway", frame)
            seed_num += 1

    return seed_num

def generate_window_update_frames(corpus_dir, start_num):
    """Generate WINDOW_UPDATE frames"""
    seed_num = start_num

    increments = [1, 100, 1000, 65535, 0x7FFFFFFF]

    for stream_id in [0, 1, 3]:
        for increment in increments:
            payload = struct.pack('!I', increment & 0x7FFFFFFF)
            frame = make_frame(WINDOW_UPDATE, 0, stream_id, payload)
            save_seed(corpus_dir, f"http2_{seed_num:03d}_window", frame)
            seed_num += 1

    return seed_num

def generate_malformed(corpus_dir, start_num):
    """Generate malformed frames"""
    seed_num = start_num

    malformed = [
        # Truncated frame header
        b'\x00\x00\x10\x00\x00',  # Only 5 bytes

        # Wrong frame length
        make_frame(DATA, 0, 1, b'A' * 100)[:-50],  # Says 100 bytes but only 50

        # Invalid stream ID 0 for stream-specific frame
        make_frame(DATA, 0, 0, b'Invalid'),

        # SETTINGS on non-zero stream
        make_frame(SETTINGS, 0, 1, b''),

        # Huge frame length
        b'\xFF\xFF\xFF' + struct.pack('!BBI', 0, 0, 1) + b'A' * 100,
    ]

    for data in malformed:
        save_seed(corpus_dir, f"http2_{seed_num:03d}_malformed", data)
        seed_num += 1

    # Random
    for i in range(10):
        save_seed(corpus_dir, f"http2_{seed_num:03d}_random", os.urandom(50 + i * 10))
        seed_num += 1

    return seed_num

def main():
    print("Generating HTTP/2 corpus...")

    corpus_dir = get_corpus_dir()
    print(f"Output directory: {corpus_dir}")

    seed_count = 0

    print("  - Connection preface...")
    seed_count = generate_connection_preface(corpus_dir)

    print("  - DATA frames...")
    seed_count = generate_data_frames(corpus_dir, seed_count)

    print("  - HEADERS frames...")
    seed_count = generate_headers_frames(corpus_dir, seed_count)

    print("  - PRIORITY frames...")
    seed_count = generate_priority_frames(corpus_dir, seed_count)

    print("  - RST_STREAM frames...")
    seed_count = generate_rst_stream_frames(corpus_dir, seed_count)

    print("  - PING frames...")
    seed_count = generate_ping_frames(corpus_dir, seed_count)

    print("  - GOAWAY frames...")
    seed_count = generate_goaway_frames(corpus_dir, seed_count)

    print("  - WINDOW_UPDATE frames...")
    seed_count = generate_window_update_frames(corpus_dir, seed_count)

    print("  - Malformed frames...")
    seed_count = generate_malformed(corpus_dir, seed_count)

    print(f"\n✓ Generated {seed_count} HTTP/2 seeds in {corpus_dir}")

if __name__ == '__main__':
    main()
