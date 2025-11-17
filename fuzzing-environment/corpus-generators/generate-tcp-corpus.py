#!/usr/bin/env python3
"""
TCP Stream Reassembly Corpus Generator

Generates diverse TCP segment test cases:
  - Valid TCP segments
  - Out-of-order delivery
  - Retransmissions
  - Overlapping segments
  - Sequence number edge cases
  - Window manipulation
  - Various TCP flags

Generates 120+ seeds
"""

import os
import struct
from pathlib import Path

def get_corpus_dir():
    fuzz_root = os.environ.get('FUZZING_ROOT', '.')
    corpus_dir = Path(fuzz_root) / 'corpus' / 'tcp'
    corpus_dir.mkdir(parents=True, exist_ok=True)
    return corpus_dir

def save_seed(corpus_dir, name, data):
    filepath = corpus_dir / f"{name}.bin"
    with filepath.open('wb') as f:
        f.write(data)

def make_tcp_header(sport=12345, dport=80, seq=1000, ack=0,
                   flags=0, window=65535, payload_len=0):
    """Create TCP header"""
    data_offset = 5  # 5 * 4 = 20 bytes (no options)
    offset_flags = (data_offset << 12) | flags

    header = struct.pack('!HHIIHHH',
        sport,
        dport,
        seq,
        ack,
        offset_flags,
        window,
        0  # Checksum
    )
    header += struct.pack('!H', 0)  # Urgent pointer

    return header

def generate_valid_segments(corpus_dir):
    """Generate valid TCP segments"""
    seed_num = 0

    # TCP flags
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10

    # SYN
    pkt = make_tcp_header(flags=SYN, seq=1000)
    save_seed(corpus_dir, f"tcp_{seed_num:03d}_syn", pkt)
    seed_num += 1

    # SYN-ACK
    pkt = make_tcp_header(flags=SYN|ACK, seq=2000, ack=1001)
    save_seed(corpus_dir, f"tcp_{seed_num:03d}_synack", pkt)
    seed_num += 1

    # ACK
    pkt = make_tcp_header(flags=ACK, seq=1001, ack=2001)
    save_seed(corpus_dir, f"tcp_{seed_num:03d}_ack", pkt)
    seed_num += 1

    # Data segments
    for i in range(10):
        size = 100 * (i + 1)
        payload = b'A' * size
        pkt = make_tcp_header(flags=PSH|ACK, seq=1001 + i*100, ack=2001, payload_len=size)
        pkt += payload
        save_seed(corpus_dir, f"tcp_{seed_num:03d}_data", pkt)
        seed_num += 1

    # FIN
    pkt = make_tcp_header(flags=FIN|ACK, seq=2000, ack=1001)
    save_seed(corpus_dir, f"tcp_{seed_num:03d}_fin", pkt)
    seed_num += 1

    # RST
    pkt = make_tcp_header(flags=RST, seq=2000)
    save_seed(corpus_dir, f"tcp_{seed_num:03d}_rst", pkt)
    seed_num += 1

    return seed_num

def generate_out_of_order(corpus_dir, start_num):
    """Generate out-of-order segments"""
    seed_num = start_num

    FIN = 0x01
    PSH = 0x08
    ACK = 0x10

    # Send segments out of order
    segments = [
        (1500, b'C' * 500),  # Segment 3
        (1000, b'B' * 500),  # Segment 2
        (500, b'A' * 500),   # Segment 1
        (2000, b'D' * 500),  # Segment 4
    ]

    for seq, payload in segments:
        pkt = make_tcp_header(flags=PSH|ACK, seq=seq, ack=1000, payload_len=len(payload))
        pkt += payload
        save_seed(corpus_dir, f"tcp_{seed_num:03d}_ooo", pkt)
        seed_num += 1

    return seed_num

def generate_overlapping(corpus_dir, start_num):
    """Generate overlapping segments"""
    seed_num = start_num

    PSH = 0x08
    ACK = 0x10

    # Overlapping data
    overlaps = [
        (1000, b'A' * 500),
        (1200, b'B' * 500),  # Overlaps last 300 bytes of first
        (1000, b'C' * 1000), # Completely overlaps both
    ]

    for seq, payload in overlaps:
        pkt = make_tcp_header(flags=PSH|ACK, seq=seq, ack=1000, payload_len=len(payload))
        pkt += payload
        save_seed(corpus_dir, f"tcp_{seed_num:03d}_overlap", pkt)
        seed_num += 1

    return seed_num

def generate_retransmissions(corpus_dir, start_num):
    """Generate retransmission scenarios"""
    seed_num = start_num

    PSH = 0x08
    ACK = 0x10

    # Same sequence, different data (retransmission with corruption)
    for i in range(3):
        payload = bytes([ord('A') + i]) * 500
        pkt = make_tcp_header(flags=PSH|ACK, seq=5000, ack=1000, payload_len=len(payload))
        pkt += payload
        save_seed(corpus_dir, f"tcp_{seed_num:03d}_retrans", pkt)
        seed_num += 1

    return seed_num

def generate_seq_edge_cases(corpus_dir, start_num):
    """Generate sequence number edge cases"""
    seed_num = start_num

    PSH = 0x08
    ACK = 0x10

    edge_seqs = [
        0,  # Zero
        1,  # Minimum
        0xFFFFFFFF,  # Maximum (wraparound)
        0xFFFFFFF0,  # Near wraparound
        0x80000000,  # Middle
    ]

    for seq in edge_seqs:
        payload = b'X' * 100
        pkt = make_tcp_header(flags=PSH|ACK, seq=seq, ack=1000, payload_len=len(payload))
        pkt += payload
        save_seed(corpus_dir, f"tcp_{seed_num:03d}_seq_edge", pkt)
        seed_num += 1

    # Sequence wraparound
    pkt1 = make_tcp_header(flags=PSH|ACK, seq=0xFFFFFFF0, ack=1000, payload_len=100)
    pkt1 += b'Y' * 100
    save_seed(corpus_dir, f"tcp_{seed_num:03d}_wrap1", pkt1)
    seed_num += 1

    pkt2 = make_tcp_header(flags=PSH|ACK, seq=0x00000050, ack=1000, payload_len=100)
    pkt2 += b'Z' * 100
    save_seed(corpus_dir, f"tcp_{seed_num:03d}_wrap2", pkt2)
    seed_num += 1

    return seed_num

def generate_window_edge_cases(corpus_dir, start_num):
    """Generate window size edge cases"""
    seed_num = start_num

    ACK = 0x10

    windows = [0, 1, 100, 1000, 32768, 65535]

    for window in windows:
        pkt = make_tcp_header(flags=ACK, seq=1000, ack=1000, window=window)
        save_seed(corpus_dir, f"tcp_{seed_num:03d}_window", pkt)
        seed_num += 1

    return seed_num

def generate_flag_combinations(corpus_dir, start_num):
    """Generate various flag combinations"""
    seed_num = start_num

    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20

    # Invalid/unusual flag combinations
    flag_combos = [
        SYN | FIN,       # SYN+FIN (invalid)
        SYN | RST,       # SYN+RST (invalid)
        FIN | RST,       # FIN+RST (unusual)
        0,               # No flags
        0xFF,            # All flags
        URG | PSH | ACK, # URG+PSH+ACK
    ]

    for flags in flag_combos:
        pkt = make_tcp_header(flags=flags, seq=1000, ack=1000)
        save_seed(corpus_dir, f"tcp_{seed_num:03d}_flags", pkt)
        seed_num += 1

    return seed_num

def generate_malformed(corpus_dir, start_num):
    """Generate malformed TCP segments"""
    seed_num = start_num

    malformed = [
        # Truncated header
        b'\x30\x39\x00\x50',

        # Data offset too small (< 5)
        struct.pack('!HHIIHHH',
            12345, 80, 1000, 0,
            (4 << 12),  # offset = 4 (16 bytes, but min is 20)
            65535, 0) + b'\x00\x00',

        # Data offset too large
        struct.pack('!HHIIHHH',
            12345, 80, 1000, 0,
            (15 << 12),  # offset = 15 (60 bytes)
            65535, 0) + b'\x00\x00',

        # Zero checksum with data
        make_tcp_header() + b'DATA',
    ]

    for data in malformed:
        save_seed(corpus_dir, f"tcp_{seed_num:03d}_malformed", data)
        seed_num += 1

    # Random noise
    for i in range(10):
        save_seed(corpus_dir, f"tcp_{seed_num:03d}_random", os.urandom(50 + i * 10))
        seed_num += 1

    return seed_num

def main():
    print("Generating TCP corpus...")

    corpus_dir = get_corpus_dir()
    print(f"Output directory: {corpus_dir}")

    seed_count = 0

    print("  - Valid segments...")
    seed_count = generate_valid_segments(corpus_dir)

    print("  - Out-of-order segments...")
    seed_count = generate_out_of_order(corpus_dir, seed_count)

    print("  - Overlapping segments...")
    seed_count = generate_overlapping(corpus_dir, seed_count)

    print("  - Retransmissions...")
    seed_count = generate_retransmissions(corpus_dir, seed_count)

    print("  - Sequence number edge cases...")
    seed_count = generate_seq_edge_cases(corpus_dir, seed_count)

    print("  - Window edge cases...")
    seed_count = generate_window_edge_cases(corpus_dir, seed_count)

    print("  - Flag combinations...")
    seed_count = generate_flag_combinations(corpus_dir, seed_count)

    print("  - Malformed segments...")
    seed_count = generate_malformed(corpus_dir, seed_count)

    print(f"\n✓ Generated {seed_count} TCP seeds in {corpus_dir}")

if __name__ == '__main__':
    main()
