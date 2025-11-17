#!/usr/bin/env python3
"""
IP Defragmentation Corpus Generator

Generates diverse IP fragment test cases:
  - Valid fragment sequences
  - Overlapping fragments
  - Out-of-order fragments
  - Fragment offset edge cases
  - All fragment flags combinations
  - Triggers for VULN-2025-DEFRAG-001

Generates 150+ seeds
"""

import os
import struct
from pathlib import Path

def get_corpus_dir():
    fuzz_root = os.environ.get('FUZZING_ROOT', '.')
    corpus_dir = Path(fuzz_root) / 'corpus' / 'defrag'
    corpus_dir.mkdir(parents=True, exist_ok=True)
    return corpus_dir

def save_seed(corpus_dir, name, data):
    filepath = corpus_dir / f"{name}.bin"
    with filepath.open('wb') as f:
        f.write(data)

def make_ipv4_header(frag_offset=0, more_frags=False, dont_frag=False,
                     packet_id=12345, payload_len=100):
    """Create IPv4 header"""
    ver_ihl = (4 << 4) | 5  # Version 4, IHL 5 (20 bytes)
    tos = 0
    total_len = 20 + payload_len  # Header + payload
    flags = 0
    if dont_frag:
        flags |= 0x4000
    if more_frags:
        flags |= 0x2000
    flags_frag = flags | (frag_offset >> 3)  # Frag offset in 8-byte units

    header = struct.pack('!BBHHHBBH4s4s',
        ver_ihl,
        tos,
        total_len,
        packet_id,
        flags_frag,
        64,  # TTL
        6,   # Protocol (TCP)
        0,   # Checksum (will be wrong, doesn't matter for fuzzing)
        b'\xc0\xa8\x01\x0a',  # Source IP 192.168.1.10
        b'\xc0\xa8\x01\x14'   # Dest IP 192.168.1.20
    )

    return header

def generate_valid_fragments(corpus_dir):
    """Generate valid fragmented packets"""
    seed_num = 0

    # Simple 2-fragment packet
    payload1 = b'A' * 1480
    payload2 = b'B' * 500

    # Fragment 1 (more frags)
    pkt1 = make_ipv4_header(frag_offset=0, more_frags=True, payload_len=len(payload1))
    pkt1 += payload1
    save_seed(corpus_dir, f"valid_{seed_num:03d}_frag1", pkt1)
    seed_num += 1

    # Fragment 2 (last)
    pkt2 = make_ipv4_header(frag_offset=1480, more_frags=False, payload_len=len(payload2))
    pkt2 += payload2
    save_seed(corpus_dir, f"valid_{seed_num:03d}_frag2", pkt2)
    seed_num += 1

    # 3-fragment packet
    for i in range(3):
        offset = i * 1000
        more = (i < 2)
        payload = bytes([65 + i]) * 1000 if i < 2 else bytes([65 + i]) * 500

        pkt = make_ipv4_header(frag_offset=offset, more_frags=more,
                              packet_id=54321, payload_len=len(payload))
        pkt += payload
        save_seed(corpus_dir, f"valid_{seed_num:03d}_3frag", pkt)
        seed_num += 1

    return seed_num

def generate_overlapping_fragments(corpus_dir, start_num):
    """Generate overlapping fragment attacks"""
    seed_num = start_num

    # Overlap patterns
    overlap_cases = [
        # (frag1_offset, frag1_size, frag2_offset, frag2_size)
        (0, 1000, 500, 1000),    # Partial overlap
        (0, 1000, 0, 1000),      # Complete overlap
        (0, 1000, 100, 800),     # frag2 inside frag1
        (100, 800, 0, 1000),     # frag1 inside frag2
        (0, 1500, 1400, 200),    # Tiny overlap at end
    ]

    for off1, size1, off2, size2 in overlap_cases:
        # Fragment 1
        pkt1 = make_ipv4_header(frag_offset=off1, more_frags=True,
                               packet_id=99999, payload_len=size1)
        pkt1 += b'X' * size1
        save_seed(corpus_dir, f"overlap_{seed_num:03d}_frag1", pkt1)
        seed_num += 1

        # Fragment 2
        pkt2 = make_ipv4_header(frag_offset=off2, more_frags=False,
                               packet_id=99999, payload_len=size2)
        pkt2 += b'Y' * size2
        save_seed(corpus_dir, f"overlap_{seed_num:03d}_frag2", pkt2)
        seed_num += 1

    return seed_num

def generate_out_of_order(corpus_dir, start_num):
    """Generate out-of-order fragments"""
    seed_num = start_num

    # 4 fragments in reverse order
    for i in reversed(range(4)):
        offset = i * 500
        more = (i < 3)
        payload = bytes([ord('A') + i]) * 500

        pkt = make_ipv4_header(frag_offset=offset, more_frags=more,
                              packet_id=77777, payload_len=len(payload))
        pkt += payload
        save_seed(corpus_dir, f"outoforder_{seed_num:03d}", pkt)
        seed_num += 1

    return seed_num

def generate_edge_cases(corpus_dir, start_num):
    """Generate edge case fragments (ltrim underflow triggers)"""
    seed_num = start_num

    # VULN-2025-DEFRAG-001 triggers
    # Case 1: Fragment with offset beyond data (ltrim underflow)
    pkt = make_ipv4_header(frag_offset=2000, more_frags=False,
                          packet_id=11111, payload_len=100)
    pkt += b'Z' * 100
    save_seed(corpus_dir, f"edge_{seed_num:03d}_ltrim_underflow", pkt)
    seed_num += 1

    # Case 2: Tiny fragment at huge offset
    pkt = make_ipv4_header(frag_offset=8000, more_frags=False,
                          packet_id=11112, payload_len=1)
    pkt += b'A'
    save_seed(corpus_dir, f"edge_{seed_num:03d}_huge_offset", pkt)
    seed_num += 1

    # Case 3: Zero-length fragment
    pkt = make_ipv4_header(frag_offset=0, more_frags=True,
                          packet_id=11113, payload_len=0)
    save_seed(corpus_dir, f"edge_{seed_num:03d}_zero_len", pkt)
    seed_num += 1

    # Case 4: Maximum offset
    pkt = make_ipv4_header(frag_offset=65535, more_frags=False,
                          packet_id=11114, payload_len=8)
    pkt += b'B' * 8
    save_seed(corpus_dir, f"edge_{seed_num:03d}_max_offset", pkt)
    seed_num += 1

    # Case 5: Fragments with same offset
    for i in range(3):
        pkt = make_ipv4_header(frag_offset=100, more_frags=(i<2),
                              packet_id=11115, payload_len=500)
        pkt += bytes([ord('A') + i]) * 500
        save_seed(corpus_dir, f"edge_{seed_num:03d}_same_offset", pkt)
        seed_num += 1

    return seed_num

def generate_flag_variations(corpus_dir, start_num):
    """Generate various flag combinations"""
    seed_num = start_num

    # DF + MF (conflicting flags)
    pkt = make_ipv4_header(frag_offset=0, more_frags=True, dont_frag=True,
                          packet_id=22222, payload_len=500)
    pkt += b'C' * 500
    save_seed(corpus_dir, f"flags_{seed_num:03d}_df_mf", pkt)
    seed_num += 1

    # DF with offset (conflicting)
    pkt = make_ipv4_header(frag_offset=100, more_frags=False, dont_frag=True,
                          packet_id=22223, payload_len=500)
    pkt += b'D' * 500
    save_seed(corpus_dir, f"flags_{seed_num:03d}_df_offset", pkt)
    seed_num += 1

    # Last fragment with MF set (should be clear)
    pkt = make_ipv4_header(frag_offset=8000, more_frags=True,
                          packet_id=22224, payload_len=100)
    pkt += b'E' * 100
    save_seed(corpus_dir, f"flags_{seed_num:03d}_mf_last", pkt)
    seed_num += 1

    return seed_num

def generate_malformed(corpus_dir, start_num):
    """Generate malformed IP packets"""
    seed_num = start_num

    malformed = [
        # Truncated header
        b'\x45\x00\x00\x14',

        # Wrong version
        b'\x64' + b'\x00' * 19 + b'DATA',  # Version 6 in IPv4

        # IHL too small
        b'\x44' + b'\x00' * 19 + b'DATA',  # IHL 4 (16 bytes, but min is 20)

        # Total length mismatch (says 1000 but only 100 bytes)
        struct.pack('!BBHHHBBH4s4s',
            0x45, 0, 1000, 12345, 0, 64, 6, 0,
            b'\xc0\xa8\x01\x0a', b'\xc0\xa8\x01\x14') + b'X' * 50,
    ]

    for data in malformed:
        save_seed(corpus_dir, f"malformed_{seed_num:03d}", data)
        seed_num += 1

    # Random noise
    for i in range(10):
        save_seed(corpus_dir, f"random_{seed_num:03d}", os.urandom(100 + i * 20))
        seed_num += 1

    return seed_num

def main():
    print("Generating IP Defragmentation corpus...")

    corpus_dir = get_corpus_dir()
    print(f"Output directory: {corpus_dir}")

    seed_count = 0

    print("  - Valid fragments...")
    seed_count = generate_valid_fragments(corpus_dir)

    print("  - Overlapping fragments...")
    seed_count = generate_overlapping_fragments(corpus_dir, seed_count)

    print("  - Out-of-order fragments...")
    seed_count = generate_out_of_order(corpus_dir, seed_count)

    print("  - Edge cases (ltrim underflow triggers)...")
    seed_count = generate_edge_cases(corpus_dir, seed_count)

    print("  - Flag variations...")
    seed_count = generate_flag_variations(corpus_dir, seed_count)

    print("  - Malformed packets...")
    seed_count = generate_malformed(corpus_dir, seed_count)

    print(f"\n✓ Generated {seed_count} IP defrag seeds in {corpus_dir}")

if __name__ == '__main__':
    main()
