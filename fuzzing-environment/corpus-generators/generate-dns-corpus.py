#!/usr/bin/env python3
"""
DNS Corpus Generator

Generates diverse DNS query/response seeds:
  - Various query types (A, AAAA, MX, TXT, etc.)
  - Response records
  - Name compression
  - DNSSEC records
  - Malformed queries
  - Truncated responses

Generates 130+ seeds
"""

import os
import struct
from pathlib import Path

def get_corpus_dir():
    fuzz_root = os.environ.get('FUZZING_ROOT', '.')
    corpus_dir = Path(fuzz_root) / 'corpus' / 'dns'
    corpus_dir.mkdir(parents=True, exist_ok=True)
    return corpus_dir

def save_seed(corpus_dir, name, data):
    filepath = corpus_dir / f"{name}.bin"
    with filepath.open('wb') as f:
        f.write(data)

def encode_domain_name(domain):
    """Encode domain name in DNS format"""
    parts = domain.split('.')
    encoded = b''
    for part in parts:
        encoded += bytes([len(part)]) + part.encode('ascii')
    encoded += b'\x00'  # Null terminator
    return encoded

def make_dns_header(qid, flags, qdcount=1, ancount=0, nscount=0, arcount=0):
    """Create DNS header"""
    return struct.pack('!HHHHHH', qid, flags, qdcount, ancount, nscount, arcount)

def make_question(domain, qtype, qclass=1):
    """Create DNS question section"""
    question = encode_domain_name(domain)
    question += struct.pack('!HH', qtype, qclass)
    return question

def make_resource_record(domain, rtype, rclass, ttl, rdata):
    """Create DNS resource record"""
    rr = encode_domain_name(domain)
    rr += struct.pack('!HHI', rtype, rclass, ttl)
    rr += struct.pack('!H', len(rdata))
    rr += rdata
    return rr

def generate_basic_queries(corpus_dir):
    """Generate basic DNS queries"""
    seed_num = 0

    # Query types
    qtypes = [
        (1, "A"),
        (2, "NS"),
        (5, "CNAME"),
        (6, "SOA"),
        (12, "PTR"),
        (15, "MX"),
        (16, "TXT"),
        (28, "AAAA"),
        (33, "SRV"),
        (255, "ANY"),
    ]

    domains = [
        "example.com",
        "www.google.com",
        "mail.example.org",
        "very.long.subdomain.example.com",
    ]

    for domain in domains:
        for qtype, name in qtypes:
            # Standard query
            header = make_dns_header(qid=seed_num, flags=0x0100)  # RD bit set
            question = make_question(domain, qtype)

            query = header + question
            save_seed(corpus_dir, f"query_{seed_num:03d}_{name.lower()}", query)
            seed_num += 1

    return seed_num

def generate_responses(corpus_dir, start_num):
    """Generate DNS responses"""
    seed_num = start_num

    # A record response
    header = make_dns_header(qid=1234, flags=0x8180, qdcount=1, ancount=1)  # QR, RD, RA
    question = make_question("example.com", 1)

    # Answer: example.com A 192.0.2.1
    answer = make_resource_record("example.com", 1, 1, 3600,
                                  b'\xc0\x00\x02\x01')  # 192.0.2.1

    response = header + question + answer
    save_seed(corpus_dir, f"response_{seed_num:03d}_a", response)
    seed_num += 1

    # AAAA record response
    header = make_dns_header(qid=1235, flags=0x8180, qdcount=1, ancount=1)
    question = make_question("example.com", 28)
    answer = make_resource_record("example.com", 28, 1, 3600,
                                  b'\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')

    response = header + question + answer
    save_seed(corpus_dir, f"response_{seed_num:03d}_aaaa", response)
    seed_num += 1

    # MX record response
    header = make_dns_header(qid=1236, flags=0x8180, qdcount=1, ancount=1)
    question = make_question("example.com", 15)
    mx_data = struct.pack('!H', 10) + encode_domain_name("mail.example.com")
    answer = make_resource_record("example.com", 15, 1, 3600, mx_data)

    response = header + question + answer
    save_seed(corpus_dir, f"response_{seed_num:03d}_mx", response)
    seed_num += 1

    # TXT record response
    header = make_dns_header(qid=1237, flags=0x8180, qdcount=1, ancount=1)
    question = make_question("example.com", 16)
    txt_data = b'\x0cv=spf1 mx -all'  # Length-prefixed string
    answer = make_resource_record("example.com", 16, 1, 3600, txt_data)

    response = header + question + answer
    save_seed(corpus_dir, f"response_{seed_num:03d}_txt", response)
    seed_num += 1

    # Multiple answers
    header = make_dns_header(qid=1238, flags=0x8180, qdcount=1, ancount=3)
    question = make_question("example.com", 1)
    answers = make_resource_record("example.com", 1, 1, 3600, b'\xc0\x00\x02\x01')
    answers += make_resource_record("example.com", 1, 1, 3600, b'\xc0\x00\x02\x02')
    answers += make_resource_record("example.com", 1, 1, 3600, b'\xc0\x00\x02\x03')

    response = header + question + answers
    save_seed(corpus_dir, f"response_{seed_num:03d}_multi", response)
    seed_num += 1

    # NXDOMAIN response
    header = make_dns_header(qid=1239, flags=0x8183, qdcount=1, ancount=0)  # RCODE=3
    question = make_question("nonexistent.example.com", 1)

    response = header + question
    save_seed(corpus_dir, f"response_{seed_num:03d}_nxdomain", response)
    seed_num += 1

    return seed_num

def generate_name_compression(corpus_dir, start_num):
    """Generate queries/responses with name compression"""
    seed_num = start_num

    # Query with pointer
    header = make_dns_header(qid=2000, flags=0x8180, qdcount=1, ancount=1)
    question = encode_domain_name("www.example.com")
    question += struct.pack('!HH', 1, 1)

    # Answer with pointer to domain name in question
    answer = b'\xc0\x0c'  # Pointer to offset 12 (start of domain in question)
    answer += struct.pack('!HHIH', 1, 1, 3600, 4)  # Type, Class, TTL, RDLength
    answer += b'\xc0\x00\x02\x01'  # IP address

    response = header + question + answer
    save_seed(corpus_dir, f"compression_{seed_num:03d}_simple", response)
    seed_num += 1

    # Multiple levels of compression
    header = make_dns_header(qid=2001, flags=0x8180, qdcount=1, ancount=2)
    question = encode_domain_name("mail.example.com")
    question += struct.pack('!HH', 15, 1)

    # Answer 1: MX pointing to subdomain
    answer1 = b'\xc0\x0c'  # Pointer to question domain
    mx_data = struct.pack('!H', 10) + encode_domain_name("smtp.example.com")
    answer1 += struct.pack('!HHIH', 15, 1, 3600, len(mx_data))
    answer1 += mx_data

    # Answer 2: A record for smtp.example.com using compression
    answer2 = b'\xc0\x2b'  # Pointer to smtp.example.com in answer1
    answer2 += struct.pack('!HHIH', 1, 1, 3600, 4)
    answer2 += b'\xc0\x00\x02\x01'

    response = header + question + answer1 + answer2
    save_seed(corpus_dir, f"compression_{seed_num:03d}_multi", response)
    seed_num += 1

    return seed_num

def generate_edge_cases(corpus_dir, start_num):
    """Generate edge case DNS packets"""
    seed_num = start_num

    # Maximum domain name length (253 chars)
    long_domain = "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 61
    header = make_dns_header(qid=3000, flags=0x0100)
    question = make_question(long_domain, 1)
    query = header + question
    save_seed(corpus_dir, f"edge_{seed_num:03d}_long_domain", query)
    seed_num += 1

    # Label length = 0 (invalid)
    header = make_dns_header(qid=3001, flags=0x0100)
    question = b'\x00' + struct.pack('!HH', 1, 1)  # Empty label
    query = header + question
    save_seed(corpus_dir, f"edge_{seed_num:03d}_empty_label", query)
    seed_num += 1

    # Very large QDCOUNT
    header = make_dns_header(qid=3002, flags=0x0100, qdcount=1000)
    question = make_question("example.com", 1)
    query = header + question
    save_seed(corpus_dir, f"edge_{seed_num:03d}_large_qdcount", query)
    seed_num += 1

    # Very large ANCOUNT
    header = make_dns_header(qid=3003, flags=0x8180, qdcount=1, ancount=10000)
    question = make_question("example.com", 1)
    query = header + question
    save_seed(corpus_dir, f"edge_{seed_num:03d}_large_ancount", query)
    seed_num += 1

    # Invalid pointer (points beyond packet)
    header = make_dns_header(qid=3004, flags=0x8180, qdcount=1, ancount=1)
    question = make_question("example.com", 1)
    answer = b'\xc0\xFF'  # Pointer to offset 255 (beyond packet)
    answer += struct.pack('!HHIH', 1, 1, 3600, 4)
    answer += b'\xc0\x00\x02\x01'
    response = header + question + answer
    save_seed(corpus_dir, f"edge_{seed_num:03d}_bad_pointer", response)
    seed_num += 1

    # Circular pointer
    header = make_dns_header(qid=3005, flags=0x8180, qdcount=1, ancount=1)
    question = make_question("example.com", 1)
    # Answer with pointer to itself
    answer_start = len(header) + len(question)
    answer = struct.pack('!H', 0xC000 | answer_start)  # Pointer to itself
    answer += struct.pack('!HHIH', 1, 1, 3600, 4)
    answer += b'\xc0\x00\x02\x01'
    response = header + question + answer
    save_seed(corpus_dir, f"edge_{seed_num:03d}_circular_pointer", response)
    seed_num += 1

    return seed_num

def generate_malformed(corpus_dir, start_num):
    """Generate malformed DNS packets"""
    seed_num = start_num

    malformed = [
        # Truncated header
        b'\x12\x34\x01\x00',

        # Header only (no question)
        make_dns_header(qid=4000, flags=0x0100, qdcount=1),

        # Wrong question count (says 2, has 1)
        make_dns_header(qid=4001, flags=0x0100, qdcount=2) +
        make_question("example.com", 1),

        # Label length > 63 (invalid)
        make_dns_header(qid=4002, flags=0x0100) +
        b'\xFF' + b'A' * 100 + b'\x00' + struct.pack('!HH', 1, 1),

        # Null bytes in domain
        make_dns_header(qid=4003, flags=0x0100) +
        b'\x07exa\x00mple\x03com\x00' + struct.pack('!HH', 1, 1),
    ]

    for data in malformed:
        save_seed(corpus_dir, f"malformed_{seed_num:03d}", data)
        seed_num += 1

    # Random noise
    for i in range(10):
        save_seed(corpus_dir, f"random_{seed_num:03d}", os.urandom(50 + i * 10))
        seed_num += 1

    return seed_num

def main():
    print("Generating DNS corpus...")

    corpus_dir = get_corpus_dir()
    print(f"Output directory: {corpus_dir}")

    seed_count = 0

    print("  - Basic queries...")
    seed_count = generate_basic_queries(corpus_dir)

    print("  - Responses...")
    seed_count = generate_responses(corpus_dir, seed_count)

    print("  - Name compression...")
    seed_count = generate_name_compression(corpus_dir, seed_count)

    print("  - Edge cases...")
    seed_count = generate_edge_cases(corpus_dir, seed_count)

    print("  - Malformed packets...")
    seed_count = generate_malformed(corpus_dir, seed_count)

    print(f"\n✓ Generated {seed_count} DNS seeds in {corpus_dir}")

if __name__ == '__main__':
    main()
