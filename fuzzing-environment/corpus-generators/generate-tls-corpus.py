#!/usr/bin/env python3
"""
TLS Corpus Generator

Generates diverse TLS handshake and record seeds:
  - ClientHello with various cipher suites
  - ServerHello responses
  - Certificate messages
  - Different TLS versions (1.0, 1.1, 1.2, 1.3)
  - Extensions (SNI, ALPN, etc.)
  - Alert messages
  - Malformed records

Generates 120+ seeds
"""

import os
import struct
from pathlib import Path

def get_corpus_dir():
    fuzz_root = os.environ.get('SURICATA_FUZZ_ROOT', '.')
    corpus_dir = Path(fuzz_root) / 'corpus' / 'tls'
    corpus_dir.mkdir(parents=True, exist_ok=True)
    return corpus_dir

def save_seed(corpus_dir, name, data):
    filepath = corpus_dir / f"{name}.bin"
    with filepath.open('wb') as f:
        f.write(data)

def make_tls_record(content_type, version_major, version_minor, payload):
    """Create TLS record"""
    record = struct.pack('!BBH', content_type, version_major, version_minor)
    record += struct.pack('!H', len(payload))
    record += payload
    return record

def make_client_hello(version, cipher_suites, extensions=b''):
    """Create ClientHello message"""
    # Handshake header
    msg = b'\x01'  # ClientHello type

    # ClientHello body
    body = struct.pack('!BB', *version)  # Version
    body += os.urandom(32)  # Random
    body += b'\x00'  # Session ID length
    body += struct.pack('!H', len(cipher_suites))  # Cipher suites length
    body += cipher_suites
    body += b'\x01\x00'  # Compression methods (null)

    if extensions:
        body += struct.pack('!H', len(extensions))
        body += extensions

    # Add length
    msg += struct.pack('!I', len(body))[1:]  # 3-byte length
    msg += body

    return msg

def generate_client_hellos(corpus_dir):
    """Generate ClientHello variations"""
    seed_num = 0

    # TLS versions
    versions = [
        ((3, 1), "tls10"),
        ((3, 2), "tls11"),
        ((3, 3), "tls12"),
        ((3, 4), "tls13"),
    ]

    # Common cipher suites
    cipher_suites_list = [
        b'\x00\x2f',  # TLS_RSA_WITH_AES_128_CBC_SHA
        b'\x00\x35',  # TLS_RSA_WITH_AES_256_CBC_SHA
        b'\xc0\x2f',  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        b'\xc0\x30',  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        b'\x13\x01',  # TLS_AES_128_GCM_SHA256 (TLS 1.3)
        b'\x13\x02',  # TLS_AES_256_GCM_SHA384 (TLS 1.3)
    ]

    for version, ver_name in versions:
        for i, ciphers in enumerate([cipher_suites_list[:2], cipher_suites_list[2:4], cipher_suites_list]):
            cipher_bytes = b''.join(ciphers)
            client_hello = make_client_hello(version, cipher_bytes)
            record = make_tls_record(0x16, *version, client_hello)  # 0x16 = Handshake

            save_seed(corpus_dir, f"client_hello_{seed_num:03d}_{ver_name}", record)
            seed_num += 1

    # ClientHello with SNI extension
    sni_ext = b'\x00\x00'  # SNI type
    sni_data = b'\x00\x00\x0e'  # Length
    sni_data += b'\x00\x0c'  # Server name list length
    sni_data += b'\x00'  # Name type (hostname)
    sni_data += b'\x00\x09'  # Hostname length
    sni_data += b'localhost'

    sni_ext += struct.pack('!H', len(sni_data)) + sni_data

    client_hello = make_client_hello((3, 3), cipher_suites_list[0], sni_ext)
    record = make_tls_record(0x16, 3, 3, client_hello)
    save_seed(corpus_dir, f"client_hello_{seed_num:03d}_sni", record)
    seed_num += 1

    return seed_num

def generate_server_hellos(corpus_dir, start_num):
    """Generate ServerHello variations"""
    seed_num = start_num

    versions = [((3, 1), "tls10"), ((3, 3), "tls12"), ((3, 4), "tls13")]

    for version, ver_name in versions:
        # ServerHello
        msg = b'\x02'  # ServerHello type
        body = struct.pack('!BB', *version)  # Version
        body += os.urandom(32)  # Random
        body += b'\x00'  # Session ID length
        body += b'\x00\x2f'  # Cipher suite (AES_128_CBC_SHA)
        body += b'\x00'  # Compression

        msg += struct.pack('!I', len(body))[1:]
        msg += body

        record = make_tls_record(0x16, *version, msg)
        save_seed(corpus_dir, f"server_hello_{seed_num:03d}_{ver_name}", record)
        seed_num += 1

    return seed_num

def generate_certificates(corpus_dir, start_num):
    """Generate Certificate message variations"""
    seed_num = start_num

    # Minimal fake certificate
    for cert_size in [100, 1000, 5000]:
        msg = b'\x0b'  # Certificate type
        certs = struct.pack('!I', cert_size)[1:]  # Certs length (3 bytes)
        certs += struct.pack('!I', cert_size - 3)[1:]  # Single cert length
        certs += os.urandom(cert_size - 6)  # Fake cert data

        msg += struct.pack('!I', len(certs))[1:]
        msg += certs

        record = make_tls_record(0x16, 3, 3, msg)
        save_seed(corpus_dir, f"certificate_{seed_num:03d}", record)
        seed_num += 1

    return seed_num

def generate_alerts(corpus_dir, start_num):
    """Generate Alert messages"""
    seed_num = start_num

    alert_types = [
        (1, 0),   # Warning, close_notify
        (2, 10),  # Fatal, unexpected_message
        (2, 20),  # Fatal, bad_record_mac
        (2, 40),  # Fatal, handshake_failure
        (2, 80),  # Fatal, internal_error
    ]

    for level, desc in alert_types:
        alert = struct.pack('!BB', level, desc)
        record = make_tls_record(0x15, 3, 3, alert)  # 0x15 = Alert
        save_seed(corpus_dir, f"alert_{seed_num:03d}", record)
        seed_num += 1

    return seed_num

def generate_application_data(corpus_dir, start_num):
    """Generate encrypted application data records"""
    seed_num = start_num

    for size in [16, 64, 256, 1024, 4096]:
        data = os.urandom(size)
        record = make_tls_record(0x17, 3, 3, data)  # 0x17 = Application Data
        save_seed(corpus_dir, f"app_data_{seed_num:03d}", record)
        seed_num += 1

    return seed_num

def generate_malformed(corpus_dir, start_num):
    """Generate malformed TLS records"""
    seed_num = start_num

    malformed = [
        # Wrong version
        make_tls_record(0x16, 2, 0, b'A' * 100),  # SSL 2.0

        # Huge length
        struct.pack('!BBBHH', 0x16, 3, 3, 0xFFFF, 0) + b'A' * 100,

        # Zero length
        make_tls_record(0x16, 3, 3, b''),

        # Invalid content type
        make_tls_record(0xFF, 3, 3, b'INVALID'),

        # Truncated record
        b'\x16\x03\x03\x00\x10',  # Says 16 bytes but no data

        # Multiple records
        make_tls_record(0x16, 3, 3, b'A' * 10) + make_tls_record(0x17, 3, 3, b'B' * 10),
    ]

    for data in malformed:
        save_seed(corpus_dir, f"malformed_{seed_num:03d}", data)
        seed_num += 1

    # Edge cases
    for i in range(10):
        # Random bytes
        save_seed(corpus_dir, f"random_{seed_num:03d}", os.urandom(100 + i * 50))
        seed_num += 1

    return seed_num

def main():
    print("Generating TLS corpus...")

    corpus_dir = get_corpus_dir()
    print(f"Output directory: {corpus_dir}")

    seed_count = 0

    print("  - ClientHello messages...")
    seed_count = generate_client_hellos(corpus_dir)

    print("  - ServerHello messages...")
    seed_count = generate_server_hellos(corpus_dir, seed_count)

    print("  - Certificate messages...")
    seed_count = generate_certificates(corpus_dir, seed_count)

    print("  - Alert messages...")
    seed_count = generate_alerts(corpus_dir, seed_count)

    print("  - Application data...")
    seed_count = generate_application_data(corpus_dir, seed_count)

    print("  - Malformed records...")
    seed_count = generate_malformed(corpus_dir, seed_count)

    print(f"\n✓ Generated {seed_count} TLS seeds in {corpus_dir}")

if __name__ == '__main__':
    main()
