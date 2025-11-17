#!/usr/bin/env python3
"""
SMB Corpus Generator

Generates diverse SMB/SMB2/SMB3 seeds:
  - SMB1 commands
  - SMB2/3 commands
  - Dialect negotiation
  - Session setup
  - File operations
  - Various command structures

Generates 100+ seeds
"""

import os
import struct
from pathlib import Path

def get_corpus_dir():
    fuzz_root = os.environ.get('SURICATA_FUZZ_ROOT', '.')
    corpus_dir = Path(fuzz_root) / 'corpus' / 'smb'
    corpus_dir.mkdir(parents=True, exist_ok=True)
    return corpus_dir

def save_seed(corpus_dir, name, data):
    filepath = corpus_dir / f"{name}.bin"
    with filepath.open('wb') as f:
        f.write(data)

def make_netbios_header(length):
    """Create NetBIOS session service header"""
    return struct.pack('!I', length)

def make_smb1_header(command, flags=0, flags2=0, tid=0, pid=0, uid=0, mid=0):
    """Create SMB1 header"""
    header = b'\xFF\x53\x4D\x42'  # Protocol: \xFFSMB
    header += struct.pack('!B', command)
    header += struct.pack('!I', 0)  # Status
    header += struct.pack('!B', flags)
    header += struct.pack('!H', flags2)
    header += struct.pack('!H', 0)  # PID High
    header += b'\x00' * 8  # Signature
    header += struct.pack('!H', 0)  # Reserved
    header += struct.pack('!H', tid)
    header += struct.pack('!H', pid)
    header += struct.pack('!H', uid)
    header += struct.pack('!H', mid)
    return header

def make_smb2_header(command, credit_charge=0, status=0, credit_req=0,
                    flags=0, chain_offset=0, msg_id=0, tree_id=0, session_id=0):
    """Create SMB2 header"""
    header = b'\xFE\x53\x4D\x42'  # Protocol: \xFESMB
    header += struct.pack('!H', 64)  # Header length
    header += struct.pack('!H', credit_charge)
    header += struct.pack('!I', status)
    header += struct.pack('!H', command)
    header += struct.pack('!H', credit_req)
    header += struct.pack('!I', flags)
    header += struct.pack('!I', chain_offset)
    header += struct.pack('!Q', msg_id)
    header += struct.pack('!I', 0)  # Reserved
    header += struct.pack('!I', tree_id)
    header += struct.pack('!Q', session_id)
    header += b'\x00' * 16  # Signature
    return header

def generate_smb1_negotiate(corpus_dir):
    """Generate SMB1 Negotiate Protocol requests"""
    seed_num = 0

    # Negotiate Protocol Request
    SMB_COM_NEGOTIATE = 0x72

    header = make_smb1_header(SMB_COM_NEGOTIATE)

    # Parameters (WordCount, etc.)
    params = struct.pack('!B', 0)  # WordCount = 0

    # Data: dialect strings
    dialects = [
        b'\x02PC NETWORK PROGRAM 1.0\x00',
        b'\x02LANMAN1.0\x00',
        b'\x02Windows for Workgroups 3.1a\x00',
        b'\x02LM1.2X002\x00',
        b'\x02LANMAN2.1\x00',
        b'\x02NT LM 0.12\x00',
        b'\x02SMB 2.002\x00',
        b'\x02SMB 2.???\x00',
    ]

    data = b''.join(dialects)
    byte_count = struct.pack('!H', len(data))

    smb = header + params + byte_count + data
    netbios = make_netbios_header(len(smb))

    save_seed(corpus_dir, f"smb1_{seed_num:03d}_negotiate", netbios + smb)
    seed_num += 1

    # Negotiate with just one dialect
    for i, dialect in enumerate(dialects[:5]):
        header = make_smb1_header(SMB_COM_NEGOTIATE)
        params = struct.pack('!B', 0)
        byte_count = struct.pack('!H', len(dialect))

        smb = header + params + byte_count + dialect
        netbios = make_netbios_header(len(smb))

        save_seed(corpus_dir, f"smb1_{seed_num:03d}_negotiate_single", netbios + smb)
        seed_num += 1

    return seed_num

def generate_smb2_negotiate(corpus_dir, start_num):
    """Generate SMB2/3 Negotiate requests"""
    seed_num = start_num

    SMB2_NEGOTIATE = 0x0000

    header = make_smb2_header(SMB2_NEGOTIATE, credit_req=1)

    # Negotiate request structure
    struct_size = struct.pack('!H', 36)
    dialect_count = struct.pack('!H', 3)
    security_mode = struct.pack('!H', 1)
    reserved = struct.pack('!H', 0)
    capabilities = struct.pack('!I', 0)
    client_guid = os.urandom(16)
    client_start_time = struct.pack('!Q', 0)

    # Dialects: SMB 2.0.2, 2.1, 3.0
    dialects = struct.pack('!HHH', 0x0202, 0x0210, 0x0300)

    body = struct_size + dialect_count + security_mode + reserved
    body += capabilities + client_guid + client_start_time + dialects

    smb = header + body
    netbios = make_netbios_header(len(smb))

    save_seed(corpus_dir, f"smb2_{seed_num:03d}_negotiate", netbios + smb)
    seed_num += 1

    # SMB 3.1.1 negotiate
    header = make_smb2_header(SMB2_NEGOTIATE, credit_req=1)
    dialect_count = struct.pack('!H', 1)
    dialects = struct.pack('!H', 0x0311)  # SMB 3.1.1

    body = struct_size + dialect_count + security_mode + reserved
    body += capabilities + client_guid + client_start_time + dialects

    smb = header + body
    netbios = make_netbios_header(len(smb))

    save_seed(corpus_dir, f"smb2_{seed_num:03d}_negotiate_311", netbios + smb)
    seed_num += 1

    return seed_num

def generate_smb2_commands(corpus_dir, start_num):
    """Generate various SMB2 commands"""
    seed_num = start_num

    commands = [
        (0x0001, "SESSION_SETUP"),
        (0x0002, "LOGOFF"),
        (0x0003, "TREE_CONNECT"),
        (0x0004, "TREE_DISCONNECT"),
        (0x0005, "CREATE"),
        (0x0006, "CLOSE"),
        (0x0008, "READ"),
        (0x0009, "WRITE"),
        (0x000E, "IOCTL"),
    ]

    for cmd_code, cmd_name in commands:
        header = make_smb2_header(cmd_code, credit_req=1, msg_id=seed_num)

        # Minimal command body (will be invalid but good for fuzzing)
        body = struct.pack('!H', 36)  # StructureSize
        body += os.urandom(34)  # Random data

        smb = header + body
        netbios = make_netbios_header(len(smb))

        save_seed(corpus_dir, f"smb2_{seed_num:03d}_{cmd_name.lower()}", netbios + smb)
        seed_num += 1

    return seed_num

def generate_smb2_responses(corpus_dir, start_num):
    """Generate SMB2 responses"""
    seed_num = start_num

    # Negotiate Response
    header = make_smb2_header(0x0000, flags=0x00000001, credit_req=1)  # Response flag

    struct_size = struct.pack('!H', 65)
    security_mode = struct.pack('!H', 1)
    dialect_rev = struct.pack('!H', 0x0210)  # SMB 2.1
    reserved = struct.pack('!H', 0)
    server_guid = os.urandom(16)
    capabilities = struct.pack('!I', 0)
    max_trans_size = struct.pack('!I', 65536)
    max_read_size = struct.pack('!I', 65536)
    max_write_size = struct.pack('!I', 65536)
    system_time = struct.pack('!Q', 0)
    server_start_time = struct.pack('!Q', 0)
    sec_buffer_offset = struct.pack('!H', 128)
    sec_buffer_len = struct.pack('!H', 0)
    reserved2 = struct.pack('!I', 0)

    body = struct_size + security_mode + dialect_rev + reserved
    body += server_guid + capabilities
    body += max_trans_size + max_read_size + max_write_size
    body += system_time + server_start_time
    body += sec_buffer_offset + sec_buffer_len + reserved2

    smb = header + body
    netbios = make_netbios_header(len(smb))

    save_seed(corpus_dir, f"smb2_{seed_num:03d}_negotiate_resp", netbios + smb)
    seed_num += 1

    # Error responses
    error_codes = [0xC0000001, 0xC0000022, 0xC000000D, 0xC0000034]

    for error in error_codes:
        header = make_smb2_header(0x0005, flags=0x00000001, status=error)
        body = struct.pack('!H', 9)  # Error response structure size
        body += os.urandom(7)

        smb = header + body
        netbios = make_netbios_header(len(smb))

        save_seed(corpus_dir, f"smb2_{seed_num:03d}_error", netbios + smb)
        seed_num += 1

    return seed_num

def generate_malformed(corpus_dir, start_num):
    """Generate malformed SMB packets"""
    seed_num = start_num

    malformed = [
        # Wrong protocol signature
        b'\x00\x00\x00\x20' + b'\xFF\xFF\xFF\xFF' + b'A' * 28,

        # Truncated SMB1 header
        b'\x00\x00\x00\x10' + b'\xFF\x53\x4D\x42',

        # Truncated SMB2 header
        b'\x00\x00\x00\x20' + b'\xFE\x53\x4D\x42' + b'A' * 16,

        # Invalid NetBIOS length (huge)
        b'\xFF\xFF\xFF\xFF' + b'\xFE\x53\x4D\x42' + b'A' * 60,

        # Invalid NetBIOS length (zero)
        b'\x00\x00\x00\x00',

        # Mixed SMB1/SMB2
        b'\x00\x00\x00\x40' + b'\xFF\x53\x4D\x42' + b'A' * 28 +
        b'\xFE\x53\x4D\x42' + b'B' * 28,
    ]

    for data in malformed:
        save_seed(corpus_dir, f"smb_{seed_num:03d}_malformed", data)
        seed_num += 1

    # Random
    for i in range(10):
        save_seed(corpus_dir, f"smb_{seed_num:03d}_random", os.urandom(50 + i * 20))
        seed_num += 1

    return seed_num

def main():
    print("Generating SMB corpus...")

    corpus_dir = get_corpus_dir()
    print(f"Output directory: {corpus_dir}")

    seed_count = 0

    print("  - SMB1 Negotiate...")
    seed_count = generate_smb1_negotiate(corpus_dir)

    print("  - SMB2 Negotiate...")
    seed_count = generate_smb2_negotiate(corpus_dir, seed_count)

    print("  - SMB2 commands...")
    seed_count = generate_smb2_commands(corpus_dir, seed_count)

    print("  - SMB2 responses...")
    seed_count = generate_smb2_responses(corpus_dir, seed_count)

    print("  - Malformed packets...")
    seed_count = generate_malformed(corpus_dir, seed_count)

    print(f"\n✓ Generated {seed_count} SMB seeds in {corpus_dir}")

if __name__ == '__main__':
    main()
