#!/usr/bin/env python3
"""
Crash Analysis and Triage Tool

Analyzes all crashes found by fuzzers:
  - Deduplicates crashes by stack trace
  - Triages severity (exploitable vs non-exploitable)
  - Generates crash reports
  - Creates reproducers

Usage:
    python3 scripts/analyze-crashes.py
    python3 scripts/analyze-crashes.py --protocol http
    python3 scripts/analyze-crashes.py --exploitable-only
"""

import os
import sys
import subprocess
import hashlib
import json
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional
import re

# Colors
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    MAGENTA = '\033[0;35m'
    NC = '\033[0m'

@dataclass
class Crash:
    """Represents a unique crash"""
    protocol: str
    crash_file: Path
    stack_trace: str
    stack_hash: str
    crash_type: str  # ASAN type or signal
    severity: str    # critical, high, medium, low
    exploitable: bool
    function: Optional[str] = None
    file_line: Optional[str] = None

    def to_dict(self):
        return asdict(self)

class CrashAnalyzer:
    def __init__(self, findings_dir: Path, fuzz_root: Path):
        self.findings_dir = findings_dir
        self.fuzz_root = fuzz_root
        self.build_dir = fuzz_root / "builds"
        self.crashes: List[Crash] = []
        self.crash_groups: Dict[str, List[Crash]] = defaultdict(list)

    def analyze_all(self, protocol: Optional[str] = None):
        """Analyze crashes for all protocols or specific protocol"""
        protocols = [protocol] if protocol else [
            "http", "tls", "defrag", "tcp", "http2", "dns", "smb"
        ]

        print(f"{Colors.CYAN}Analyzing crashes...{Colors.NC}\n")

        for proto in protocols:
            crash_dir = self.findings_dir / proto / "default" / "crashes"
            if not crash_dir.exists():
                continue

            crash_files = [f for f in crash_dir.iterdir()
                          if f.is_file() and f.name.startswith("id:")]

            if not crash_files:
                continue

            print(f"{Colors.YELLOW}[{proto}]{Colors.NC} Found {len(crash_files)} crash files")

            for crash_file in crash_files:
                crash = self.analyze_crash(proto, crash_file)
                if crash:
                    self.crashes.append(crash)
                    self.crash_groups[crash.stack_hash].append(crash)

        self.print_summary()
        self.generate_reports()

    def analyze_crash(self, protocol: str, crash_file: Path) -> Optional[Crash]:
        """Analyze individual crash file"""
        fuzzer_bin = self.build_dir / "fuzzers" / f"fuzz_{protocol}"

        if not fuzzer_bin.exists():
            return None

        # Run fuzzer with crash input under GDB
        try:
            result = subprocess.run(
                [str(fuzzer_bin)],
                stdin=crash_file.open('rb'),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
                env={**os.environ, 'ASAN_OPTIONS': 'symbolize=1:abort_on_error=1'}
            )
            stderr = result.stderr.decode('utf-8', errors='replace')

        except subprocess.TimeoutExpired:
            # Hang
            stderr = "TIMEOUT"
        except Exception as e:
            print(f"{Colors.RED}Error analyzing {crash_file}: {e}{Colors.NC}")
            return None

        # Parse ASAN output
        crash_type = self.extract_crash_type(stderr)
        stack_trace = self.extract_stack_trace(stderr)
        stack_hash = hashlib.sha256(stack_trace.encode()).hexdigest()[:16]

        # Extract function and file
        function = self.extract_function(stderr)
        file_line = self.extract_file_line(stderr)

        # Triage severity
        severity, exploitable = self.triage_crash(crash_type, stderr)

        return Crash(
            protocol=protocol,
            crash_file=crash_file,
            stack_trace=stack_trace,
            stack_hash=stack_hash,
            crash_type=crash_type,
            severity=severity,
            exploitable=exploitable,
            function=function,
            file_line=file_line
        )

    def extract_crash_type(self, stderr: str) -> str:
        """Extract crash type from ASAN/UBSAN output"""
        patterns = [
            r'ERROR: AddressSanitizer: ([a-z-]+)',
            r'runtime error: (.+)',
            r'SEGV on (.+)',
            r'Signal (\d+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, stderr)
            if match:
                return match.group(1)

        return "unknown"

    def extract_stack_trace(self, stderr: str) -> str:
        """Extract normalized stack trace"""
        lines = []
        in_trace = False

        for line in stderr.split('\n'):
            if '#0 ' in line or 'SCARINESS' in line:
                in_trace = True

            if in_trace:
                # Remove addresses for normalization
                line = re.sub(r'0x[0-9a-f]+', '0xXXX', line)
                lines.append(line)

                if 'SUMMARY:' in line:
                    break

        return '\n'.join(lines[:20])  # Top 20 frames

    def extract_function(self, stderr: str) -> Optional[str]:
        """Extract crashing function"""
        match = re.search(r'#0 .* in ([a-zA-Z_][a-zA-Z0-9_]*)', stderr)
        if match:
            return match.group(1)
        return None

    def extract_file_line(self, stderr: str) -> Optional[str]:
        """Extract source file and line"""
        match = re.search(r'([a-zA-Z0-9/_.-]+\.[ch]):(\d+)', stderr)
        if match:
            return f"{match.group(1)}:{match.group(2)}"
        return None

    def triage_crash(self, crash_type: str, stderr: str) -> tuple[str, bool]:
        """Triage crash severity and exploitability"""

        # Exploitable types
        if crash_type in ['heap-buffer-overflow', 'stack-buffer-overflow',
                         'heap-use-after-free', 'double-free']:
            return 'critical', True

        # Potentially exploitable
        if crash_type in ['integer-overflow', 'signed-integer-overflow']:
            return 'high', True

        # DoS but not RCE
        if crash_type in ['null-dereference', 'SEGV', 'divide-by-zero']:
            return 'medium', False

        # Memory leaks (low severity)
        if 'leak' in crash_type.lower():
            return 'low', False

        return 'unknown', False

    def print_summary(self):
        """Print analysis summary"""
        unique_crashes = len(self.crash_groups)
        total_crashes = len(self.crashes)
        exploitable = sum(1 for c in self.crashes if c.exploitable)

        print(f"\n{Colors.CYAN}{'='*70}{Colors.NC}")
        print(f"{Colors.GREEN}Crash Analysis Summary{Colors.NC}")
        print(f"{Colors.CYAN}{'='*70}{Colors.NC}\n")

        print(f"  Total crash files:    {total_crashes}")
        print(f"  Unique crashes:       {unique_crashes}")
        print(f"  Exploitable:          {Colors.RED}{exploitable}{Colors.NC}")
        print(f"  DoS only:             {total_crashes - exploitable}")
        print()

        # Group by protocol
        by_protocol = defaultdict(int)
        for crash in self.crashes:
            by_protocol[crash.protocol] += 1

        print(f"{Colors.YELLOW}Crashes by protocol:{Colors.NC}")
        for proto, count in sorted(by_protocol.items(), key=lambda x: -x[1]):
            print(f"  {proto:10s} {count:3d}")
        print()

        # Top crashes
        print(f"{Colors.YELLOW}Unique crashes (by stack hash):{Colors.NC}\n")

        for i, (stack_hash, crashes) in enumerate(
            sorted(self.crash_groups.items(), key=lambda x: -len(x[1]))[:10], 1
        ):
            crash = crashes[0]  # Representative
            color = Colors.RED if crash.exploitable else Colors.YELLOW

            print(f"{color}{i:2d}. [{crash.protocol}] {crash.crash_type}{Colors.NC}")
            print(f"    Count:      {len(crashes)}")
            print(f"    Severity:   {crash.severity}")
            print(f"    Function:   {crash.function or 'unknown'}")
            print(f"    Location:   {crash.file_line or 'unknown'}")
            print(f"    Hash:       {stack_hash}")
            print()

    def generate_reports(self):
        """Generate crash reports and reproducers"""
        report_dir = self.fuzz_root / "crash-reports"
        reproducer_dir = self.fuzz_root / "reproducers"
        report_dir.mkdir(exist_ok=True)
        reproducer_dir.mkdir(exist_ok=True)

        # JSON report
        json_report = report_dir / "crash_analysis.json"
        with json_report.open('w') as f:
            json.dump({
                'summary': {
                    'total': len(self.crashes),
                    'unique': len(self.crash_groups),
                    'exploitable': sum(1 for c in self.crashes if c.exploitable)
                },
                'crashes': [c.to_dict() for c in self.crashes]
            }, f, indent=2, default=str)

        print(f"{Colors.GREEN}✓{Colors.NC} Generated report: {json_report}")

        # Copy exploitable crashes to reproducers
        for crash in self.crashes:
            if crash.exploitable:
                dest = reproducer_dir / f"{crash.protocol}_{crash.stack_hash}.bin"
                subprocess.run(['cp', str(crash.crash_file), str(dest)])

        print(f"{Colors.GREEN}✓{Colors.NC} Copied exploitable crashes to: {reproducer_dir}")
        print()

def main():
    import argparse

    parser = argparse.ArgumentParser(description='Analyze fuzzing crashes')
    parser.add_argument('--protocol', help='Analyze specific protocol only')
    parser.add_argument('--exploitable-only', action='store_true',
                       help='Show only exploitable crashes')
    args = parser.parse_args()

    # Get environment
    fuzz_root = Path(os.environ.get('SURICATA_FUZZ_ROOT', '.'))
    findings_dir = Path(os.environ.get('FINDINGS_DIR', fuzz_root / 'findings'))

    if not findings_dir.exists():
        print(f"{Colors.RED}Error: Findings directory not found: {findings_dir}{Colors.NC}")
        sys.exit(1)

    analyzer = CrashAnalyzer(findings_dir, fuzz_root)
    analyzer.analyze_all(protocol=args.protocol)

if __name__ == '__main__':
    main()
