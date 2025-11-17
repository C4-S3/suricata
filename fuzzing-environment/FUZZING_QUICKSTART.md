# Fuzzing Quickstart Guide

**Get from zero to finding crashes in 30 minutes**

This guide walks you through every step of setting up and running the Suricata fuzzing environment.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [First Fuzzing Session](#first-fuzzing-session)
4. [Understanding the Results](#understanding-the-results)
5. [Advanced Workflows](#advanced-workflows)
6. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Install Nix

If you don't have Nix installed:

```bash
# Install Nix (multi-user installation)
sh <(curl -L https://nixos.org/nix/install) --daemon

# Enable flakes (add to ~/.config/nix/nix.conf)
mkdir -p ~/.config/nix
echo "experimental-features = nix-command flakes" >> ~/.config/nix/nix.conf
```

### System Requirements

- **OS**: Linux (x86_64 or aarch64)
- **RAM**: 8GB minimum, 16GB recommended
- **Disk**: 10GB free space
- **CPU**: Modern CPU with 4+ cores

---

## Installation

### Step 1: Clone Repository

```bash
cd ~
git clone https://github.com/yourusername/suricata-fuzzing-nix.git
cd suricata-fuzzing-nix
```

### Step 2: Enter Nix Environment

```bash
nix develop
```

**First time?** This will:
- Download all dependencies (~2GB)
- Build AFL++, Clang, sanitizers, etc.
- Take 5-10 minutes depending on internet speed

You'll see a banner when ready:

```
╔════════════════════════════════════════════════════════════════╗
║        Suricata Security Research & Fuzzing Environment        ║
╚════════════════════════════════════════════════════════════════╝
✓ AFL++ with QEMU mode
✓ Clang with sanitizers
✓ Python with Scapy
...
```

### Step 3: One-Time Setup

```bash
./scripts/setup-everything.sh
```

This script will:

1. **Clone Suricata** from GitHub (~5 minutes)
2. **Build Suricata with ASAN** (~10 minutes)
3. **Build Suricata with UBSAN** (~10 minutes)
4. **Build Suricata with Coverage** (~10 minutes)
5. **Compile all 7 fuzzers** (~2 minutes)
6. **Generate 850+ corpus seeds** (~1 minute)

**Total time: ~40 minutes**

You'll see progress indicators:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▶ STEP: Building Suricata with AddressSanitizer
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ℹ Configuring with ASAN instrumentation...
ℹ Building Suricata (this may take 5-10 minutes)...
✓ Suricata-ASAN built successfully
```

### Verify Installation

After setup completes:

```bash
# Check Suricata builds
ls -lh builds/suricata-*/bin/suricata

# Check fuzzers
ls -lh builds/fuzzers/

# Check corpus
find corpus/ -type f | wc -l   # Should show 850+
```

---

## First Fuzzing Session

### Option 1: Fuzz All Protocols (Recommended)

```bash
./scripts/fuzz-all-parallel.sh
```

This launches 7 fuzzing campaigns in a tmux session. You'll see:

```
Starting parallel fuzzing campaigns

ℹ Starting fuzzer: http
ℹ Starting fuzzer: tls
ℹ Starting fuzzer: defrag
...
✓ All 7 fuzzers started in tmux session: suricata-fuzz

To monitor fuzzing:
  tmux attach -t suricata-fuzz

Tmux quick reference:
  Ctrl+b d      - Detach from session
  Ctrl+b n      - Next window
  Ctrl+b 0-9    - Switch to window
```

The script will auto-attach. You'll see the AFL++ UI:

```
american fuzzy lop ++4.05c (default) [fast]

     process timing ┃           overall results
  ══════════════════╬═════════════════════════════
     run time : 0 days, 0 hrs, 2 min, 45 sec
  last new find : 0 days, 0 hrs, 0 min, 12 sec
  last saved crash : none yet
  last saved hang : none yet

          cycles : 12
          corpus : 156
         crashes : 0
           hangs : 0
         execs/s : 5234
```

### Option 2: Fuzz Single Protocol

```bash
# Fuzz HTTP for 30 minutes
./scripts/fuzz-single.sh http 30

# Fuzz TLS indefinitely (Ctrl+C to stop)
./scripts/fuzz-single.sh tls
```

### Monitor Progress

While fuzzing runs, open a new terminal:

```bash
cd ~/suricata-fuzzing-nix
nix develop
./scripts/monitor-fuzzing.sh
```

You'll see:

```
╔═══════════════════════════════════════════════════════════════╗
║          Suricata Fuzzing Campaign - Live Monitor           ║
╚═══════════════════════════════════════════════════════════════╝

FUZZER     EXECS        EXEC/SEC  CRASHES  HANGS    RUNTIME
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
http       2.5M         5234      3        0        00:08
tls        1.8M         3012      0        0        00:10
defrag     4.1M         8543      7        1        00:08
tcp        3.2M         6234      1        0        00:09
http2      1.2M         2456      0        0        00:08
dns        2.8M         5678      2        0        00:09
smb        1.5M         3123      0        0        00:08
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TOTAL      17.1M        -         13       1
```

**🎉 First crash found!** Usually happens within 15-30 minutes.

### Stop Fuzzing

```bash
# Detach from tmux (keeps fuzzing)
Ctrl+b d

# Or stop all fuzzers
tmux kill-session -t suricata-fuzz
```

---

## Understanding the Results

### Crash Locations

```bash
findings/
├── http/default/crashes/      # HTTP crashes
├── tls/default/crashes/       # TLS crashes
├── defrag/default/crashes/    # Defrag crashes
├── tcp/default/crashes/       # TCP crashes
├── http2/default/crashes/     # HTTP2 crashes
├── dns/default/crashes/       # DNS crashes
└── smb/default/crashes/       # SMB crashes
```

### Analyze Crashes

```bash
python3 scripts/analyze-crashes.py
```

Output:

```
Analyzing crashes...

[http] Found 5 crash files
[tls] Found 2 crash files
[defrag] Found 12 crash files
...

═════════════════════════════════════════════════════════════
Crash Analysis Summary
═════════════════════════════════════════════════════════════

  Total crash files:    23
  Unique crashes:       8
  Exploitable:          3
  DoS only:             5

Crashes by protocol:
  defrag     12
  http        5
  tcp         4
  dns         2

Unique crashes (by stack hash):

1. [defrag] heap-buffer-overflow
    Count:      5
    Severity:   critical
    Function:   DefragRebuild
    Location:   defrag.c:891
    Hash:       a3f7d9e2b1c4

2. [http] integer-overflow
    Count:      3
    Severity:   high
    Function:   HttpRangeOpenFileAux
    Location:   app-layer-htp-range.c:264
    Hash:       b8e2c1a9d3f7
...
```

### Verify a Crash

```bash
# Verify HTTP crash
./scripts/verify-crash.sh http findings/http/default/crashes/id:000000,sig:06*
```

Output:

```
═══════════════════════════════════════════════════════════
Crash Verification
═══════════════════════════════════════════════════════════

Protocol:    http
Crash file:  findings/http/default/crashes/id:000000,sig:06,src:...
Input size:  156 bytes

Input preview:
00000000  48 54 54 50 2f 31 2e 31  20 32 30 36 20 50 61 72  |HTTP/1.1 206 Par|
00000010  74 69 61 6c 20 43 6f 6e  74 65 6e 74 0d 0a 43 6f  |tial Content..Co|
00000020  6e 74 65 6e 74 2d 52 61  6e 67 65 3a 20 62 79 74  |ntent-Range: byt|
00000030  65 73 20 31 30 30 2d 35  30 2f 31 30 30 30 0d 0a  |es 100-50/1000..|
...

Reproducing crash with AddressSanitizer...

=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000001234
READ of size 8 at 0x602000001234 thread T0
    #0 0x555555554321 in HttpRangeOpenFileAux src/app-layer-htp-range.c:264
    #1 0x555555554567 in HTPFileOpen src/app-layer-htp-file.c:123
...

✓ Crash confirmed!
```

**This is a real vulnerability!** 🐛

### Generate Reports

```bash
# HTML coverage report
./scripts/coverage-report.sh

# View coverage
firefox coverage/html/index.html
```

---

## Advanced Workflows

### Resume Fuzzing

AFL++ auto-resumes from last state:

```bash
# Just re-run the command
./scripts/fuzz-single.sh http
```

### Add Custom Seeds

```bash
# Add your own test case
echo "GET /evil HTTP/1.1\r\n\r\n" > corpus/http/custom001.bin

# Restart fuzzer (it will pick up new seeds)
./scripts/fuzz-single.sh http
```

### Test Known Vulnerabilities

```bash
./scripts/test-vulnerabilities.sh
```

This runs PoCs for:
- VULN-2025-HTTP-001 (Range underflow)
- VULN-2025-DEFRAG-001 (ltrim underflow)

### Analyze Specific Protocol

```bash
python3 scripts/analyze-crashes.py --protocol defrag
```

### Get Exploitable Crashes Only

```bash
python3 scripts/analyze-crashes.py --exploitable-only
```

---

## Troubleshooting

### Q: No crashes found after 1 hour?

**A:** This is normal. Try:

```bash
# Check execution speed (should be > 1000/sec)
./scripts/monitor-fuzzing.sh

# Run longer (fuzzing is a marathon, not a sprint)
./scripts/fuzz-all-parallel.sh 1440  # 24 hours

# Check coverage to find unexplored paths
./scripts/coverage-report.sh
```

### Q: Fuzzer crashes immediately?

**A:** Test the fuzzer:

```bash
# Manual test
echo "GET / HTTP/1.1\r\n\r\n" | ./builds/fuzzers/fuzz_http

# Check for errors
echo $?  # Should be 0
```

### Q: Build failed during setup?

**A:** Clean rebuild:

```bash
./scripts/setup-everything.sh --clean
```

### Q: Low execution speed (< 500/sec)?

**A:** Disable CPU frequency scaling:

```bash
# Check current governor
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor

# Set to performance (requires sudo)
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

### Q: Out of disk space?

**A:** Clean old findings:

```bash
# Backup important crashes first
cp -r findings/ findings-backup/

# Clean
rm -rf findings/*/default/queue/*  # Keep only crashes
```

### Q: Want to fuzz modified Suricata code?

**A:**

```bash
# Edit code in suricata/src/...
vim suricata/src/app-layer-htp-range.c

# Rebuild
./scripts/build-suricata-asan.sh
./scripts/build-all-fuzzers.sh

# Fuzz
./scripts/fuzz-single.sh http
```

---

## Next Steps

### Reproduce and Report Bugs

1. **Verify crash** with `verify-crash.sh`
2. **Minimize test case** (AFL++ does this automatically)
3. **Create PoC** based on crash input
4. **Report** following [Suricata's security policy](https://suricata.io/our-story/security-policy/)

### Improve Fuzzing

- Add more seeds to `corpus/` directories
- Modify fuzzers in `fuzzers/` to cover more code
- Adjust sanitizer options in build scripts
- Try different AFL++ strategies (`-P explore`, `-L 0`)

### Scale Up

- Run on multiple machines
- Use AFL++'s distributed mode
- Fuzz for weeks, not hours
- Monitor coverage to guide seed generation

---

## Useful Commands Reference

```bash
# Setup
nix develop                             # Enter environment
./scripts/setup-everything.sh           # One-time setup
./scripts/setup-everything.sh --clean   # Clean rebuild

# Fuzzing
./scripts/fuzz-all-parallel.sh          # Fuzz all protocols
./scripts/fuzz-single.sh <proto> [min]  # Fuzz one protocol
tmux attach -t suricata-fuzz            # Attach to session
tmux kill-session -t suricata-fuzz      # Stop all fuzzers

# Monitoring
./scripts/monitor-fuzzing.sh            # Live stats
watch -n 5 ./scripts/monitor-fuzzing.sh # Auto-refresh

# Analysis
python3 scripts/analyze-crashes.py      # Analyze all crashes
./scripts/verify-crash.sh <p> <file>    # Verify crash
./scripts/coverage-report.sh            # Coverage report

# Maintenance
./scripts/test-vulnerabilities.sh       # Test known bugs
find findings/ -name "id:*" | wc -l     # Count crash files
du -sh findings/                        # Disk usage
```

---

## Getting Help

- **Check logs**: `findings/*/default/fuzzer_stats`
- **AFL++ docs**: https://aflplus.plus/
- **Suricata docs**: https://suricata.readthedocs.io/
- **File issue**: https://github.com/yourusername/suricata-fuzzing-nix/issues

---

**Happy Fuzzing! 🐛**

Remember: Fuzzing is an art. The longer you run it, the deeper the bugs you find.
