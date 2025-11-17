{
  description = "Suricata Security Research & Fuzzing Environment - Complete Turnkey Solution";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnfree = true;
        };

        # AFL++ with LLVM 18 support
        aflplusplus = pkgs.aflplusplus.override {
          llvmPackages = pkgs.llvmPackages_18;
        };

        # Python environment with all required packages
        pythonEnv = pkgs.python3.withPackages (ps: with ps; [
          scapy
          pyyaml
          requests
          pandas
          matplotlib
          cryptography
          construct
          pytest
          ipython
          dpkt
          pyshark
          numpy
          click
          rich
          tabulate
          jinja2
        ]);

        # Suricata dependencies
        suricataDeps = with pkgs; [
          # Core dependencies
          libpcap
          libyaml
          jansson
          file  # provides libmagic
          zlib
          pcre
          pcre2

          # Optional but recommended
          libnet
          libnfnetlink
          libnetfilter_queue
          libnetfilter_log
          # libhtp - built by Suricata from bundled source
          # libmaxminddb - optional GeoIP support
          luajit
          lz4
          nss
          nspr
          openssl
          libnftnl
          libmnl

          # Rust support
          cargo
          rustc
          rust-bindgen
          rustPackages.cbindgen

          # Build tools
          autoconf
          automake
          libtool
          pkg-config

          # Python bindings
          python3
          python3Packages.pyyaml
        ];

        # Compiler toolchains with sanitizers
        clangWithSanitizers = pkgs.llvmPackages_18.clang;
        llvmTools = pkgs.llvmPackages_18;
        gccWithSanitizers = pkgs.gcc13;

        # Debugging and analysis tools
        debugTools = with pkgs; [
          gdb
          rr
          valgrind
          strace
          ltrace
          lsof
        ];

        # Performance analysis
        perfTools = with pkgs; [
          perf
          flamegraph
          # hotspot - Qt-based GUI, skip for now
        ];

        # Binary analysis
        binaryTools = with pkgs; [
          binutils
          elfutils
          patchelf
          radare2
          # ghidra - large Java-based tool, optional
        ];

        # Network tools
        networkTools = with pkgs; [
          tcpdump
          wireshark  # includes tshark, editcap
          tcpreplay
          nmap
        ];

        # Development tools
        devTools = with pkgs; [
          neovim
          ripgrep
          fd
          bat
          fzf
          jq
          git
          tmux
          tree
          htop
          ncdu
        ];

        # Fuzzing utilities
        fuzzingTools = with pkgs; [
          honggfuzz
          radamsa
          # zzuf - may not be in nixpkgs
          # afl-utils - not in nixpkgs, AFL++ has built-in tools
        ];

        # Coverage tools
        coverageTools = with pkgs; [
          lcov
          gcovr
        ];

      in
      {
        devShells.default = pkgs.mkShell {
          name = "suricata-fuzzing-env";

          buildInputs = [
            # Fuzzing engines
            aflplusplus
            llvmTools.libllvm
            llvmTools.lld

            # Compilers
            clangWithSanitizers
            gccWithSanitizers

            # Suricata dependencies
          ] ++ suricataDeps
            ++ debugTools
            ++ perfTools
            ++ binaryTools
            ++ networkTools
            ++ devTools
            ++ fuzzingTools
            ++ coverageTools
            ++ [
              pythonEnv
            ];

          shellHook = ''
            # Colors for output
            RED='\033[0;31m'
            GREEN='\033[0;32m'
            YELLOW='\033[1;33m'
            BLUE='\033[0;34m'
            MAGENTA='\033[0;35m'
            CYAN='\033[0;36m'
            NC='\033[0m' # No Color

            echo -e "''${CYAN}╔════════════════════════════════════════════════════════════════╗''${NC}"
            echo -e "''${CYAN}║                                                                ║''${NC}"
            echo -e "''${CYAN}║        ''${GREEN}Suricata Security Research & Fuzzing Environment''${CYAN}        ║''${NC}"
            echo -e "''${CYAN}║                                                                ║''${NC}"
            echo -e "''${CYAN}╚════════════════════════════════════════════════════════════════╝''${NC}"
            echo ""
            echo -e "''${GREEN}✓''${NC} AFL++ with QEMU mode:     ''${BLUE}$(afl-fuzz -h | head -1)''${NC}"
            echo -e "''${GREEN}✓''${NC} Clang with sanitizers:    ''${BLUE}$(clang --version | head -1)''${NC}"
            echo -e "''${GREEN}✓''${NC} Python with Scapy:        ''${BLUE}$(python3 --version)''${NC}"
            echo -e "''${GREEN}✓''${NC} Debugging tools:          ''${BLUE}gdb, rr, valgrind, strace''${NC}"
            echo -e "''${GREEN}✓''${NC} Network tools:            ''${BLUE}tcpdump, tshark, tcpreplay''${NC}"
            echo ""
            echo -e "''${YELLOW}Quick Start:''${NC}"
            echo -e "  ''${CYAN}1.''${NC} First time setup:      ''${GREEN}./scripts/setup-everything.sh''${NC}"
            echo -e "  ''${CYAN}2.''${NC} Start fuzzing:         ''${GREEN}./scripts/fuzz-all-parallel.sh''${NC}"
            echo -e "  ''${CYAN}3.''${NC} Monitor progress:      ''${GREEN}./scripts/monitor-fuzzing.sh''${NC}"
            echo -e "  ''${CYAN}4.''${NC} Analyze crashes:       ''${GREEN}python3 scripts/analyze-crashes.py''${NC}"
            echo ""
            echo -e "''${YELLOW}Documentation:''${NC}"
            echo -e "  ''${GREEN}cat FUZZING_QUICKSTART.md''${NC}    - Detailed guide"
            echo -e "  ''${GREEN}./scripts/<script> --help''${NC}    - Script help"
            echo ""
            echo -e "''${MAGENTA}Environment Variables Set:''${NC}"

            # Set up environment for fuzzing
            export CC="${clangWithSanitizers}/bin/clang"
            export CXX="${clangWithSanitizers}/bin/clang++"
            export AFL_CC="$CC"
            export AFL_CXX="$CXX"

            # AFL++ configuration
            export AFL_SKIP_CPUFREQ=1
            export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
            export AFL_AUTORESUME=1

            # Sanitizer options
            export ASAN_OPTIONS="detect_leaks=0:allocator_may_return_null=1:abort_on_error=1:symbolize=1"
            export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"
            export MSAN_OPTIONS="halt_on_error=1"

            # Project paths
            export FUZZING_ROOT="$(pwd)"
            export SURICATA_SRC="$FUZZING_ROOT/suricata-src"
            export BUILD_DIR="$FUZZING_ROOT/builds"
            export CORPUS_DIR="$FUZZING_ROOT/corpus"
            export FINDINGS_DIR="$FUZZING_ROOT/findings"
            export CRASH_REPORTS_DIR="$FUZZING_ROOT/crash-reports"
            export REPRODUCERS_DIR="$FUZZING_ROOT/reproducers"
            export FUZZERS_DIR="$FUZZING_ROOT/fuzzers"
            export SCRIPTS_DIR="$FUZZING_ROOT/scripts"
            export BUILD_ASAN="$BUILD_DIR/suricata-asan"
            export BUILD_UBSAN="$BUILD_DIR/suricata-ubsan"
            export BUILD_COVERAGE="$BUILD_DIR/suricata-coverage"
            export BUILD_FUZZERS="$BUILD_DIR/fuzzers"

            # Coverage settings
            export GCOV_PREFIX="$BUILD_DIR/coverage-data"
            export GCOV_PREFIX_STRIP=10

            # Rust settings
            export CARGO_HOME="$FUZZING_ROOT/.cargo"
            export RUSTFLAGS="-C debuginfo=2"

            # Performance settings
            export MAKEFLAGS="-j$(nproc)"

            # Add scripts to PATH
            export PATH="$SCRIPTS_DIR:$PATH"

            # Create necessary directories
            mkdir -p "$BUILD_DIR" "$CORPUS_DIR" "$FINDINGS_DIR" \
                     "$CRASH_REPORTS_DIR" "$REPRODUCERS_DIR" \
                     "$BUILD_FUZZERS" "$GCOV_PREFIX"

            # Helpful aliases
            alias fuzz-http='./scripts/fuzz-single.sh http'
            alias fuzz-tls='./scripts/fuzz-single.sh tls'
            alias fuzz-dns='./scripts/fuzz-single.sh dns'
            alias fuzz-tcp='./scripts/fuzz-single.sh tcp'
            alias fuzz-defrag='./scripts/fuzz-single.sh defrag'
            alias fuzz-http2='./scripts/fuzz-single.sh http2'
            alias fuzz-smb='./scripts/fuzz-single.sh smb'
            alias fuzz-all='./scripts/fuzz-all-parallel.sh'
            alias monitor='./scripts/monitor-fuzzing.sh'
            alias analyze='python3 scripts/analyze-crashes.py'
            alias coverage='./scripts/coverage-report.sh'
            alias setup='./scripts/setup-everything.sh'

            echo -e "  ''${CYAN}CC''${NC}              = ''${GREEN}$CC''${NC}"
            echo -e "  ''${CYAN}CXX''${NC}             = ''${GREEN}$CXX''${NC}"
            echo -e "  ''${CYAN}SURICATA_SRC''${NC}    = ''${GREEN}$SURICATA_SRC''${NC}"
            echo ""
            echo -e "''${GREEN}Ready to fuzz!''${NC} Run ''${YELLOW}./scripts/setup-everything.sh''${NC} to begin."
            echo ""
          '';

          # Additional environment setup
          LOCALE_ARCHIVE = "${pkgs.glibcLocales}/lib/locale/locale-archive";

          # Increase limits for fuzzing
          hardeningDisable = [ "fortify" ];
        };

        # Provide packages for direct use
        packages = {
          aflplusplus = aflplusplus;
          pythonEnv = pythonEnv;
        };
      }
    );
}
