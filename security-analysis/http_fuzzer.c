/*
 * suricata_http_fuzzer.c
 *
 * AFL++ persistent mode fuzzer for Suricata HTTP parser
 *
 * Target: src/app-layer-htp.c (via libhtp)
 * Priority: CRITICAL - 8 historical CVEs, complex state machine
 *
 * Build: ./build_http_fuzzer.sh
 * Run: afl-fuzz -i corpus_http -o findings_http -m none -- ./http_fuzzer
 *
 * Based on vulnerability analysis showing:
 * - Integer overflows in range handling (app-layer-htp-range.c:264)
 * - Buffer overflows in header accumulation (app-layer-htp.c:1869-1871)
 * - Unsafe memcpy in multipart parsing (app-layer-htp.c:1095-1197)
 */

#include "suricata-common.h"
#include "app-layer-htp.h"
#include "app-layer-parser.h"
#include "flow.h"
#include "stream-tcp.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

// AFL persistent mode
__AFL_FUZZ_INIT();

// Global configuration
static int g_initialized = 0;
static StreamTcpThread *g_stream_thread = NULL;

// Initialize Suricata components once
static void GlobalSetup(void) {
    if (g_initialized)
        return;

    // Initialize detection engine
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        fprintf(stderr, "Failed to initialize detection engine\n");
        exit(1);
    }

    // Register protocol parsers
    AppLayerParserRegisterProtocolParsers();

    // Initialize HTTP parser
    HTPConfigure();

    // Setup stream TCP
    StreamTcpInitConfig(TRUE);

    g_initialized = 1;
}

// Cleanup between fuzzing iterations
static void IterationCleanup(Flow *f) {
    if (f == NULL)
        return;

    // Free application layer state
    if (f->alstate != NULL) {
        AppLayerParserStateCleanup(&f->proto, f->alstate, ALPROTO_HTTP1);
        f->alstate = NULL;
    }

    // Free TCP session
    if (f->protoctx != NULL) {
        StreamTcpSessionClear(f->protoctx);
        SCFree(f->protoctx);
        f->protoctx = NULL;
    }
}

int main(int argc, char **argv) {
    // One-time setup
    GlobalSetup();

    #ifdef __AFL_HAVE_MANUAL_CONTROL
        __AFL_INIT();
    #endif

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {
        size_t len = __AFL_FUZZ_TESTCASE_LEN;

        // Sanity check input size
        if (len < 10 || len > 65535)
            continue;

        // Create flow structure
        Flow *f = SCCalloc(1, sizeof(Flow));
        if (f == NULL)
            continue;

        FLOW_INITIALIZE(f);
        f->proto = IPPROTO_TCP;
        f->alproto = ALPROTO_HTTP1;
        f->flags |= FLOW_IPV4;

        // Create TCP session
        TcpSession *ssn = SCCalloc(1, sizeof(TcpSession));
        if (ssn == NULL) {
            SCFree(f);
            continue;
        }

        f->protoctx = ssn;
        ssn->state = TCP_ESTABLISHED;

        // Parse HTTP data in both directions to test request & response parsing
        int result;

        // Test as HTTP request (TOSERVER)
        result = AppLayerParserParse(
            NULL,                    // Thread vars
            NULL,                    // Alp thread ctx
            f,                       // Flow
            ALPROTO_HTTP1,           // Protocol
            STREAM_TOSERVER,         // Direction
            buf,                     // Data buffer
            len                      // Data length
        );

        // Also test as HTTP response (TOCLIENT) with same data
        // This triggers different code paths
        result = AppLayerParserParse(
            NULL,
            NULL,
            f,
            ALPROTO_HTTP1,
            STREAM_TOCLIENT,
            buf,
            len
        );

        // Cleanup for next iteration
        IterationCleanup(f);
        SCFree(f);
    }

    return 0;
}
