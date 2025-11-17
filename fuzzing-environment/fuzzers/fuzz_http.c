/*
 * HTTP/1.x Protocol Fuzzer for Suricata
 *
 * Fuzzes HTTP request and response parsing including:
 *   - Request methods and headers
 *   - Response status codes and headers
 *   - Content-Length/Transfer-Encoding
 *   - Range requests
 *   - Chunked encoding
 *   - Malformed HTTP
 *
 * Compile:
 *   afl-clang-fast -fsanitize=address fuzz_http.c -o fuzz_http \
 *     -I$SURICATA_SRC/src -L$BUILD_DIR/suricata-asan/lib -lsuricata
 *
 * Run:
 *   afl-fuzz -i corpus/http -o findings/http -- ./fuzz_http
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

/* Suricata headers */
#include "suricata-common.h"
#include "app-layer-htp.h"
#include "app-layer-parser.h"
#include "flow.h"
#include "stream-tcp.h"
#include "util-unittest.h"

/* AFL++ persistent mode for speed */
__AFL_FUZZ_INIT();

#define MAX_INPUT_SIZE (64 * 1024)  /* 64KB max */

static int initialized = 0;

static void init_suricata(void) {
    if (initialized) return;

    /* Initialize Suricata subsystems */
    GlobalsInitPreConfig();

    /* Minimal config */
    ConfInit();
    ConfYamlLoadString("", 0);

    /* Initialize app layer */
    AppLayerSetup();
    AppLayerParserRegisterProtocolParsers();

    initialized = 1;
}

static void fuzz_http_request(const uint8_t *data, size_t size) {
    Flow f;
    TcpSession tcp_session;
    AppLayerParserThreadCtx *alp_ctx;

    memset(&f, 0, sizeof(f));
    memset(&tcp_session, 0, sizeof(tcp_session));

    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_HTTP1;
    f.protoctx = &tcp_session;

    alp_ctx = AppLayerParserThreadCtxAlloc();
    if (!alp_ctx) return;

    /* Parse HTTP request */
    AppLayerParserParse(
        NULL,           /* thread vars */
        alp_ctx,
        &f,
        ALPROTO_HTTP1,
        STREAM_TOSERVER,  /* client to server */
        (uint8_t *)data,
        size
    );

    /* Cleanup */
    AppLayerParserThreadCtxFree(alp_ctx);

    if (f.alstate) {
        HtpState *htp_state = f.alstate;
        HTPStateFree(htp_state);
    }
}

static void fuzz_http_response(const uint8_t *data, size_t size) {
    Flow f;
    TcpSession tcp_session;
    AppLayerParserThreadCtx *alp_ctx;

    memset(&f, 0, sizeof(f));
    memset(&tcp_session, 0, sizeof(tcp_session));

    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_HTTP1;
    f.protoctx = &tcp_session;

    alp_ctx = AppLayerParserThreadCtxAlloc();
    if (!alp_ctx) return;

    /* First send a minimal request to establish state */
    const char *req = "GET / HTTP/1.1\r\nHost: test\r\n\r\n";
    AppLayerParserParse(
        NULL, alp_ctx, &f, ALPROTO_HTTP1,
        STREAM_TOSERVER,
        (uint8_t *)req, strlen(req)
    );

    /* Then parse fuzzed response */
    AppLayerParserParse(
        NULL, alp_ctx, &f, ALPROTO_HTTP1,
        STREAM_TOCLIENT,  /* server to client */
        (uint8_t *)data, size
    );

    /* Cleanup */
    AppLayerParserThreadCtxFree(alp_ctx);

    if (f.alstate) {
        HtpState *htp_state = f.alstate;
        HTPStateFree(htp_state);
    }
}

int main(int argc, char **argv) {
    init_suricata();

    #ifdef __AFL_HAVE_MANUAL_CONTROL
        __AFL_INIT();
    #endif

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;

        if (len < 1 || len > MAX_INPUT_SIZE)
            continue;

        /* Determine if input is request or response based on first bytes */
        if (len > 4 && memcmp(buf, "HTTP", 4) == 0) {
            /* Starts with "HTTP" - response */
            fuzz_http_response(buf, len);
        } else {
            /* Request */
            fuzz_http_request(buf, len);
        }
    }

    return 0;
}
