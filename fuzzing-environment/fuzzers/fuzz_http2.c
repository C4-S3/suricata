/*
 * HTTP/2 Protocol Fuzzer for Suricata
 *
 * Fuzzes HTTP/2 frame parsing:
 *   - Frame headers (9 bytes)
 *   - DATA frames
 *   - HEADERS frames with HPACK compression
 *   - SETTINGS frames
 *   - PRIORITY frames
 *   - Stream multiplexing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "suricata-common.h"
#include "app-layer-http2.h"
#include "app-layer-parser.h"
#include "flow.h"
#include "stream-tcp.h"

__AFL_FUZZ_INIT();

#define MAX_INPUT_SIZE (64 * 1024)

static int initialized = 0;

static void init_suricata(void) {
    if (initialized) return;

    GlobalsInitPreConfig();
    ConfInit();
    ConfYamlLoadString("", 0);
    AppLayerSetup();
    AppLayerParserRegisterProtocolParsers();

    initialized = 1;
}

static void fuzz_http2_frame(const uint8_t *data, size_t size, uint8_t direction) {
    Flow f;
    TcpSession tcp_session;
    AppLayerParserThreadCtx *alp_ctx;

    memset(&f, 0, sizeof(f));
    memset(&tcp_session, 0, sizeof(tcp_session));

    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_HTTP2;
    f.protoctx = &tcp_session;

    alp_ctx = AppLayerParserThreadCtxAlloc();
    if (!alp_ctx) return;

    /* Send HTTP/2 connection preface if client-side */
    if (direction == STREAM_TOSERVER) {
        const char *preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        AppLayerParserParse(NULL, alp_ctx, &f, ALPROTO_HTTP2,
            STREAM_TOSERVER, (uint8_t *)preface, 24);
    }

    /* Parse fuzzed HTTP/2 frames */
    AppLayerParserParse(NULL, alp_ctx, &f, ALPROTO_HTTP2,
        direction, (uint8_t *)data, size);

    /* Cleanup */
    AppLayerParserThreadCtxFree(alp_ctx);

    if (f.alstate) {
        HTP_http2State *h2_state = f.alstate;
        HTTP2StateFree(h2_state);
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

        if (len < 9 || len > MAX_INPUT_SIZE)  /* HTTP/2 frame header is 9 bytes */
            continue;

        /* Alternate directions based on frame type */
        uint8_t direction = (len > 3 && buf[3] & 0x01) ?
            STREAM_TOCLIENT : STREAM_TOSERVER;

        fuzz_http2_frame(buf, len, direction);
    }

    return 0;
}
